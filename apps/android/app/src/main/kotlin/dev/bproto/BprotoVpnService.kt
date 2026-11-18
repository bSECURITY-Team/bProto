package dev.bproto

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import dev.bproto.client.R
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The tunnel, built on the Android [VpnService] contract.
 *
 * Order matters and is the whole point of this class:
 *
 * 1. Install a [VpnProtector] so every socket the native side opens is marked
 *    with `VpnService.protect()` *before* its first packet. This includes the
 *    TCP fallback socket, which used to be created without any protection.
 * 2. `Bproto.connect()` runs the handshake before the VPN exists, so the
 *    server learns which address to lease.
 * 3. Protect the established link too, then `establish()` the tun interface.
 *    When the device accepts an IPv6 address we capture `::/0`; the native
 *    pump answers captured v6 with ICMPv6 "no route" so apps fall back to v4
 *    immediately instead of waiting for a TCP timeout. If the device refuses
 *    the v6 address we fall back to a real IPv4-only interface and warn.
 * 4. Start `Bproto.pump()` and announce "connected" only after the native
 *    datapath is actually running; otherwise a failed `establish()`/`pump()`
 *    looks like a connected but completely dead tunnel.
 */
class BprotoVpnService : VpnService() {

    companion object {
        private const val TAG = "bproto"
        private const val CHANNEL_ID = "bproto-tunnel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "dev.bproto.client.CONNECT"
        const val ACTION_DISCONNECT = "dev.bproto.client.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_ROUTING = "routing"
        const val EXTRA_CANDIDATES = "candidates"

        /** Broadcast the activity listens to for status updates. */
        const val ACTION_STATUS = "dev.bproto.client.STATUS"

        /** Tunnel MTU. Must match `MAX_DATAGRAM` minus the encapsulating header. */
        const val MTU = 1251
        private const val PREFIX = 24

        /**
         * Capture address for IPv6. The datapath carries IPv4 only: v6 packets
         * must either be captured (and rejected with ICMPv6) or explicitly
         * reported as a leak. `62 70 72 6f 74 6f` is "bproto" in hex.
         */
        private const val IPV6_ADDRESS = "fd00:6270:726f:746f::2"
        private const val IPV6_PREFIX = 64

        /** Last status line, for the activity to render after a reconnect. */
        @Volatile
        var lastStatus: String = ""

        @Volatile
        var running: Boolean = false
            private set

        @Volatile var connecting: Boolean = false
            private set
    }

    // Touched from the main thread (start) and the tunnel thread (finally).
    @Volatile
    private var worker: Thread? = null
    @Volatile private var carrier: java.io.Closeable? = null
    @Volatile private var protector: VpnProtector? = null
    private var routing = RoutingPolicy()
    private var candidates: List<String> = emptyList()
    @Volatile private var cancelled = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                if (worker != null) return START_NOT_STICKY
                val config = intent.getStringExtra(EXTRA_CONFIG)
                if (config.isNullOrBlank()) {
                    publish("no key: nothing to connect with")
                } else {
                    val policy = runCatching {
                        RoutingPolicy.parse(intent.getStringExtra(EXTRA_ROUTING)?.let { org.json.JSONObject(it) })
                    }
                    if (policy.isFailure) publish("Invalid routing policy") else {
                        candidates = intent.getStringArrayListExtra(EXTRA_CANDIDATES)?.take(128).orEmpty()
                        routing = policy.getOrThrow()
                        if (packageName in routing.bypassApps) {
                            publish("The VPN application cannot bypass its own tunnel")
                            return START_NOT_STICKY
                        }
                        start(config)
                    }
                }
            }
            ACTION_DISCONNECT -> stopTunnel()
            else -> Unit
        }
        return START_NOT_STICKY
    }

    /** Start the tunnel on a private thread. No-op if one is already running. */
    fun start(config: String) {
        if (worker != null) {
            return
        }
        cancelled = false
        connecting = true
        Bproto.reset()
        val activeProtector = try {
            VpnProtector(this).also {
                protector = it
                Bproto.setSocketProtector(it)
            }
        } catch (t: Throwable) {
            Log.w(TAG, "cannot install socket protector", t)
            publish("failed: ${t.message ?: t.javaClass.simpleName}")
            connecting = false
            return
        }
        goForeground()
        worker = Thread({ pump(config, activeProtector) }, "bproto-vpn").apply { start() }
    }

    fun stopTunnel() {
        cancelled = true
        carrier?.close()
        Bproto.stop()
    }

    override fun onRevoke() {
        // The system took the tunnel away (another VPN, or the user revoked it).
        publish("revoked by the system")
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun pump(config: String, activeProtector: SocketProtector) {
        var handle = 0L
        var tun: ParcelFileDescriptor? = null
        var pumpThread: Thread? = null
        var pumpDone: CountDownLatch? = null
        try {
            val allChoices = candidates.ifEmpty { listOf(config) }
            val choices = if (QuicProfile.requiresEchUri(config)) {
                allChoices.filter { QuicProfile.requiresEchUri(it) }
            } else allChoices
            if (choices.isEmpty()) {
                publish("No compatible ECH server in the selection")
                return
            }
            for ((index, candidate) in choices.withIndex()) {
                if (cancelled) return
                // A carrier that died during the previous candidate may have
                // raised stop(); do not let it cancel the next attempt.
                Bproto.reset()
                publish("Connecting to server ${index + 1}/${choices.size}")
                carrier?.close()
                carrier = null
                val prepared = runCatching {
                    QuicCarrier.prepare(candidate, activeProtector) { Bproto.stop() }
                }
                if (prepared.isFailure) {
                    publish("Carrier failed for server ${index + 1}: ${prepared.exceptionOrNull()?.message}")
                    continue
                }
                val (nativeConfig, activeCarrier) = prepared.getOrThrow()
                carrier = activeCarrier
                if (cancelled) return
                handle = Bproto.connect(nativeConfig)
                if (handle != 0L) break
            }
            if (handle == 0L) {
                publish("handshake failed: ${Bproto.lastError()}")
                return
            }

            if (cancelled) return
            val address = Bproto.assignedIp(handle)
            if (address.isEmpty()) {
                publish("server leased no address: ${Bproto.lastError()}")
                return
            }

            // Protect the established link too. The native hook already did
            // this before the handshake; the extra call registers the fd for
            // re-protection after Wi-Fi <-> LTE changes. TCP fallback now
            // returns a real descriptor here instead of -1.
            val socket = Bproto.socketFd(handle)
            if (socket < 0) {
                publish("no socket descriptor: ${Bproto.lastError()}")
                return
            }
            if (!activeProtector.protectFd(socket)) {
                publish("could not protect socket $socket")
                return
            }

            // The tun interface. IPv6 is either captured and rejected with
            // ICMPv6, or (if the OEM refuses it) explicitly not captured.
            val (established, warning) = establishTunnel(address)
            tun = established
            if (tun == null) {
                publish("establish() was refused (no VPN permission?): ${warning ?: "unknown error"}")
                return
            }
            val tunFd = tun.fd

            val done = CountDownLatch(1)
            pumpDone = done
            val error = AtomicReference<String?>(null)
            pumpThread = Thread({
                try {
                    error.set(Bproto.pump(handle, tunFd))
                } catch (t: Throwable) {
                    Log.w(TAG, "native pump crashed", t)
                    error.set("native pump failed: ${t.message ?: t.javaClass.simpleName}")
                } finally {
                    done.countDown()
                }
            }, "bproto-pump").apply { start() }

            // Do not lie to the UI: the handshake alone is not a working
            // datapath. Wait until run_pump() has set PUMPING (or failed).
            val startDeadline = SystemClock.elapsedRealtime() + 5_000
            var announced = false
            while (!done.await(50, TimeUnit.MILLISECONDS)) {
                if (Bproto.pumpActive() != 0 && !cancelled) {
                    connecting = false
                    running = true
                    announced = true
                    publish(
                        if (warning != null) "connected as $address — warning: $warning"
                        else "connected as $address"
                    )
                    break
                }
                if (SystemClock.elapsedRealtime() > startDeadline) {
                    Bproto.stop()
                    break
                }
            }

            // Wait for the pump to finish; log counters so logcat can tell a
            // dead session apart from a working one.
            var nextStats = SystemClock.elapsedRealtime() + 10_000
            while (!done.await(1_000, TimeUnit.MILLISECONDS)) {
                if (SystemClock.elapsedRealtime() >= nextStats) {
                    Log.d(TAG, "stats: ${Bproto.stats(handle)}")
                    nextStats = SystemClock.elapsedRealtime() + 10_000
                }
            }
            pumpThread.join()

            val pumpError = error.get()
            if (pumpError != null) {
                publish("tunnel stopped: $pumpError")
            } else if (announced || cancelled) {
                publish("disconnected")
            } else {
                publish("tunnel did not start: ${Bproto.lastError()}")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "tunnel failed", t)
            publish("failed: ${t.message ?: t.javaClass.simpleName}")
        } finally {
            running = false
            connecting = false
            Bproto.stop()
            // Never free the handle while a native pump is still using it.
            runCatching { pumpDone?.await(5_000, TimeUnit.MILLISECONDS) }
            runCatching { pumpThread?.join(5_000) }
            val pumpStillAlive = pumpThread?.isAlive == true
            Bproto.setSocketProtector(null)
            protector?.close()
            protector = null
            if (handle != 0L && !pumpStillAlive) {
                Bproto.close(handle)
            } else if (pumpStillAlive) {
                Log.w(TAG, "pump thread still alive; keeping handle $handle to avoid use-after-free")
            }
            carrier?.close()
            carrier = null
            runCatching { tun?.close() }
            worker = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    /**
     * Establishes the tun interface.
     *
     * The datapath is IPv4 only. When the device accepts a ULA v6 address we
     * capture `::/0` and the native pump answers v6 with ICMPv6 "no route to
     * destination" — a fast kernel error, not a black hole. A route-only `::/0`
     * capture without an address (the old second attempt) is intentionally
     * gone: it was the exact configuration that made every v6 connect hang.
     * If v6 is refused we establish IPv4-only and warn loudly.
     *
     * @return the descriptor, plus an optional warning describing what was lost.
     */
    private fun establishTunnel(address: String): Pair<ParcelFileDescriptor?, String?> {
        val warning = "IPv6 is not captured on this device; IPv6 traffic may bypass the VPN"
        try {
            val fd = vpnBuilder(address)
                .addAddress(IPV6_ADDRESS, IPV6_PREFIX)
                .addRoute("::", 0)
                .establish()
            if (fd != null) return fd to null
            Log.w(TAG, "full v6 capture: establish() returned null; trying IPv4-only")
        } catch (refused: IllegalArgumentException) {
            Log.i(TAG, "v6 address/route capture refused; falling back to IPv4-only", refused)
        }
        try {
            return vpnBuilder(address).establish() to warning
        } catch (refused: IllegalArgumentException) {
            Log.w(TAG, "IPv4-only establish() refused", refused)
            return null to "$warning; establish() was refused"
        }
    }

    private fun vpnBuilder(address: String): Builder {
        val builder = Builder()
            .setSession("bProto")
            .setMtu(MTU)
            .addAddress(address, PREFIX)
        routing.routes.forEach {
            val parts = it.split('/')
            builder.addRoute(parts[0], parts[1].toInt())
        }
        routing.dns.forEach {
            builder.addDnsServer(it)
            builder.addRoute(it, 32)
        }
        routing.bypassApps.forEach { builder.addDisallowedApplication(it) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        return builder
    }

    private fun goForeground() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            )
            manager.createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun publish(status: String) {
        lastStatus = status
        Log.i(TAG, status)
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName))
    }
}
