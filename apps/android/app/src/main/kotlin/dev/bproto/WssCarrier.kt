package dev.bproto

import java.io.Closeable
import java.net.*
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject

/**
 * Protect each TCP socket before OkHttp connects it; never downgrade WSS.
 *
 * `Socket()` has no fd, so `VpnService.protect(Socket)` used to fail here. The
 * protector hands us a `SocketChannel`-backed socket with a real fd instead.
 */
internal class ProtectedSocketFactory(private val protector: SocketProtector) : SocketFactory() {
    override fun createSocket(): Socket = protector.createSocket().also {
        if (!protector.protectSocket(it)) {
            it.close()
            error("WSS socket protection failed")
        }
    }

    private fun connected(remote: InetSocketAddress, local: InetSocketAddress? = null): Socket {
        // With a peer we can bind a wildcard of the right family before
        // protect(); with an explicit local address, bind that instead.
        val socket = if (local != null) {
            protector.createSocket().also { it.bind(local) }
        } else {
            protector.createSocket(remote.address)
        }
        try {
            if (!protector.protectSocket(socket, remote.address)) error("WSS socket protection failed")
            socket.connect(remote)
            return socket
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    override fun createSocket(host: String, port: Int) = connected(InetSocketAddress(host, port))
    override fun createSocket(host: InetAddress, port: Int) = connected(InetSocketAddress(host, port))
    override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int) =
        connected(InetSocketAddress(host, port), InetSocketAddress(local, localPort))
    override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int) =
        connected(InetSocketAddress(host, port), InetSocketAddress(local, localPort))
}

class WssCarrier private constructor(
    private val client: OkHttpClient,
    private val local: DatagramSocket,
    private val failed: () -> Unit,
) : Closeable {
    private val closed = AtomicBoolean()
    private val opened = CountDownLatch(1)
    @Volatile private var connected = false
    @Volatile private var peer: SocketAddress? = null
    private var websocket: WebSocket? = null
    val port: Int get() = local.localPort

    private fun fail() {
        if (!closed.get()) { close(); failed() }
    }

    private fun start(profile: WssProfile) {
        websocket = client.newWebSocket(Request.Builder().url(profile.url)
            .header("Authorization", "Bearer ${profile.token}").build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                connected = true
                opened.countDown()
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                if (bytes.size !in 1..2048) { fail(); return }
                try { peer?.let { local.send(DatagramPacket(bytes.toByteArray(), bytes.size, it)) } }
                catch (_: Exception) { fail() }
            }
            override fun onMessage(webSocket: WebSocket, text: String) { fail() }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                opened.countDown()
                fail()
            }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { fail() }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { fail() }
        })
        check(opened.await(12, TimeUnit.SECONDS) && connected && !closed.get()) { "WSS handshake failed" }
        Thread({
            try {
                while (!closed.get()) {
                    val packet = DatagramPacket(ByteArray(2049), 2049)
                    local.receive(packet)
                    if (peer == null) peer = packet.socketAddress
                    if (peer == packet.socketAddress) {
                        check(packet.length in 1..2048)
                        val ws = checkNotNull(websocket)
                        check(ws.queueSize() <= 128 * 2048) { "WSS send queue exceeded" }
                        check(ws.send(packet.data.toByteString(packet.offset, packet.length)))
                    }
                }
            } catch (_: Exception) { if (!closed.get()) fail() }
        }, "bproto-wss").start()
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            opened.countDown()
            local.close()
            websocket?.cancel()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }

    companion object {
        internal fun connect(profile: WssProfile, protector: SocketProtector, failed: () -> Unit,
                             builder: OkHttpClient.Builder = OkHttpClient.Builder()): WssCarrier {
            val client = builder.socketFactory(ProtectedSocketFactory(protector))
                .proxy(Proxy.NO_PROXY)
                .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                    .tlsVersions(TlsVersion.TLS_1_3).build()))
                .connectTimeout(10, TimeUnit.SECONDS).readTimeout(0, TimeUnit.SECONDS)
                .pingInterval(20, TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).build()
            val local = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            val carrier = WssCarrier(client, local, failed)
            try {
                check(protector.protectDatagram(local)) { "WSS relay protection failed" }
                carrier.start(profile)
                return carrier
            } catch (e: Exception) { carrier.close(); throw e }
        }

        fun prepare(uri: String, protector: SocketProtector, failed: () -> Unit): Pair<String, Closeable?> {
            val config = JSONObject(String(Base64.getUrlDecoder().decode(uri.removePrefix("bproto://import/")), Charsets.UTF_8))
            val profile = WssProfile.parse(config) ?: return TlsCarrier.prepare(uri, protector, failed)
            check(android.os.Build.VERSION.SDK_INT >= 29) { "WSS carrier requires Android 10 or newer" }
            val carrier = connect(profile, protector, failed)
            config.remove("wss")
            config.put("server", "127.0.0.1:${carrier.port}")
            val native = "bproto://import/" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(config.toString().toByteArray(Charsets.UTF_8))
            return native to carrier
        }
    }
}
