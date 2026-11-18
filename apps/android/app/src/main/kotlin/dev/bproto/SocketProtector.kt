package dev.bproto

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.Closeable
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.channels.SocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Everything that can open an egress socket in this app goes through here.
 *
 * `VpnService.protect()` is bound to the network that was default when it was
 * called. On Wi-Fi <-> LTE (or VPN revoke/re-establish) a socket that was
 * protected at connect time can silently start looping back into `tun0`: the
 * tunnel still says "connected", but every request times out. We therefore
 * keep every fd/socket we protect and re-protect them on every default network
 * change, while also clearing stale fwmark/netId pins via
 * `setUnderlyingNetworks()`.
 *
 * The native side calls [protectFd] *before* the first handshake packet (JNI
 * method `protectFd(I)Z`); carriers call [protectSocket] / [protectDatagram]
 * before their own `connect()`.
 */
interface SocketProtector {
    /** JNI-visible hook: `VpnService.protect(int)`. */
    fun protectFd(fd: Int): Boolean

    /** Protect a TCP socket before it is connected. [peer] picks the bind family. */
    fun protectSocket(socket: Socket, peer: InetAddress? = null): Boolean

    /** Protect a local UDP relay socket (TLS/WSS/QUIC carriers). */
    fun protectDatagram(socket: DatagramSocket): Boolean

    /** A fresh, fd-bearing Java socket; `Socket()` alone has no fd until connect. */
    fun createSocket(peer: InetAddress? = null): Socket
}

class VpnProtector(private val vpn: VpnService) : SocketProtector, Closeable {
    companion object {
        private const val TAG = "bproto"
    }

    private val fds = CopyOnWriteArraySet<Int>()
    private val sockets = CopyOnWriteArrayList<Socket>()
    private val datagrams = CopyOnWriteArrayList<DatagramSocket>()
    private val closed = AtomicBoolean(false)
    private val connectivity =
        vpn.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = applyUnderlying(network)
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
            applyUnderlying(network)
        override fun onLost(network: Network) = applyUnderlying(null)
    }

    init {
        // A missing permission or an OEM quirk must not kill the tunnel; the
        // native hook still protects each socket on creation.
        connectivity?.runCatching { registerDefaultNetworkCallback(networkCallback) }
            ?.onFailure { Log.w(TAG, "default network callback unavailable", it) }
    }

    override fun protectFd(fd: Int): Boolean {
        if (closed.get() || fd < 0) return false
        val ok = runCatching { vpn.protect(fd) }.getOrDefault(false)
        if (ok) fds.add(fd)
        return ok
    }

    override fun protectSocket(socket: Socket, peer: InetAddress?): Boolean {
        if (closed.get()) return false
        // With no peer (OkHttp's `createSocket()`) leave the channel socket
        // unbound: binding now to an IPv4 wildcard would break IPv6 peers.
        // `SocketChannel.open()` already owns a real fd, so protect() works.
        if (!socket.isBound && peer != null) {
            val wildcard = if (peer is Inet6Address) {
                InetAddress.getByName("::")
            } else {
                InetAddress.getByName("0.0.0.0")
            }
            val bound = runCatching { socket.bind(InetSocketAddress(wildcard, 0)) }
            if (bound.isFailure) {
                Log.w(TAG, "cannot bind socket before protect()", bound.exceptionOrNull())
                return false
            }
        }
        val ok = protectSocketNow(socket)
        // Keep the socket itself, not a dup fd: the dup is closed by `use`, so
        // its integer could later be reused by an unrelated socket.
        if (ok) sockets.add(socket)
        return ok
    }

    override fun protectDatagram(socket: DatagramSocket): Boolean {
        if (closed.get()) return false
        val ok = protectDatagramNow(socket)
        if (ok) datagrams.add(socket)
        return ok
    }

    private fun protectSocketNow(socket: Socket): Boolean {
        if (runCatching { vpn.protect(socket) }.getOrDefault(false)) return true
        // Some OEMs return false for the Socket overload on a channel socket;
        // the raw fd overload is the same operation.
        return runCatching {
            ParcelFileDescriptor.fromSocket(socket)?.use { vpn.protect(it.fd) } ?: false
        }.getOrDefault(false)
    }

    private fun protectDatagramNow(socket: DatagramSocket): Boolean {
        if (runCatching { vpn.protect(socket) }.getOrDefault(false)) return true
        return runCatching {
            ParcelFileDescriptor.fromDatagramSocket(socket)?.use { vpn.protect(it.fd) } ?: false
        }.getOrDefault(false)
    }

    override fun createSocket(peer: InetAddress?): Socket {
        // `SocketChannel.open().socket()` owns a real fd immediately, unlike a
        // bare `Socket()`; this is what makes protect()-before-connect() work.
        val socket = SocketChannel.open().socket()
        if (peer != null && !socket.isBound) {
            val wildcard = if (peer is Inet6Address) {
                InetAddress.getByName("::")
            } else {
                InetAddress.getByName("0.0.0.0")
            }
            socket.bind(InetSocketAddress(wildcard, 0))
        }
        return socket
    }

    private fun applyUnderlying(network: Network?) {
        if (closed.get()) return
        val caps = network?.let { runCatching { connectivity?.getNetworkCapabilities(it) }.getOrNull() }
        val usable = caps != null &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        runCatching { vpn.setUnderlyingNetworks(if (usable) arrayOf(network!!) else null) }
            .onFailure { Log.w(TAG, "setUnderlyingNetworks failed", it) }
        reprotect()
    }

    private fun reprotect() {
        fds.forEach { fd -> runCatching { vpn.protect(fd) } }
        sockets.forEach { socket ->
            runCatching { if (!socket.isClosed) protectSocketNow(socket) }
        }
        datagrams.forEach { socket ->
            runCatching { if (!socket.isClosed) protectDatagramNow(socket) }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        connectivity?.runCatching { unregisterNetworkCallback(networkCallback) }
        runCatching { vpn.setUnderlyingNetworks(null) }
        fds.clear()
        sockets.clear()
        datagrams.clear()
    }
}
