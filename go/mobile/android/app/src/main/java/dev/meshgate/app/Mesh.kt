package dev.meshgate.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import dev.meshgate.meshcore.Engine
import dev.meshgate.meshcore.Meshcore
import dev.meshgate.meshcore.Platform
import java.net.Inet4Address

/**
 * Process-wide access to the Go engine. The activity uses it to join and
 * read status; [MeshVpnService] attaches itself while the VPN runs so the
 * engine can create the TUN interface and protect its sockets.
 */
object Mesh {
    @Volatile
    var service: MeshVpnService? = null

    private lateinit var appContext: Context
    lateinit var engine: Engine
        private set

    fun init(context: Context) {
        if (::engine.isInitialized) return
        appContext = context.applicationContext
        engine = Meshcore.newEngine(appContext.filesDir.resolve("mesh").absolutePath, bridge)
    }

    private val bridge = object : Platform {
        override fun protect(fd: Int): Boolean = service?.protect(fd) ?: true

        override fun configureTunnel(settingsJSON: String): Int =
            service?.configureTunnel(settingsJSON) ?: -1

        override fun localAddresses(): String {
            val cm = appContext.getSystemService(ConnectivityManager::class.java)
            val out = mutableListOf<String>()
            @Suppress("DEPRECATION")
            for (n in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                cm.getLinkProperties(n)?.linkAddresses?.forEach { la ->
                    if (la.address is Inet4Address) out += la.address.hostAddress ?: ""
                }
            }
            return out.filter { it.isNotEmpty() }.joinToString(",")
        }

        override fun log(msg: String) {
            Log.i("meshgate", msg)
        }
    }
}
