package dev.meshgate.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.util.Log
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Hosts the tunnel. The Go engine decides addresses and routes; this class
 * only turns them into a VpnService interface and tells the engine when the
 * phone switches between Wi-Fi and mobile data.
 */
class MeshVpnService : VpnService() {

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        Mesh.init(this)
        startForegroundCompat()
        Mesh.service = this
        thread(name = "meshgate-start") {
            try {
                Mesh.engine.start()
                watchNetworks()
            } catch (e: Exception) {
                Log.e("meshgate", "start failed", e)
                shutdown()
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user disabled us in system settings.
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun shutdown() {
        networkCallback?.let {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
        }
        networkCallback = null
        if (Mesh.service === this) {
            Mesh.engine.stop()
            Mesh.service = null
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    /** Called by the engine (via [Mesh]) whenever addresses or routes change. */
    fun configureTunnel(settingsJSON: String): Int {
        val s = JSONObject(settingsJSON)
        val builder = Builder()
            .setSession("meshgate")
            .setMtu(s.getInt("mtu"))
            .addAddress(s.getString("address"), s.getInt("prefix"))
            .setBlocking(true)
        val routes = s.getJSONArray("routes")
        for (i in 0 until routes.length()) {
            val (ip, bits) = routes.getString(i).split("/")
            builder.addRoute(ip, bits.toInt())
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        val pfd = builder.establish() ?: return -1
        // The Go side owns the descriptor from here on.
        return pfd.detachFd()
    }

    private fun watchNetworks() {
        val cm = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = Mesh.engine.networkChanged()
            override fun onLost(network: Network) = Mesh.engine.networkChanged()
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                Mesh.engine.networkChanged()
        }
        cm.registerNetworkCallback(request, cb)
        networkCallback = cb
    }

    private fun startForegroundCompat() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW)
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, MeshVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_mesh)
            .setContentTitle("meshgate connected")
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "Disconnect", stop).build())
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(1, n)
        }
    }

    companion object {
        const val ACTION_STOP = "dev.meshgate.app.STOP"
        private const val CHANNEL = "vpn"
    }
}
