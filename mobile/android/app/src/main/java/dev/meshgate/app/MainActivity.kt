package dev.meshgate.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Mesh.init(this)
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Scaffold { pad ->
                    Column(Modifier.padding(pad).fillMaxSize()) { App() }
                }
            }
        }
    }
}

data class Peer(val name: String, val kind: String, val meshIp: String, val path: String, val handshake: Long)
data class AdminLink(val name: String, val url: String)
data class Status(
    val joined: Boolean, val running: Boolean, val name: String, val meshIp: String,
    val relay: String, val error: String, val peers: List<Peer>, val admin: List<AdminLink>,
)

fun parseStatus(json: String): Status {
    val o = JSONObject(json)
    val peers = o.optJSONArray("peers")
    val list = (0 until (peers?.length() ?: 0)).map {
        val p = peers!!.getJSONObject(it)
        Peer(p.optString("name"), p.optString("kind"), p.optString("mesh_ip"), p.optString("path"), p.optLong("last_handshake"))
    }
    val adminArr = o.optJSONArray("admin")
    val admin = (0 until (adminArr?.length() ?: 0)).map {
        val a = adminArr!!.getJSONObject(it)
        AdminLink(a.optString("name"), a.optString("url"))
    }
    return Status(
        o.optBoolean("joined"), o.optBoolean("running"), o.optString("name"), o.optString("mesh_ip"),
        o.optString("home_relay"), o.optString("error"), list, admin,
    )
}

@Composable
fun ColumnScope.App() {
    var status by remember { mutableStateOf(parseStatus(Mesh.engine.statusJSON())) }
    LaunchedEffect(Unit) {
        while (true) {
            status = parseStatus(Mesh.engine.statusJSON())
            delay(2000)
        }
    }
    var adminUrl by remember { mutableStateOf<String?>(null) }
    val url = adminUrl
    when {
        !status.joined -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            JoinScreen { status = parseStatus(Mesh.engine.statusJSON()) }
        }
        // The dashboard gets the whole width; it has its own phone layout.
        url != null -> AdminScreen(url) { adminUrl = null }
        else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
            StatusScreen(status, onAdmin = { adminUrl = it }) { status = parseStatus(Mesh.engine.statusJSON()) }
        }
    }
}

@Composable
fun ColumnScope.JoinScreen(onJoined: () -> Unit) {
    val scope = rememberCoroutineScope()
    var token by remember { mutableStateOf("") }
    var name by remember { mutableStateOf(Build.MODEL ?: "phone") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    val scan = rememberLauncherForActivityResult(ScanContract()) { r -> r.contents?.let { token = it } }

    fun join() {
        busy = true; error = ""
        scope.launch {
            try {
                withContext(Dispatchers.IO) { Mesh.engine.join(token.trim(), name.trim()) }
                onJoined()
            } catch (e: Exception) {
                error = e.message ?: "join failed"
            } finally {
                busy = false
            }
        }
    }

    Text("Join a mesh", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    Text(
        "Create a token in the web UI (Add devices → Phone) or with `sudo meshgate token`, then scan its QR code.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Spacer(Modifier.height(16.dp))
    Button(onClick = {
        scan.launch(ScanOptions().setPrompt("Scan the meshgate join code").setBeepEnabled(false).setOrientationLocked(false))
    }, modifier = Modifier.fillMaxWidth()) { Text("Scan QR code") }
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(token, { token = it }, label = { Text("…or paste token") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
    OutlinedTextField(name, { name = it }, label = { Text("Device name") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
    Spacer(Modifier.height(12.dp))
    Button(onClick = ::join, enabled = !busy && token.startsWith("mg1."), modifier = Modifier.fillMaxWidth()) {
        Text(if (busy) "Joining…" else "Join")
    }
    if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
}

@Composable
fun ColumnScope.StatusScreen(s: Status, onAdmin: (String) -> Unit, onChange: () -> Unit) {
    val activity = androidx.compose.ui.platform.LocalContext.current as Activity
    val startVpn = {
        activity.startForegroundService(Intent(activity, MeshVpnService::class.java))
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startVpn()
    }
    var confirmLeave by remember { mutableStateOf(false) }

    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.weight(1f)) {
            Text(s.name, style = MaterialTheme.typography.headlineSmall)
            Text(s.meshIp, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
        }
        Switch(checked = s.running, onCheckedChange = { on ->
            if (on) {
                val intent = VpnService.prepare(activity)
                if (intent != null) consent.launch(intent) else startVpn()
            } else {
                activity.startService(Intent(activity, MeshVpnService::class.java).setAction(MeshVpnService.ACTION_STOP))
            }
        })
    }
    Spacer(Modifier.height(4.dp))
    Text(
        when {
            !s.running -> "Disconnected"
            s.relay.isNotEmpty() -> "Connected · relay ${s.relay}"
            else -> "Connected"
        },
        color = if (s.running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (s.error.isNotEmpty()) Text(s.error, color = MaterialTheme.colorScheme.error)
    // Full mesh management from the phone: the web UI through the tunnel,
    // behind its admin login. Always shown, so it says what is missing.
    Spacer(Modifier.height(12.dp))
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text("Admin", fontWeight = FontWeight.SemiBold)
            Text(
                when {
                    s.admin.isEmpty() -> "No node in this mesh hosts the web UI yet. On pfSense run `meshgate pfsense install`, " +
                        "or on a server `meshgate webui enable`."
                    !s.running -> "Turn the tunnel on to manage the mesh."
                    else -> "Sign in with the web UI admin login to manage devices, forwards and rules."
                },
                style = MaterialTheme.typography.bodySmall,
            )
            s.admin.forEach { link ->
                Spacer(Modifier.height(8.dp))
                Button(onClick = { onAdmin(link.url) }, enabled = s.running, modifier = Modifier.fillMaxWidth()) {
                    Text("Open admin · ${link.name}")
                }
            }
        }
    }
    Spacer(Modifier.height(16.dp))

    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.weight(1f)) {
        items(s.peers) { p ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(p.name, fontWeight = FontWeight.SemiBold)
                        Text("${p.kind} · ${p.meshIp}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text(p.path.ifEmpty { "–" }, style = MaterialTheme.typography.bodyMedium)
                        Text(handshakeText(p.handshake), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
    if (confirmLeave) {
        Row {
            Text("Remove this phone from the mesh?", Modifier.weight(1f).align(Alignment.CenterVertically))
            TextButton(onClick = { confirmLeave = false }) { Text("Cancel") }
            TextButton(onClick = {
                activity.startService(Intent(activity, MeshVpnService::class.java).setAction(MeshVpnService.ACTION_STOP))
                Mesh.engine.leave()
                confirmLeave = false
                onChange()
            }) { Text("Leave") }
        }
    } else {
        OutlinedButton(onClick = { confirmLeave = true }, modifier = Modifier.fillMaxWidth()) { Text("Leave mesh") }
    }
}

fun handshakeText(unix: Long): String {
    if (unix <= 0) return "no handshake"
    val s = System.currentTimeMillis() / 1000 - unix
    return when {
        s < 60 -> "${s}s ago"
        s < 3600 -> "${s / 60}m ago"
        else -> "${s / 3600}h ago"
    }
}

/** The mesh web UI inside the app. Requires the web UI's admin login. */
@Composable
fun ColumnScope.AdminScreen(url: String, onClose: () -> Unit) {
    var web by remember { mutableStateOf<WebView?>(null) }
    BackHandler {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else onClose()
    }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp)) {
        TextButton(onClick = onClose) { Text("‹ Back") }
        Text(
            android.net.Uri.parse(url).host ?: url,
            style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
        )
        TextButton(onClick = { web?.reload() }) { Text("Reload") }
    }
    AndroidView(
        modifier = Modifier.fillMaxWidth().weight(1f),
        factory = { ctx ->
            WebView(ctx).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                webViewClient = WebViewClient()
                loadUrl(url)
                web = this
            }
        },
    )
}
