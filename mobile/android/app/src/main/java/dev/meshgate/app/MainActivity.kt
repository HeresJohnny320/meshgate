package dev.meshgate.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import android.view.ViewGroup
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.FilterChip
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
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
            val dark = isSystemInDarkTheme()
            val colors = when {
                Build.VERSION.SDK_INT >= 31 && dark -> dynamicDarkColorScheme(this)
                Build.VERSION.SDK_INT >= 31 -> dynamicLightColorScheme(this)
                dark -> darkColorScheme()
                else -> lightColorScheme()
            }
            MaterialTheme(colorScheme = colors) {
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
    val home: Boolean, val exit: String, val exitWanted: String, val warnings: List<String>,
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
    val warnArr = o.optJSONArray("warnings")
    val warnings = (0 until (warnArr?.length() ?: 0)).map { warnArr!!.getString(it) }
    return Status(
        o.optBoolean("joined"), o.optBoolean("running"), o.optString("name"), o.optString("mesh_ip"),
        o.optString("home_relay"), o.optString("error"), list, admin,
        o.optBoolean("home"), o.optString("exit"), o.optString("exit_wanted"), warnings,
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
    var tests by remember { mutableStateOf(false) }
    val url = adminUrl
    when {
        !status.joined -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            JoinScreen { status = parseStatus(Mesh.engine.statusJSON()) }
        }
        // The dashboard gets the whole width; it has its own phone layout.
        url != null -> AdminScreen(url) { adminUrl = null }
        tests -> TestsScreen(status) { tests = false }
        else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
            StatusScreen(status, onAdmin = { adminUrl = it }, onTests = { tests = true }) { status = parseStatus(Mesh.engine.statusJSON()) }
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
fun ColumnScope.StatusScreen(s: Status, onAdmin: (String) -> Unit, onTests: () -> Unit, onChange: () -> Unit) {
    val activity = androidx.compose.ui.platform.LocalContext.current as Activity
    val startVpn = {
        activity.startForegroundService(Intent(activity, MeshVpnService::class.java))
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startVpn()
    }
    var confirmLeave by remember { mutableStateOf(false) }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth().weight(1f)) {
        item { ConnectionCard(s) { on ->
            if (on) {
                val intent = VpnService.prepare(activity)
                if (intent != null) consent.launch(intent) else startVpn()
            } else {
                activity.startService(Intent(activity, MeshVpnService::class.java).setAction(MeshVpnService.ACTION_STOP))
            }
        } }
        // Full mesh management from the phone: the web UI through the tunnel,
        // behind its admin login. Always shown, so it says what is missing.
        item {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Admin", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        when {
                            s.admin.isEmpty() -> "No node in this mesh hosts the web UI yet. On pfSense run `meshgate pfsense install`, " +
                                "or on a server `meshgate webui enable`."
                            !s.running -> "Turn the tunnel on to manage the mesh."
                            else -> "Devices, port forwards, exit nodes and rules. Sign in with the admin login."
                        },
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    s.admin.forEach { link ->
                        Spacer(Modifier.height(12.dp))
                        FilledTonalButton(onClick = { onAdmin(link.url) }, enabled = s.running, modifier = Modifier.fillMaxWidth()) {
                            Text("Open admin · ${link.name}")
                        }
                    }
                }
            }
        }
        item {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Tests", style = MaterialTheme.typography.titleMedium)
                        Text("Public IP / exit node, ping, ports, HTTPS — from this phone.",
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Spacer(Modifier.width(12.dp))
                    FilledTonalButton(onClick = onTests) { Text("Open") }
                }
            }
        }
        item {
            Text("Devices", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp, start = 4.dp))
        }
        items(s.peers) { p -> PeerRow(p) }
        item {
            TextButton(onClick = { confirmLeave = true }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text("Leave mesh", color = MaterialTheme.colorScheme.error)
            }
        }
    }
    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text("Leave the mesh?") },
            text = { Text("This phone is removed from the mesh. To come back you need a new join token.") },
            confirmButton = {
                TextButton(onClick = {
                    activity.startService(Intent(activity, MeshVpnService::class.java).setAction(MeshVpnService.ACTION_STOP))
                    Mesh.engine.leave()
                    confirmLeave = false
                    onChange()
                }) { Text("Leave", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text("Cancel") } },
        )
    }
}

/** The big switch plus where traffic goes right now. */
@Composable
fun ConnectionCard(s: Status, onToggle: (Boolean) -> Unit) {
    val on = s.running
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (on) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(s.name, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
                    Text(s.meshIp, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
                }
                Switch(checked = on, onCheckedChange = onToggle)
            }
            Spacer(Modifier.height(12.dp))
            Text(
                when {
                    !on -> "Disconnected"
                    s.home -> "At home · direct to your network"
                    s.relay.isNotEmpty() -> "Away · connected via ${s.relay}"
                    else -> "Connected"
                },
                style = MaterialTheme.typography.titleMedium,
            )
            if (on) {
                Text(
                    when {
                        s.exit.isNotEmpty() -> "Internet: through ${s.exit}"
                        s.exitWanted.isNotEmpty() && s.home -> "Internet: your own connection (through ${s.exitWanted} when away)"
                        else -> "Internet: your own connection"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            (listOf(s.error) + s.warnings).filter { it.isNotEmpty() }.forEach {
                Spacer(Modifier.height(6.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun PeerRow(p: Peer) {
    val age = if (p.handshake > 0) System.currentTimeMillis() / 1000 - p.handshake else Long.MAX_VALUE
    val dot = when {
        age < 180 && p.path == "direct" -> Color(0xFF2E9E5B)
        age < 180 -> Color(0xFFD08A1E)
        else -> MaterialTheme.colorScheme.outline
    }
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(10.dp).clip(CircleShape).background(dot))
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(p.name, fontWeight = FontWeight.SemiBold)
                Text("${p.kind} · ${p.meshIp}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(p.path.ifEmpty { "–" }, style = MaterialTheme.typography.bodyMedium)
                Text(handshakeText(p.handshake), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
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
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ColumnScope.AdminScreen(url: String, onClose: () -> Unit) {
    var web by remember { mutableStateOf<WebView?>(null) }
    BackHandler {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else onClose()
    }
    TopAppBar(
        title = {
            Column {
                Text("Admin", style = MaterialTheme.typography.titleMedium)
                Text(android.net.Uri.parse(url).host ?: url, style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        },
        navigationIcon = {
            IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
        },
        actions = {
            IconButton(onClick = { web?.reload() }) { Icon(Icons.Filled.Refresh, contentDescription = "Reload") }
        },
    )
    AndroidView(
        modifier = Modifier.fillMaxWidth().weight(1f),
        factory = { ctx ->
            WebView(ctx).apply {
                // Fill the space Compose gives us; with the default
                // wrap_content the page sees a near-zero viewport height.
                layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = true
                webViewClient = WebViewClient()
                loadUrl(url)
                web = this
            }
        },
    )
}

/** Checks run from the phone itself, through the VPN like any app. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ColumnScope.TestsScreen(s: Status, onClose: () -> Unit) {
    BackHandler(onBack = onClose)
    val scope = rememberCoroutineScope()
    val kinds = listOf("myip" to "My public IP", "ping" to "Ping", "tcp" to "TCP port", "udp" to "UDP", "http" to "HTTP(S)")
    var kind by remember { mutableStateOf("myip") }
    var target by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Pair<Boolean, String>?>(null) }

    TopAppBar(
        title = { Text("Tests") },
        navigationIcon = {
            IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
        },
    )
    LazyColumn(Modifier.fillMaxWidth().weight(1f).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                kinds.forEach { (k, label) ->
                    FilterChip(selected = kind == k, onClick = { kind = k; result = null }, label = { Text(label) })
                }
            }
        }
        item {
            Text(
                when (kind) {
                    "myip" -> if (s.exit.isNotEmpty()) "Shows the IP websites see. With exit node ${s.exit} on, it should be ${s.exit}'s IP."
                        else "Shows the IP websites see from this phone right now."
                    "ping" -> "Ping a mesh device, a LAN address at home (e.g. 192.168.1.20) or any host."
                    "tcp" -> "Is a TCP port open? E.g. a port forward on your VPS, or a service at home."
                    "udp" -> "Answers only from a meshgate test service (turn it on under Admin → Nodes → Edit)."
                    else -> "Fetch a page; for HTTPS also shows the certificate and when it expires."
                },
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (kind != "myip") {
            item {
                OutlinedTextField(target, { target = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                    label = { Text(if (kind == "http") "Address (https://…)" else "Host or IP") })
            }
            if (kind != "http") item {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    s.peers.forEach { p ->
                        AssistChip(onClick = { target = p.meshIp }, label = { Text(p.name) })
                    }
                }
            }
            if (kind == "tcp" || kind == "udp") item {
                OutlinedTextField(port, { port = it.filter(Char::isDigit).take(5) }, singleLine = true, label = { Text("Port") },
                    modifier = Modifier.fillMaxWidth())
            }
        }
        item {
            Button(
                onClick = {
                    busy = true
                    result = null
                    scope.launch {
                        val json = withContext(Dispatchers.IO) { Mesh.engine.diag(kind, target.trim(), port.toLongOrNull() ?: 0L) }
                        val o = JSONObject(json)
                        result = o.optBoolean("ok") to o.optString("output")
                        busy = false
                    }
                },
                enabled = !busy && (kind == "myip" || target.isNotBlank()),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Running…" else "Run") }
        }
        result?.let { (ok, out) ->
            item {
                Card(
                    Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = if (ok) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.errorContainer,
                    ),
                ) {
                    Text(out, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
                }
            }
        }
        item { Spacer(Modifier.height(16.dp)) }
    }
}
