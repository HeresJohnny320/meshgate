package dev.meshgate.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import android.view.ViewGroup
import android.annotation.SuppressLint
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material3.RadioButton
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
import androidx.core.content.FileProvider
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
    val exitBlocked: Boolean = false,
    val killSwitch: Boolean = false,
    val exitOnly: Boolean = false,
    val exits: List<ExitOption> = emptyList(),
    val exitChoice: String = "",
    val access: List<Pair<String, String>> = emptyList(),
)

data class ExitOption(val id: String, val name: String, val up: Boolean)

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
        o.optBoolean("exit_blocked"), o.optBoolean("kill_switch"), o.optBoolean("exit_only"),
        o.optJSONArray("exits")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) }.map { ExitOption(it.optString("id"), it.optString("name"), it.optBoolean("up")) } } ?: emptyList(),
        o.optString("exit_choice"),
        o.optJSONArray("access")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) }.map { it.optString("node") to it.optString("what") } } ?: emptyList(),
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
    var admin by remember { mutableStateOf(false) }
    var tests by remember { mutableStateOf(false) }
    when {
        !status.joined -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            JoinScreen { status = parseStatus(Mesh.engine.statusJSON()) }
        }
        // The dashboard gets the whole width; it has its own phone layout.
        admin -> AdminScreen { admin = false }
        tests -> TestsScreen(status) { tests = false }
        else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
            StatusScreen(status, onAdmin = { admin = true }, onTests = { tests = true }) { status = parseStatus(Mesh.engine.statusJSON()) }
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
fun ColumnScope.StatusScreen(s: Status, onAdmin: () -> Unit, onTests: () -> Unit, onChange: () -> Unit) {
    val activity = androidx.compose.ui.platform.LocalContext.current as Activity
    val startVpn = {
        activity.startForegroundService(Intent(activity, MeshVpnService::class.java))
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) startVpn()
    }
    var confirmLeave by remember { mutableStateOf(false) }
    var pickExit by remember { mutableStateOf(false) }

    LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth().weight(1f)) {
        item { ConnectionCard(s, onPickExit = { pickExit = true }) { on ->
            if (on) {
                val intent = VpnService.prepare(activity)
                if (intent != null) consent.launch(intent) else startVpn()
            } else {
                activity.startService(Intent(activity, MeshVpnService::class.java).setAction(MeshVpnService.ACTION_STOP))
            }
        } }
        // Full mesh management from the phone: the dashboard is bundled in the
        // app and works through any server, so one being down does not matter.
        item {
            ElevatedCard(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Admin", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (s.running) "Devices, port forwards, exit nodes and rules. Works through any of your servers."
                            else "Turn the tunnel on to manage the mesh.",
                            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.width(12.dp))
                    FilledTonalButton(onClick = onAdmin, enabled = s.running) { Text("Open") }
                }
            }
        }
        item { KillSwitchCard(s, activity, onChange) }
        item { AccessCard(s) }
        item { UpdateCard(activity) }
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
    if (pickExit) ExitPicker(s, onDone = { pickExit = false; onChange() })
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

/**
 * Kill switch: this phone's internet only goes through an exit node; with
 * none reachable (or if the tunnel cannot start) it is blocked. Turning
 * meshgate off is a deliberate choice and gives normal internet. Blocking
 * while the app is not running at all is Android's job (Always-on VPN).
 */
@Composable
fun KillSwitchCard(s: Status, activity: Activity, onChange: () -> Unit) {
    val lockdown = Mesh.service?.let { Build.VERSION.SDK_INT >= 29 && it.isLockdownEnabled } ?: false
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Kill switch", style = MaterialTheme.typography.titleMedium)
                    Text((if (s.exitOnly) "Your admin requires exit only for this phone. " else "") +
                        "Internet only through an exit node: blocked when none is reachable. Turning meshgate off still gives normal internet.",
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = s.killSwitch, onCheckedChange = { Mesh.engine.setKillSwitch(it); onChange() })
            }
            if (s.killSwitch && s.exitWanted.isEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text("Pick an exit node for this phone first (Admin → Nodes → Edit), otherwise there is nothing to protect.",
                    color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (lockdown) "Also blocks while the app is off or crashed: on (Android Always-on VPN)."
                    else "To also block while the app is off or crashed, turn on Android's Always-on VPN + Block connections without VPN.",
                    style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }) { Text("Settings") }
            }
        }
    }
}

/**
 * In-app updates: compare with the latest GitHub release, download its APK
 * (checksum-verified by the engine) and let Android install it.
 */
@Composable
fun UpdateCard(activity: Activity) {
    val scope = rememberCoroutineScope()
    val current = remember {
        runCatching { activity.packageManager.getPackageInfo(activity.packageName, 0).versionName }.getOrNull() ?: "?"
    }
    var latest by remember { mutableStateOf<String?>(null) }
    var state by remember { mutableStateOf("") }
    var showChanges by remember { mutableStateOf(false) }
    if (showChanges) ChangelogDialog { showChanges = false }
    LaunchedEffect(Unit) { latest = withContext(Dispatchers.IO) { Mesh.engine.updateAvailable(current) } }
    ElevatedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Updates", style = MaterialTheme.typography.titleMedium)
                Text(
                    when {
                        state.isNotEmpty() -> state
                        latest == null -> "Version $current · checking…"
                        latest!!.isEmpty() -> "Version $current · up to date"
                        else -> "Version $current · ${latest} is available"
                    },
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = { showChanges = true }, contentPadding = PaddingValues(0.dp)) { Text("What's new") }
            }
            val tag = latest
            if (!tag.isNullOrEmpty()) {
                Spacer(Modifier.width(12.dp))
                FilledTonalButton(enabled = state.isEmpty() || state.startsWith("Failed"), onClick = {
                    state = "Downloading $tag…"
                    scope.launch {
                        val file = java.io.File(activity.cacheDir, "updates/meshgate-$tag.apk")
                        val err = withContext(Dispatchers.IO) { runCatching { Mesh.engine.downloadAPK(tag, file.path) }.exceptionOrNull() }
                        if (err != null) {
                            state = "Failed: ${err.message}"
                            return@launch
                        }
                        state = "Downloaded and verified; Android asks you to install it."
                        val uri = FileProvider.getUriForFile(activity, activity.packageName + ".files", file)
                        activity.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                }) { Text("Update") }
            }
        }
    }
}

/** The changelog built into this version: + added, - removed, ~ changed or fixed. */
@Composable
fun ChangelogDialog(onDone: () -> Unit) {
    val lines = remember { Mesh.engine.changelog().lines().filter { it.isNotBlank() && !it.startsWith("# ") } }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("What's new") },
        text = {
            LazyColumn(Modifier.heightIn(max = 480.dp)) {
                items(lines) { l ->
                    val (sign, color) = when {
                        l.startsWith("+ ") -> "+" to Color(0xFF2E9E5B)
                        l.startsWith("- ") -> "-" to MaterialTheme.colorScheme.error
                        l.startsWith("~ ") -> "~" to Color(0xFFD08A1E)
                        else -> "" to Color.Unspecified
                    }
                    when {
                        l.startsWith("## ") -> Text(l.removePrefix("## "), style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
                        sign.isNotEmpty() -> Row(Modifier.padding(vertical = 2.dp)) {
                            Text(sign, color = color, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, modifier = Modifier.width(16.dp))
                            Text(l.drop(2).replace("`", ""), style = MaterialTheme.typography.bodySmall)
                        }
                        else -> Text(l.replace("`", ""), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text("Close") } },
    )
}

/** Choose among the exit nodes this phone may use (its permissions). */
@Composable
fun ExitPicker(s: Status, onDone: () -> Unit) {
    val choices = buildList {
        add("" to "Admin default" + if (s.exitWanted.isNotEmpty()) " (${s.exitWanted})" else " (own connection)")
        s.exits.forEach { add(it.id to it.name + if (it.up) "" else " — down") }
        add("off" to "Own connection" + if (s.killSwitch) " (blocked: kill switch is on)" else "")
    }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("Internet away from home") },
        text = {
            Column {
                choices.forEach { (id, label) ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()
                        .clickable { Mesh.engine.setExitChoice(id); onDone() }.padding(vertical = 6.dp)) {
                        RadioButton(selected = s.exitChoice == id, onClick = { Mesh.engine.setExitChoice(id); onDone() })
                        val opt = s.exits.find { it.id == id }
                        if (opt != null) {
                            Box(Modifier.size(8.dp).clip(CircleShape).background(if (opt.up) Color(0xFF2E9E5B) else MaterialTheme.colorScheme.outline))
                            Spacer(Modifier.width(8.dp))
                        }
                        Text(label)
                    }
                }
                Text("If the one in use goes down, the phone moves to another exit it may use.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text("Close") } },
    )
}

/** What the admin allows this device: exit nodes and what it may reach. */
@Composable
fun AccessCard(s: Status) {
    ElevatedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Your access", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            Text("Exit nodes", style = MaterialTheme.typography.labelLarge)
            if (s.exits.isEmpty()) {
                Text("None allowed for this device.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            s.exits.forEach { ex ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(if (ex.up) Color(0xFF2E9E5B) else MaterialTheme.colorScheme.outline))
                    Spacer(Modifier.width(8.dp))
                    Text(ex.name + if (ex.up) "" else " (down)", style = MaterialTheme.typography.bodyMedium)
                }
            }
            if (s.access.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text("Networks you can reach", style = MaterialTheme.typography.labelLarge)
                s.access.forEach { (node, what) ->
                    Text("$node · $what", style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                }
            }
            Text("Set by an admin; updates here automatically.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 6.dp))
        }
    }
}

/** The big switch plus where traffic goes right now. */
@Composable
fun ConnectionCard(s: Status, onPickExit: () -> Unit, onToggle: (Boolean) -> Unit) {
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
                        s.exitBlocked -> "Internet: blocked — no exit node reachable (exit only)"
                        s.exit.isNotEmpty() -> "Internet: through ${s.exit}"
                        s.exitWanted.isNotEmpty() && s.home -> "Internet: your own connection (through ${s.exitWanted} when away)"
                        else -> "Internet: your own connection"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (s.exitBlocked) MaterialTheme.colorScheme.error else Color.Unspecified,
                )
            }
            if (s.exits.isNotEmpty()) {
                TextButton(onClick = onPickExit, contentPadding = PaddingValues(0.dp)) { Text("Change exit node") }
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

/**
 * The admin dashboard, bundled in the APK. Its requests go through
 * MeshgateApp.request to the Go engine, which sends them to whichever server
 * answers (pfSense, the VPS, ...) with one admin login, so managing the mesh
 * keeps working while a server is down.
 */
@SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ColumnScope.AdminScreen(onClose: () -> Unit) {
    var web by remember { mutableStateOf<WebView?>(null) }
    var server by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    BackHandler {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else onClose()
    }
    TopAppBar(
        title = {
            Column {
                Text("Admin", style = MaterialTheme.typography.titleMedium)
                Text(if (server.isEmpty()) "connecting…" else "via $server", style = MaterialTheme.typography.bodySmall,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
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
                val view = this
                addJavascriptInterface(object {
                    @JavascriptInterface
                    fun request(id: Int, method: String, path: String, body: String) {
                        scope.launch {
                            val reply = JSONObject(withContext(Dispatchers.IO) { Mesh.engine.admin(method, path, body) })
                            reply.optString("server").takeIf { it.isNotEmpty() }?.let { server = it }
                            view.evaluateJavascript(
                                "window.__meshgateReply($id, ${reply.optInt("status")}, ${JSONObject.quote(reply.optString("body"))})", null,
                            )
                        }
                    }
                }, "MeshgateApp")
                // Only the bundled dashboard may run here (it has the bridge).
                webViewClient = object : WebViewClient() {
                    override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest) =
                        !r.url.toString().startsWith("file:///android_asset/dashboard/")
                }
                loadUrl("file:///android_asset/dashboard/index.html")
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
