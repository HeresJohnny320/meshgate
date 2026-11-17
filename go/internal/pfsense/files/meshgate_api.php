<?php
/*
 * meshgate_api.php
 *
 * Proxy from the dashboard on VPN > meshgate to the meshgate agent's local
 * socket. guiconfig.inc enforces the pfSense login; csrf-magic is skipped
 * because the dashboard posts JSON, so POSTs must carry the X-Meshgate
 * header instead (a cross-site page cannot set it without a CORS preflight,
 * which this endpoint never grants). Installed by `meshgate pfsense install`.
 */

$nocsrf = true;
require_once("guiconfig.inc");

header("Content-Type: application/json");
header("Cache-Control: no-store");

function fail($code, $msg) {
	http_response_code($code);
	echo json_encode(array("error" => $msg));
	exit;
}

// e.g. "/api/view", "/api/history?range=1d",
// "/api/history?from=..&to=..&step=.." or
// "/api/events?since=..&node=..&q=..&important=..&limit=.." or
// "/api/rawlog?node=..&n=.." (the only
// queries anything sends; the search text is URL-encoded).
if (!preg_match('#^/?(api|auth)/([a-z-]+)(\?(range=[0-9a-z]{1,4}|from=[0-9]{1,12}&to=[0-9]{1,12}&step=[0-9]{1,6}|since=[0-9]{0,12}&node=[A-Za-z0-9_-]{0,64}&q=[A-Za-z0-9%+._~-]{0,300}&important=[01]&limit=[0-9]{1,4}|node=[A-Za-z0-9_-]{0,64}&n=[0-9]{1,5}))?$#', $_GET['p'] ?? '', $m)) {
	fail(404, "not found");
}
$post = $_SERVER['REQUEST_METHOD'] === 'POST';
if ($post && ($_SERVER['HTTP_X_MESHGATE'] ?? '') !== '1') {
	fail(403, "missing X-Meshgate header");
}

// The pfSense login stands in for meshgate's own.
if ($m[1] === 'auth') {
	echo json_encode(array("ok" => true, "user" => $_SESSION['Username'] ?? ''));
	exit;
}

$ch = curl_init("http://meshgate/v1/" . $m[2] . ($m[3] ?? ''));
curl_setopt_array($ch, array(
	CURLOPT_UNIX_SOCKET_PATH => '@@SOCKET@@',
	CURLOPT_RETURNTRANSFER => true,
	CURLOPT_TIMEOUT => 90,
	CURLOPT_CUSTOMREQUEST => $post ? 'POST' : 'GET',
	CURLOPT_HTTPHEADER => array('Content-Type: application/json'),
));
if ($post) {
	curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}
$body = curl_exec($ch);
if ($body === false) {
	fail(502, "meshgate agent not reachable (" . curl_error($ch) . "); check /var/log/meshgate.log");
}
http_response_code(curl_getinfo($ch, CURLINFO_RESPONSE_CODE));
echo $body;
