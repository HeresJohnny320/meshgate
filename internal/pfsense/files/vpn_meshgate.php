<?php
/*
 * vpn_meshgate.php
 *
 * VPN > meshgate: the meshgate dashboard inside the pfSense GUI, behind the
 * pfSense login. Installed by `meshgate pfsense install`; the dashboard's
 * API calls go through meshgate_api.php.
 */

require_once("guiconfig.inc");

$opt = config_get_path("installedpackages/meshgate/opt", "");
$pgtitle = array(gettext("VPN"), "meshgate");
include("head.inc");
?>
<div class="panel panel-default">
	<div class="panel-body" style="padding:0">
		<iframe src="/meshgate/index.html" title="meshgate"
			style="display:block;width:100%;height:calc(100vh - 220px);min-height:520px;border:0"></iframe>
	</div>
</div>
<?php if ($opt !== ""): ?>
<div class="infoblock">
	<p>What mesh devices may reach on your network is set in
	<a href="/firewall_rules.php?if=<?=htmlspecialchars($opt)?>">Firewall &gt; Rules &gt; MESHGATE</a>.</p>
</div>
<?php endif; ?>
<?php include("foot.inc"); ?>
