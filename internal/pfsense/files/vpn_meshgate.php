<?php
/*
 * vpn_meshgate.php
 *
 * VPN > meshgate: the meshgate dashboard inside the pfSense GUI, behind the
 * pfSense login. Installed by `meshgate pfsense install`; the dashboard's
 * API calls go through meshgate_api.php. The page uses the full window: the
 * frame fills everything below pfSense's menu and follows window resizes.
 */

require_once("guiconfig.inc");

$opt = config_get_path("installedpackages/meshgate/opt", "");
$pgtitle = array(gettext("VPN"), "meshgate");
include("head.inc");
?>
<style>
	/* This page only: use the whole width, not pfSense's fixed column. */
	body > .container, .container { box-sizing: border-box; width: 100%; max-width: none; padding-left: 12px; padding-right: 12px; }
	#mg-bar { display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; justify-content: flex-end; margin: -6px 0 8px; font-size: 13px; }
	#mg-frame { box-sizing: border-box; display: block; width: 100%; min-height: 420px; border: 1px solid #ddd; border-radius: 6px; }
</style>
<div id="mg-bar">
<?php if ($opt !== ""): ?>
	<a href="/firewall_rules.php?if=<?=htmlspecialchars($opt)?>">Firewall &gt; Rules &gt; MESHGATE</a>
<?php endif; ?>
	<a href="/meshgate/index.html" target="_blank" rel="noopener" class="btn btn-xs btn-default"><i class="fa fa-expand"></i> Full screen</a>
</div>
<iframe id="mg-frame" src="/meshgate/index.html" title="meshgate"></iframe>
<script>
// Fill the window below pfSense's menu, and keep doing so on resize.
(function () {
	var f = document.getElementById("mg-frame");
	function fit() {
		var h = window.innerHeight - f.getBoundingClientRect().top - 12;
		f.style.height = Math.max(420, h) + "px";
	}
	window.addEventListener("resize", fit);
	window.addEventListener("load", fit);
	fit();
})();
</script>
<?php include("foot.inc"); ?>
