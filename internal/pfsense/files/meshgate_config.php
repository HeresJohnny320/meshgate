<?php
/*
 * meshgate_config.php
 *
 * Edits pfSense's config.xml for `meshgate pfsense install|remove`:
 *   - VPN > meshgate menu entry
 *   - meshgate's WireGuard interface assigned as MESHGATE (type None, so
 *     meshgate keeps managing its address), giving it a tab under
 *     Firewall > Rules
 *   - one "pass any" rule on that tab, added only on the first install so a
 *     rule you narrowed or deleted is never widened again
 *
 *   php -f meshgate_config.php install <iface>
 *   php -f meshgate_config.php remove
 */

require_once("config.inc");
require_once("util.inc");
require_once("filter.inc");

$menu_url = "/vpn_meshgate.php";
$state = config_get_path("installedpackages/meshgate", array());
if (!is_array($state)) {
	$state = array();
}

function without_menu($url) {
	$keep = array();
	foreach (config_get_path("installedpackages/menu", array()) as $m) {
		if (is_array($m) && ($m['url'] ?? '') !== $url) {
			$keep[] = $m;
		}
	}
	return $keep;
}

switch ($argv[1] ?? '') {
case "install":
	$iface = $argv[2] ?? '';
	if (!preg_match('/^[a-z][a-z0-9_]{0,14}$/', $iface)) {
		fwrite(STDERR, "bad interface name\n");
		exit(1);
	}

	$menus = without_menu($menu_url);
	$menus[] = array('name' => 'meshgate', 'tooltiptext' => 'meshgate mesh VPN', 'section' => 'VPN', 'url' => $menu_url);
	config_set_path("installedpackages/menu", $menus);

	$opt = '';
	foreach (config_get_path("interfaces", array()) as $name => $cfg) {
		if (($cfg['if'] ?? '') === $iface) {
			$opt = $name;
		}
	}
	if ($opt === '') {
		for ($i = 1; config_get_path("interfaces/opt{$i}") !== null; $i++);
		$opt = "opt{$i}";
		config_set_path("interfaces/{$opt}", array('descr' => 'MESHGATE', 'if' => $iface, 'enable' => '', 'spoofmac' => ''));
	}

	if (empty($state['seeded'])) {
		$rules = config_get_path("filter/rule", array());
		$rules[] = array(
			'type' => 'pass',
			'interface' => $opt,
			'ipprotocol' => 'inet',
			'source' => array('any' => ''),
			'destination' => array('any' => ''),
			'descr' => 'meshgate default: mesh devices may reach anything (narrow or replace this)',
			'tracker' => (string)(int)microtime(true),
			'created' => make_config_revision_entry(null, 'meshgate'),
		);
		config_set_path("filter/rule", $rules);
		$state['seeded'] = '1';
	}

	$state['iface'] = $iface;
	$state['opt'] = $opt;
	config_set_path("installedpackages/meshgate", $state);
	write_config("meshgate: VPN menu, MESHGATE interface and default rule");
	filter_configure();
	echo $opt, "\n";
	exit(0);

case "remove":
	config_set_path("installedpackages/menu", without_menu($menu_url));
	$opt = $state['opt'] ?? '';
	if ($opt !== '' && config_get_path("interfaces/{$opt}") !== null) {
		$keep = array();
		foreach (config_get_path("filter/rule", array()) as $r) {
			if (($r['interface'] ?? '') !== $opt) {
				$keep[] = $r;
			}
		}
		config_set_path("filter/rule", $keep);
		// Still referenced elsewhere (floating or NAT rules)? Keep it assigned.
		$used = false;
		foreach (array("filter/rule", "nat/rule", "nat/outbound/rule", "nat/onetoone") as $path) {
			foreach (config_get_path($path, array()) as $r) {
				if (is_array($r) && in_array($opt, explode(",", $r['interface'] ?? ''), true)) {
					$used = true;
				}
			}
		}
		if ($used) {
			echo "MESHGATE ({$opt}) is still used by other rules; left assigned\n";
		} else {
			config_del_path("interfaces/{$opt}");
		}
	}
	config_del_path("installedpackages/meshgate");
	write_config("meshgate: removed VPN menu and MESHGATE interface");
	filter_configure();
	exit(0);
}

fwrite(STDERR, "usage: meshgate_config.php install <iface> | remove\n");
exit(2);
