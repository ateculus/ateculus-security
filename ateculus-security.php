<?php
/**
 * Plugin Name: Ateculus Security
 * Plugin URI:  https://ateculus.com
 * Description: Brute-force login protection, IP banning, whole-site blocking, XML-RPC blocking, bad bot filtering, and security hardening.
 * Version:     1.1.1
 * Author:      Ateculus
 * Author URI:  https://ateculus.com
 * License:     GPL-2.0+
 * Text Domain: ateculus-security
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'ASEC_VERSION', '1.1.1' );
define( 'ASEC_PATH',    plugin_dir_path( __FILE__ ) );
define( 'ASEC_URL',     plugin_dir_url( __FILE__ ) );

require_once ASEC_PATH . 'includes/class-db.php';
require_once ASEC_PATH . 'includes/class-guard.php';
require_once ASEC_PATH . 'includes/class-blocker.php';
require_once ASEC_PATH . 'includes/class-hardening.php';
require_once ASEC_PATH . 'includes/class-login-url.php';
require_once ASEC_PATH . 'includes/class-404-guard.php';
require_once ASEC_PATH . 'includes/class-honeypot.php';
require_once ASEC_PATH . 'includes/class-alerts.php';
require_once ASEC_PATH . 'includes/class-login-log.php';
require_once ASEC_PATH . 'admin/class-admin-page.php';

register_activation_hook( __FILE__, array( 'ASEC_DB',    'install'             ) );
register_activation_hook( __FILE__, array( 'ASEC_Guard', 'refresh_cloudflare_ips' ) );
register_deactivation_hook( __FILE__, array( 'ASEC_DB',  'cleanup_cron'        ) );

new ASEC_Admin_Page();

add_action( 'plugins_loaded', function () {
	ASEC_DB::maybe_upgrade();

	add_action( 'init',            array( 'ASEC_Blocker',   'check' ),              1 );
	add_action( 'init',            array( 'ASEC_Hardening', 'apply' ),              1 );
	add_action( 'wp_login_failed', array( 'ASEC_Guard',     'on_failed_login'       ) );
	add_action( 'asec_cleanup',    array( 'ASEC_DB',        'purge_old_attempts'    ) );
	add_action( 'asec_refresh_cf', array( 'ASEC_Guard',     'refresh_cloudflare_ips') );

	ASEC_Login_URL::init();
	ASEC_404_Guard::init();
	ASEC_Honeypot::init();
	ASEC_Alerts::init();
	ASEC_Login_Log::init();
} );
