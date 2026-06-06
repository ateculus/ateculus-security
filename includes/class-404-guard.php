<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_404_Guard {

	// URI substrings that indicate active scanning/probing — instant ban
	private static $probe_patterns = array(
		'.aws/', '.kube/', '.ssh/', '.git/',
		'.docker', '.dockerenv', '.env', '.ENV', '.netrc', '.npmrc', '.pypirc',
		'wp-config', 'credentials.json', 'serviceAccountKey.json',
		'service-account.json', 'docker-compose', 'docker-compose.yml',
		'_ignition/', 'actuator/', '_profiler/',
		'settings.py', 'config/secrets', 'application.properties',
		'.aws/config', '.aws/credentials', '.kube/config', '.netrc',
		'.ssh/id_rsa', '.ssh/id_dsa', '.ssh/id_ed25519',
		'appsettings.json', 'appsettings.Production', 'appsettings.Development',
		'web.config', 'secrets.json', 'secrets.yml',
		'application.yml', 'config.env', 'firebase-config.json',
		'heapdump', '.pypirc', '.npmrc',
	);

	public static function init() {
		add_action( 'template_redirect', array( __CLASS__, 'track' ), 1 );
	}

	public static function track() {
		if ( ! is_404() ) return;

		$ip = ASEC_Guard::get_ip();
		if ( ! $ip || ASEC_Guard::is_whitelisted( $ip ) ) return;

		// Already banned — blocker handles the deny on next request; skip tracking
		if ( ASEC_DB::is_banned( $ip ) ) return;

		$uri      = $_SERVER['REQUEST_URI'] ?? '';
		$duration = (int) get_option( 'asec_ban_duration_hours', 24 );

		// Instant ban for known credential/exploit probe paths
		if ( get_option( 'asec_404_instant_ban', 1 ) ) {
			foreach ( self::$probe_patterns as $pattern ) {
				if ( stripos( $uri, $pattern ) !== false ) {
					ASEC_DB::add_ban( $ip, $duration, 1, 'scan_probe' );
					ASEC_Blocker::deny( $ip, 'scan_probe' );
					return;
				}
			}
		}

		// Rate-limit: ban after X 404s in Y minutes
		if ( get_option( 'asec_404_enabled', 1 ) ) {
			$max    = (int) get_option( 'asec_404_max', 20 );
			$window = (int) get_option( 'asec_404_window_minutes', 10 );

			ASEC_DB::log_404( $ip, $uri );

			if ( ASEC_DB::count_404s( $ip, $window ) >= $max ) {
				ASEC_DB::add_ban( $ip, $duration, ASEC_DB::count_404s( $ip, $window ), '404_flood' );
			}
		}
	}
}
