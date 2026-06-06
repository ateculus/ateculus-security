<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Blocker {

	// Known scanner / attack tool user agents
	private static $bad_agents = array(
		'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei',
		'dirbuster', 'gobuster', 'wfuzz', 'hydra', 'metasploit',
		'acunetix', 'nessus', 'openvas', 'havij', 'pangolin',
		'w3af', 'skipfish', 'burpsuite', 'zap/', 'arachni',
		'python-requests/2', 'go-http-client', 'curl/7',
	);

	public static function check() {
		// Never interfere with server-side cron
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) return;

		$ip = ASEC_Guard::get_ip();
		if ( ! $ip || ASEC_Guard::is_whitelisted( $ip ) ) return;

		$uri   = $_SERVER['REQUEST_URI'] ?? '';
		$scope = get_option( 'asec_block_scope', 'admin_only' );

		// Determine whether this request falls within the block scope
		$in_scope = false;
		if ( $scope === 'entire_site' ) {
			$in_scope = true;
		} elseif ( $scope === 'admin_only' ) {
			$is_login = strpos( $uri, 'wp-login.php' ) !== false;
			$is_admin = strpos( $uri, '/wp-admin' ) !== false;
			$is_ajax  = strpos( $uri, 'admin-ajax.php' ) !== false;
			$in_scope = ( $is_login || $is_admin ) && ! $is_ajax;
		}

		if ( ! $in_scope ) {
			// Even outside scope: still block bad bots if enabled
			self::maybe_block_bad_bot( $ip );
			return;
		}

		if ( ASEC_DB::is_banned( $ip ) ) {
			self::deny( $ip, 'banned' );
		}

		self::maybe_block_bad_bot( $ip );
	}

	private static function maybe_block_bad_bot( $ip ) {
		if ( ! get_option( 'asec_block_bad_bots', 1 ) ) return;

		$agent = strtolower( $_SERVER['HTTP_USER_AGENT'] ?? '' );
		if ( empty( $agent ) ) return;

		foreach ( self::$bad_agents as $signature ) {
			if ( strpos( $agent, $signature ) !== false ) {
				// Auto-ban the IP
				if ( ! ASEC_DB::is_banned( $ip ) ) {
					$duration = (int) get_option( 'asec_ban_duration_hours', 24 );
					ASEC_DB::add_ban( $ip, $duration, 0, 'bad_bot' );
				}
				self::deny( $ip, 'bad_bot' );
			}
		}
	}

	public static function deny( $ip, $reason = 'banned' ) {
		$message = get_option( 'asec_ban_message', 'Access denied. Your IP address has been blocked. Please contact the site administrator if you believe this is an error.' );
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html( $message ),
			'403 — Access Denied',
			array( 'response' => 403 )
		);
	}
}
