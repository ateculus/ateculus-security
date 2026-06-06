<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Guard {

	// Cloudflare published IPv4 ranges — https://www.cloudflare.com/ips-v4
	private static $cloudflare_ranges = array(
		'103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
		'104.16.0.0/13',   '104.24.0.0/14',   '108.162.192.0/18',
		'131.0.72.0/22',   '141.101.64.0/18', '162.158.0.0/15',
		'172.64.0.0/13',   '173.245.48.0/20', '188.114.96.0/20',
		'190.93.240.0/20', '197.234.240.0/22','198.41.128.0/17',
	);

	// Cloudflare published IPv6 ranges — https://www.cloudflare.com/ips-v6
	private static $cloudflare_ranges_v6 = array(
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
		'2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	public static function on_failed_login( $username ) {
		$ip = self::get_ip();
		if ( ! $ip || self::is_whitelisted( $ip ) || ASEC_DB::is_banned( $ip ) ) return;

		ASEC_DB::log_attempt( $ip );

		$max_attempts = (int) get_option( 'asec_max_attempts', 5 );
		$window       = (int) get_option( 'asec_window_minutes', 60 );
		$duration     = (int) get_option( 'asec_ban_duration_hours', 24 );

		if ( ASEC_DB::count_attempts( $ip, $window ) >= $max_attempts ) {
			ASEC_DB::add_ban( $ip, $duration, ASEC_DB::count_attempts( $ip, $window ), 'brute_force' );
		}
	}

	/**
	 * Returns the real visitor IP.
	 * When behind Cloudflare, REMOTE_ADDR is a CF edge IP — we read
	 * CF-Connecting-IP instead, but only after confirming REMOTE_ADDR
	 * is actually a Cloudflare IP to prevent header spoofing.
	 */
	public static function get_ip() {
		$remote = $_SERVER['REMOTE_ADDR'] ?? '';

		if ( self::is_cloudflare_ip( $remote ) ) {
			$cf_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
			if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
				return $cf_ip;
			}
		}

		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';
	}

	public static function is_behind_cloudflare() {
		$remote = $_SERVER['REMOTE_ADDR'] ?? '';

		// Direct: REMOTE_ADDR is a Cloudflare IP (no upstream real_ip substitution)
		if ( self::is_cloudflare_ip( $remote ) ) return true;

		// Nginx/Apache real_ip scenario: upstream already replaced REMOTE_ADDR with
		// the real visitor IP from CF-Connecting-IP, so check they match.
		$cf_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
		if ( ! empty( $cf_ip ) && $cf_ip === $remote ) return true;

		return false;
	}

	private static function is_cloudflare_ip( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			foreach ( self::get_cf_ranges_v4() as $range ) {
				if ( self::ip_in_cidr( $ip, $range ) ) return true;
			}
		} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			foreach ( self::get_cf_ranges_v6() as $range ) {
				if ( self::ip6_in_cidr( $ip, $range ) ) return true;
			}
		}
		return false;
	}

	// Returns cached ranges from Cloudflare's API, falling back to the hardcoded list
	private static function get_cf_ranges_v4() {
		$cached = get_option( 'asec_cf_ips_v4', array() );
		return ! empty( $cached ) ? $cached : self::$cloudflare_ranges;
	}

	private static function get_cf_ranges_v6() {
		$cached = get_option( 'asec_cf_ips_v6', array() );
		return ! empty( $cached ) ? $cached : self::$cloudflare_ranges_v6;
	}

	// Fetches current IP ranges from Cloudflare's official published endpoints
	public static function refresh_cloudflare_ips() {
		$updated = false;

		$v4 = wp_remote_get( 'https://www.cloudflare.com/ips-v4', array( 'timeout' => 10 ) );
		if ( ! is_wp_error( $v4 ) && 200 === wp_remote_retrieve_response_code( $v4 ) ) {
			$ranges = array_values( array_filter( array_map( 'trim', explode( "\n", wp_remote_retrieve_body( $v4 ) ) ) ) );
			if ( count( $ranges ) >= 5 ) { // sanity check — CF publishes 15+ ranges
				update_option( 'asec_cf_ips_v4', $ranges );
				$updated = true;
			}
		}

		$v6 = wp_remote_get( 'https://www.cloudflare.com/ips-v6', array( 'timeout' => 10 ) );
		if ( ! is_wp_error( $v6 ) && 200 === wp_remote_retrieve_response_code( $v6 ) ) {
			$ranges = array_values( array_filter( array_map( 'trim', explode( "\n", wp_remote_retrieve_body( $v6 ) ) ) ) );
			if ( count( $ranges ) >= 3 ) {
				update_option( 'asec_cf_ips_v6', $ranges );
				$updated = true;
			}
		}

		if ( $updated ) {
			update_option( 'asec_cf_ips_updated', current_time( 'timestamp' ) );
		}

		return $updated;
	}

	private static function ip_in_cidr( $ip, $cidr ) {
		list( $subnet, $bits ) = explode( '/', $cidr );
		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		$mask        = $bits == 0 ? 0 : ( ~0 << ( 32 - (int) $bits ) );
		return ( $ip_long & $mask ) === ( $subnet_long & $mask );
	}

	private static function ip6_in_cidr( $ip, $cidr ) {
		list( $subnet, $bits ) = explode( '/', $cidr );
		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );
		if ( $ip_bin === false || $subnet_bin === false ) return false;
		$bits = (int) $bits;
		for ( $i = 0; $i < 16; $i++ ) {
			if ( $bits <= 0 ) break;
			$mask = $bits >= 8 ? 0xff : ( ( 0xff << ( 8 - $bits ) ) & 0xff );
			if ( ( ord( $ip_bin[ $i ] ) & $mask ) !== ( ord( $subnet_bin[ $i ] ) & $mask ) ) return false;
			$bits -= 8;
		}
		return true;
	}

	public static function get_whitelist() {
		$raw = get_option( 'asec_whitelist_ips', '' );
		if ( empty( $raw ) ) return array();
		return array_values( array_filter( array_map( 'trim', explode( "\n", $raw ) ) ) );
	}

	public static function is_whitelisted( $ip ) {
		return in_array( $ip, self::get_whitelist(), true );
	}
}
