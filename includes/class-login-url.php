<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Login_URL {

	const COOKIE = 'asec_gate';

	public static function init() {
		$slug = self::get_slug();
		if ( empty( $slug ) ) return;

		add_filter( 'login_url',        array( __CLASS__, 'filter_login_url' ),    10, 3 );
		add_filter( 'logout_url',       array( __CLASS__, 'filter_wp_login_refs' ), 10, 2 );
		add_filter( 'lostpassword_url', array( __CLASS__, 'filter_wp_login_refs' ), 10, 2 );

		add_action( 'init',       array( __CLASS__, 'handle_request' ),  1 );
		add_action( 'login_init', array( __CLASS__, 'gate_login_page' )    );
	}

	// ── Request handling ───────────────────────────────────────────────────

	public static function handle_request() {
		$slug = self::get_slug();
		if ( empty( $slug ) ) return;

		$uri  = $_SERVER['REQUEST_URI'] ?? '';
		$path = trim( parse_url( $uri, PHP_URL_PATH ), '/' );

		// Custom slug → set gate cookie, redirect to the real wp-login.php
		if ( $path === $slug ) {
			self::set_gate_cookie();
			$qs       = $_SERVER['QUERY_STRING'] ?? '';
			$redirect = home_url( '/wp-login.php' ) . ( $qs ? '?' . $qs : '' );
			wp_safe_redirect( $redirect );
			exit;
		}

		// Block direct wp-admin for visitors without a gate cookie and not logged in
		$is_admin = strpos( $uri, '/wp-admin' ) !== false;
		$is_ajax  = strpos( $uri, 'admin-ajax.php' ) !== false;
		$is_apost = strpos( $uri, 'admin-post.php' ) !== false;

		if ( $is_admin && ! $is_ajax && ! $is_apost && ! is_user_logged_in() && ! self::has_gate_cookie() ) {
			wp_safe_redirect( home_url( '/' ), 302 );
			exit;
		}
	}

	public static function gate_login_page() {
		// Always allow: password reset links (?key=...)
		if ( ! empty( $_GET['key'] ) ) return;

		// Always allow: password-related and registration actions
		$open_actions = array( 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register' );
		if ( in_array( $_GET['action'] ?? '', $open_actions, true ) ) return;

		// Always allow: post-logout redirect
		if ( ! empty( $_GET['loggedout'] ) ) return;

		// Allow if gate cookie is valid — refresh it while we're here
		if ( self::has_gate_cookie() ) {
			self::set_gate_cookie();
			return;
		}

		// No valid access path → redirect to homepage
		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}

	// ── Gate cookie ────────────────────────────────────────────────────────

	private static function gate_secret() {
		$secret = get_option( 'asec_gate_secret', '' );
		if ( empty( $secret ) ) {
			$secret = wp_generate_password( 32, false );
			update_option( 'asec_gate_secret', $secret );
		}
		return $secret;
	}

	private static function gate_value() {
		return hash_hmac( 'sha256', home_url(), self::gate_secret() );
	}

	private static function set_gate_cookie() {
		$days    = max( 1, (int) get_option( 'asec_gate_cookie_days', 7 ) );
		$value   = self::gate_value();
		$expire  = time() + $days * DAY_IN_SECONDS;
		$host    = parse_url( home_url(), PHP_URL_HOST );
		$secure  = is_ssl();
		setcookie( self::COOKIE, $value, $expire, '/', $host, $secure, true );
		$_COOKIE[ self::COOKIE ] = $value; // make it available in the same request
	}

	private static function has_gate_cookie() {
		$cookie = $_COOKIE[ self::COOKIE ] ?? '';
		if ( empty( $cookie ) ) return false;
		return hash_equals( self::gate_value(), $cookie );
	}

	// ── URL filters ────────────────────────────────────────────────────────

	public static function filter_login_url( $url, $redirect, $force_reauth ) {
		$slug   = self::get_slug();
		$custom = home_url( '/' . $slug . '/' );
		if ( $redirect )     $custom = add_query_arg( 'redirect_to', urlencode( $redirect ), $custom );
		if ( $force_reauth ) $custom = add_query_arg( 'reauth', '1', $custom );
		return $custom;
	}

	public static function filter_wp_login_refs( $url ) {
		$slug = self::get_slug();
		if ( empty( $slug ) ) return $url;
		$base = rtrim( home_url( '/' ), '/' );
		return str_replace( $base . '/wp-login.php', $base . '/' . $slug . '/', $url );
	}

	// ── Helpers ────────────────────────────────────────────────────────────

	public static function get_slug() {
		return trim( get_option( 'asec_login_slug', '' ), '/' );
	}
}
