<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Hardening {

	public static function apply() {
		// Block XML-RPC entirely
		if ( get_option( 'asec_block_xmlrpc', 1 ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_xmlrpc_server_class', '__return_false' );

			$uri = $_SERVER['REQUEST_URI'] ?? '';
			if ( strpos( $uri, 'xmlrpc.php' ) !== false ) {
				status_header( 403 );
				nocache_headers();
				wp_die( 'XML-RPC is disabled on this site.', '403 — Forbidden', array( 'response' => 403 ) );
			}
		}

		// Block user enumeration via ?author= queries
		if ( get_option( 'asec_block_user_enum', 1 ) ) {
			add_action( 'init', array( __CLASS__, 'block_user_enum' ), 2 );
		}

		// Remove WordPress version from head and feeds
		if ( get_option( 'asec_hide_wp_version', 1 ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		// Disable REST API for non-logged-in users
		if ( get_option( 'asec_restrict_rest_api', 0 ) ) {
			add_filter( 'rest_authentication_errors', array( __CLASS__, 'restrict_rest_api' ) );
		}

		// Remove X-Pingback header
		if ( get_option( 'asec_block_xmlrpc', 1 ) ) {
			add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		}

		// Disable theme/plugin file editing in wp-admin
		if ( get_option( 'asec_disable_file_edit', 0 ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Security headers
		if ( get_option( 'asec_security_headers', 1 ) ) {
			add_filter( 'wp_headers',   array( __CLASS__, 'add_security_headers' ) );
			add_action( 'admin_init',   array( __CLASS__, 'send_security_headers' ) );
			add_action( 'login_init',   array( __CLASS__, 'send_security_headers' ) );
		}
	}

	public static function add_security_headers( $headers ) {
		$headers['X-Frame-Options']        = 'SAMEORIGIN';
		$headers['X-Content-Type-Options'] = 'nosniff';
		$headers['X-XSS-Protection']       = '1; mode=block';
		$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
		$headers['Permissions-Policy']     = 'camera=(), microphone=(), geolocation=()';
		if ( is_ssl() ) {
			$headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
		}
		return $headers;
	}

	public static function send_security_headers() {
		if ( headers_sent() ) return;
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-XSS-Protection: 1; mode=block' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
		}
	}

	public static function block_user_enum() {
		if ( ! is_admin() && isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
			wp_die( 'User enumeration is disabled on this site.', '403 — Forbidden', array( 'response' => 403 ) );
		}
	}

	public static function restrict_rest_api( $result ) {
		if ( ! empty( $result ) ) return $result;
		if ( ! is_user_logged_in() ) {
			return new WP_Error( 'rest_not_logged_in', 'REST API access is restricted to authenticated users.', array( 'status' => 401 ) );
		}
		return $result;
	}

	public static function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
}
