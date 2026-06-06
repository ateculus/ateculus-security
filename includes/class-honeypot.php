<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Honeypot {

	public static function init() {
		if ( ! get_option( 'asec_honeypot_enabled', 1 ) ) return;
		add_action( 'login_form',  array( __CLASS__, 'add_field' ) );
		add_filter( 'authenticate', array( __CLASS__, 'check' ), 1, 3 );
	}

	public static function add_field() {
		// Visually hidden from real users; bots that auto-fill forms will populate it
		echo '<div style="display:none;visibility:hidden;position:absolute;left:-9999px;" aria-hidden="true">';
		echo '<input type="text" name="asec_hp" value="" tabindex="-1" autocomplete="off" />';
		echo '</div>';
	}

	public static function check( $user, $username, $password ) {
		// Only check on actual login form submissions
		if ( empty( $_POST['log'] ) ) return $user;
		// Field not present means request came from somewhere other than our login form — skip
		if ( ! isset( $_POST['asec_hp'] ) ) return $user;

		if ( '' !== $_POST['asec_hp'] ) {
			$ip = ASEC_Guard::get_ip();
			if ( $ip && ! ASEC_Guard::is_whitelisted( $ip ) && ! ASEC_DB::is_banned( $ip ) ) {
				$duration = (int) get_option( 'asec_ban_duration_hours', 24 );
				ASEC_DB::add_ban( $ip, $duration, 1, 'honeypot' );
			}
			// Return a generic error — don't tell the bot what triggered it
			return new WP_Error( 'login_failed', __( '<strong>Error:</strong> Incorrect username or password.', 'ateculus-security' ) );
		}

		return $user;
	}
}
