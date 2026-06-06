<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Login_Log {

	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'log' ), 10, 2 );
	}

	public static function log( $user_login, $user ) {
		$ip = ASEC_Guard::get_ip();
		if ( $ip ) {
			ASEC_DB::log_login( $ip, $user_login );
		}
	}
}
