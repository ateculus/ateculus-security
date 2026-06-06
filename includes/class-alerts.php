<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Alerts {

	private static $reason_labels = array(
		'brute_force' => 'Brute Force Login',
		'bad_bot'     => 'Bad Bot (Scanner UA)',
		'scan_probe'  => 'Scan Probe (credential/exploit path)',
		'404_flood'   => '404 Flood',
		'honeypot'    => 'Honeypot Triggered',
		'manual'      => 'Manual Ban',
	);

	public static function init() {
		if ( ! get_option( 'asec_alerts_enabled', 0 ) ) return;
		add_action( 'asec_ip_banned', array( __CLASS__, 'on_ban' ), 10, 3 );
	}

	public static function on_ban( $ip, $reason, $attempts ) {
		$to = get_option( 'asec_alerts_email', '' );
		if ( empty( $to ) ) {
			$to = get_option( 'admin_email' );
		}
		if ( empty( $to ) ) return;

		$site    = get_bloginfo( 'name' );
		$label   = self::$reason_labels[ $reason ] ?? $reason;
		$subject = sprintf( '[%s] Security Alert: IP Banned — %s', $site, $label );

		$body  = "An IP address has been automatically banned on {$site}.\n\n";
		$body .= "IP Address : {$ip}\n";
		$body .= "Reason     : {$label}\n";
		$body .= "Attempts   : " . ( $attempts > 0 ? $attempts : 'N/A' ) . "\n";
		$body .= "Time (UTC) : " . gmdate( 'Y-m-d H:i:s' ) . "\n\n";
		$body .= "Manage bans: " . admin_url( 'admin.php?page=ateculus-security&tab=bans' ) . "\n";

		wp_mail( $to, $subject, $body );
	}
}
