<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_DB {

	public static function install() {
		global $wpdb;
		$charset = $wpdb->get_charset_collate();

		$sql_attempts = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_attempts (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			attempted_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY ip (ip),
			KEY attempted_at (attempted_at)
		) $charset;";

		$sql_bans = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_bans (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			banned_at datetime NOT NULL,
			expires_at datetime DEFAULT NULL,
			attempts int(11) NOT NULL DEFAULT 0,
			reason varchar(100) NOT NULL DEFAULT 'brute_force',
			PRIMARY KEY (id),
			UNIQUE KEY ip (ip),
			KEY expires_at (expires_at)
		) $charset;";

		$sql_404s = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_404s (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			uri varchar(500) NOT NULL DEFAULT '',
			hit_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY ip_hit (ip, hit_at)
		) $charset;";

		$sql_logins = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_logins (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			username varchar(200) NOT NULL DEFAULT '',
			logged_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY ip (ip),
			KEY logged_at (logged_at)
		) $charset;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_attempts );
		dbDelta( $sql_bans );
		dbDelta( $sql_404s );
		dbDelta( $sql_logins );

		update_option( 'asec_db_version', '1.2' );

		if ( ! wp_next_scheduled( 'asec_cleanup' ) ) {
			wp_schedule_event( time(), 'hourly', 'asec_cleanup' );
		}
		if ( ! wp_next_scheduled( 'asec_refresh_cf' ) ) {
			wp_schedule_event( time(), 'daily', 'asec_refresh_cf' );
		}
	}

	// Creates any missing tables for sites that installed before the current version
	public static function maybe_upgrade() {
		if ( get_option( 'asec_db_version', '1.0' ) === '1.2' ) return;
		global $wpdb;
		$charset = $wpdb->get_charset_collate();
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta( "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_404s (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			uri varchar(500) NOT NULL DEFAULT '',
			hit_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY ip_hit (ip, hit_at)
		) $charset;" );

		dbDelta( "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}asec_logins (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			ip varchar(45) NOT NULL,
			username varchar(200) NOT NULL DEFAULT '',
			logged_at datetime NOT NULL,
			PRIMARY KEY (id),
			KEY ip (ip),
			KEY logged_at (logged_at)
		) $charset;" );

		update_option( 'asec_db_version', '1.2' );
	}

	public static function cleanup_cron() {
		wp_clear_scheduled_hook( 'asec_cleanup' );
		wp_clear_scheduled_hook( 'asec_refresh_cf' );
	}

	public static function log_attempt( $ip ) {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'asec_attempts',
			array( 'ip' => $ip, 'attempted_at' => current_time( 'mysql' ) ),
			array( '%s', '%s' )
		);
	}

	public static function count_attempts( $ip, $window_minutes ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $window_minutes * 60 ) );
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}asec_attempts WHERE ip = %s AND attempted_at >= %s",
			$ip, $since
		) );
	}

	public static function add_ban( $ip, $duration_hours, $attempts, $reason = 'brute_force' ) {
		global $wpdb;
		$already_banned = self::is_banned( $ip );
		$expires = $duration_hours > 0
			? gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) + ( $duration_hours * 3600 ) )
			: null;
		$wpdb->replace(
			$wpdb->prefix . 'asec_bans',
			array(
				'ip'         => $ip,
				'banned_at'  => current_time( 'mysql' ),
				'expires_at' => $expires,
				'attempts'   => $attempts,
				'reason'     => $reason,
			),
			array( '%s', '%s', '%s', '%d', '%s' )
		);
		// Fire alert only on a new ban, not when replacing an existing one
		if ( ! $already_banned ) {
			do_action( 'asec_ip_banned', $ip, $reason, $attempts );
		}
	}

	public static function is_banned( $ip ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT expires_at FROM {$wpdb->prefix}asec_bans WHERE ip = %s",
			$ip
		) );
		if ( ! $row ) return false;
		if ( is_null( $row->expires_at ) ) return true;
		return strtotime( $row->expires_at ) > current_time( 'timestamp' );
	}

	public static function unban( $id ) {
		global $wpdb;
		$wpdb->delete( $wpdb->prefix . 'asec_bans', array( 'id' => $id ), array( '%d' ) );
	}

	public static function ban_by_ip( $ip ) {
		global $wpdb;
		$wpdb->delete( $wpdb->prefix . 'asec_bans', array( 'ip' => $ip ), array( '%s' ) );
	}

	public static function get_bans() {
		global $wpdb;
		return $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}asec_bans ORDER BY banned_at DESC" );
	}

	public static function get_recent_attempts( $limit = 100 ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, COUNT(*) as count, MAX(attempted_at) as last_attempt
			 FROM {$wpdb->prefix}asec_attempts
			 GROUP BY ip
			 ORDER BY last_attempt DESC
			 LIMIT %d",
			$limit
		) );
	}

	public static function purge_old_attempts() {
		global $wpdb;
		$wpdb->query( "DELETE FROM {$wpdb->prefix}asec_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 7 DAY)" );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}asec_404s WHERE hit_at < DATE_SUB(NOW(), INTERVAL 7 DAY)" );
		$wpdb->query( "DELETE FROM {$wpdb->prefix}asec_logins WHERE logged_at < DATE_SUB(NOW(), INTERVAL 90 DAY)" );
		// Also purge expired bans older than 30 days
		$wpdb->query( "DELETE FROM {$wpdb->prefix}asec_bans WHERE expires_at IS NOT NULL AND expires_at < DATE_SUB(NOW(), INTERVAL 30 DAY)" );
	}

	public static function log_404( $ip, $uri ) {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'asec_404s',
			array( 'ip' => $ip, 'uri' => substr( $uri, 0, 500 ), 'hit_at' => current_time( 'mysql' ) ),
			array( '%s', '%s', '%s' )
		);
	}

	public static function count_404s( $ip, $window_minutes ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( $window_minutes * 60 ) );
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->prefix}asec_404s WHERE ip = %s AND hit_at >= %s",
			$ip, $since
		) );
	}

	public static function log_login( $ip, $username ) {
		global $wpdb;
		$wpdb->insert(
			$wpdb->prefix . 'asec_logins',
			array( 'ip' => $ip, 'username' => $username, 'logged_at' => current_time( 'mysql' ) ),
			array( '%s', '%s', '%s' )
		);
	}

	public static function get_recent_logins( $limit = 200 ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, username, logged_at FROM {$wpdb->prefix}asec_logins ORDER BY logged_at DESC LIMIT %d",
			$limit
		) );
	}

	public static function get_recent_404s( $limit = 100 ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, COUNT(*) as count, MAX(hit_at) as last_hit
			 FROM {$wpdb->prefix}asec_404s
			 GROUP BY ip
			 ORDER BY last_hit DESC
			 LIMIT %d",
			$limit
		) );
	}

	public static function get_recent_404_hits( $limit = 300 ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, uri, hit_at
			 FROM {$wpdb->prefix}asec_404s
			 ORDER BY hit_at DESC
			 LIMIT %d",
			$limit
		) );
	}
}
