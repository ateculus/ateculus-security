<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class ASEC_Admin_Page {

	public function __construct() {
		add_action( 'admin_menu',            array( $this, 'add_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_post_asec_save_settings',  array( $this, 'save_settings' ) );
		add_action( 'admin_post_asec_unban',           array( $this, 'unban_ip' ) );
		add_action( 'admin_post_asec_manual_ban',      array( $this, 'manual_ban' ) );
		add_action( 'admin_post_asec_refresh_cf_ips',  array( $this, 'refresh_cf_ips' ) );
		add_filter( 'admin_footer_text',               array( $this, 'footer_text' ) );
	}

	public function footer_text( $text ) {
		if ( isset( $_GET['page'] ) && $_GET['page'] === 'ateculus-security' ) {
			return 'Thank you for using <strong>Ateculus-Security</strong> &mdash; built by <a href="https://www.ateculus.com" target="_blank">Ateculus</a>.';
		}
		return $text;
	}

	public function add_menu() {
		add_menu_page(
			'Ateculus Security',
			'Ateculus-Security',
			'manage_options',
			'ateculus-security',
			array( $this, 'render_page' ),
			'dashicons-shield',
			80
		);
	}

	public function enqueue( $hook ) {
		if ( $hook !== 'toplevel_page_ateculus-security' ) return;
		wp_enqueue_style( 'asec-admin', ASEC_URL . 'admin/css/admin.css', array(), ASEC_VERSION );
	}

	public function save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
		check_admin_referer( 'asec_settings' );

		$checkboxes = array(
			'asec_block_xmlrpc', 'asec_block_user_enum', 'asec_hide_wp_version',
			'asec_restrict_rest_api', 'asec_block_bad_bots',
			'asec_404_enabled', 'asec_404_instant_ban',
			'asec_security_headers', 'asec_disable_file_edit',
			'asec_honeypot_enabled', 'asec_alerts_enabled',
		);
		foreach ( $checkboxes as $key ) {
			update_option( $key, isset( $_POST[ $key ] ) ? 1 : 0 );
		}

		update_option( 'asec_404_max',             max( 1, absint( $_POST['asec_404_max'] ?? 20 ) ) );
		update_option( 'asec_404_window_minutes',  max( 1, absint( $_POST['asec_404_window_minutes'] ?? 10 ) ) );
		update_option( 'asec_alerts_email',        sanitize_email( $_POST['asec_alerts_email'] ?? '' ) );
		update_option( 'asec_block_scope',         sanitize_key( $_POST['asec_block_scope'] ?? 'admin_only' ) );
		update_option( 'asec_max_attempts',        max( 1, absint( $_POST['asec_max_attempts'] ?? 5 ) ) );
		update_option( 'asec_window_minutes',      max( 1, absint( $_POST['asec_window_minutes'] ?? 60 ) ) );
		update_option( 'asec_ban_duration_hours',  absint( $_POST['asec_ban_duration_hours'] ?? 24 ) );
		update_option( 'asec_ban_message',         sanitize_textarea_field( $_POST['asec_ban_message'] ?? '' ) );
		update_option( 'asec_whitelist_ips',       sanitize_textarea_field( $_POST['asec_whitelist_ips'] ?? '' ) );

		// Login slug — only alphanumeric, hyphens, underscores
		$raw_slug = sanitize_title( $_POST['asec_login_slug'] ?? '' );
		update_option( 'asec_login_slug', $raw_slug );
		update_option( 'asec_gate_cookie_days', max( 1, absint( $_POST['asec_gate_cookie_days'] ?? 7 ) ) );

		wp_redirect( admin_url( 'admin.php?page=ateculus-security&saved=1' ) );
		exit;
	}

	public function unban_ip() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
		check_admin_referer( 'asec_unban' );

		$id = absint( $_POST['ban_id'] ?? 0 );
		if ( $id ) ASEC_DB::unban( $id );

		wp_redirect( admin_url( 'admin.php?page=ateculus-security&tab=bans&unbanned=1' ) );
		exit;
	}

	public function manual_ban() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
		check_admin_referer( 'asec_manual_ban' );

		$ip       = sanitize_text_field( $_POST['ban_ip'] ?? '' );
		$duration = absint( $_POST['ban_duration'] ?? 0 );

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			ASEC_DB::add_ban( $ip, $duration, 0, 'manual' );
		}

		wp_redirect( admin_url( 'admin.php?page=ateculus-security&tab=bans&banned=1' ) );
		exit;
	}

	public function refresh_cf_ips() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Unauthorized' );
		check_admin_referer( 'asec_refresh_cf_ips' );
		ASEC_Guard::refresh_cloudflare_ips();
		wp_redirect( admin_url( 'admin.php?page=ateculus-security&tab=help&cf_refreshed=1' ) );
		exit;
	}

	public function render_page() {
		$tab = sanitize_key( $_GET['tab'] ?? 'settings' );
		?>
		<div class="wrap asec-wrap">
			<h1>
				<span class="dashicons dashicons-shield"></span>
				<?php esc_html_e( 'Ateculus Security', 'ateculus-security' ); ?>
			</h1>

			<?php if ( isset( $_GET['saved'] ) )    : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.',        'ateculus-security' ); ?></p></div><?php endif; ?>
			<?php if ( isset( $_GET['unbanned'] ) ) : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'IP unbanned.',            'ateculus-security' ); ?></p></div><?php endif; ?>
			<?php if ( isset( $_GET['banned'] ) )   : ?><div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'IP banned successfully.', 'ateculus-security' ); ?></p></div><?php endif; ?>

			<nav class="nav-tab-wrapper">
				<a href="?page=ateculus-security&tab=settings" class="nav-tab <?php echo $tab === 'settings' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Settings',     'ateculus-security' ); ?></a>
				<a href="?page=ateculus-security&tab=bans"     class="nav-tab <?php echo $tab === 'bans'     ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Banned IPs',   'ateculus-security' ); ?></a>
				<a href="?page=ateculus-security&tab=attempts" class="nav-tab <?php echo $tab === 'attempts' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Attempts Log', 'ateculus-security' ); ?></a>
				<a href="?page=ateculus-security&tab=404s"     class="nav-tab <?php echo $tab === '404s'     ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( '404 Log',      'ateculus-security' ); ?></a>
				<a href="?page=ateculus-security&tab=logins"   class="nav-tab <?php echo $tab === 'logins'   ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Login Log',    'ateculus-security' ); ?></a>
				<a href="?page=ateculus-security&tab=help"     class="nav-tab <?php echo $tab === 'help'     ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Help',         'ateculus-security' ); ?></a>
			</nav>

			<div class="asec-tab-content">
				<?php
				if ( $tab === 'bans' )         $this->render_bans();
				elseif ( $tab === 'attempts' ) $this->render_attempts();
				elseif ( $tab === '404s' )     $this->render_404s();
				elseif ( $tab === 'logins' )   $this->render_logins();
				elseif ( $tab === 'help' )     $this->render_help();
				else                           $this->render_settings();
				?>
			</div>
		</div>
		<?php
	}

	private function render_settings() {
		$my_ip      = ASEC_Guard::get_ip();
		$raw_ip     = $_SERVER['REMOTE_ADDR'] ?? '';
		$cf_header  = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
		$nginx_mode = ! empty( $cf_header ) && $cf_header === $raw_ip; // Nginx already did the substitution
		$behind_cf  = ASEC_Guard::is_behind_cloudflare();
		$is_ipv6    = filter_var( $my_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
		?>
		<div class="asec-status-bar">
			<div class="asec-your-ip">
				<?php esc_html_e( 'Your IP:', 'ateculus-security' ); ?>
				<code><?php echo esc_html( $my_ip ); ?></code>
				<span style="color:#888;font-size:12px;">(<?php echo $is_ipv6 ? 'IPv6' : 'IPv4'; ?>)</span>
				<span class="asec-tip"><?php esc_html_e( '— add to whitelist to prevent locking yourself out.', 'ateculus-security' ); ?></span>
				<?php if ( $is_ipv6 ) : ?>
				<br><span class="asec-tip" style="font-size:12px;"><?php esc_html_e( 'You are connected via IPv6. If you also access this site over IPv4, add that address to the whitelist too.', 'ateculus-security' ); ?></span>
				<?php endif; ?>
				<?php if ( $behind_cf && $raw_ip !== $my_ip ) : ?>
				<br><span class="asec-tip" style="font-size:12px;"><?php esc_html_e( 'Cloudflare edge IP:', 'ateculus-security' ); ?> <code><?php echo esc_html( $raw_ip ); ?></code></span>
				<?php endif; ?>
			</div>
			<div class="asec-cf-status <?php echo $behind_cf ? 'asec-cf-on' : 'asec-cf-off'; ?>">
				<span class="dashicons <?php echo $behind_cf ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
				<span>
				<?php if ( $behind_cf && $nginx_mode ) : ?>
					<?php esc_html_e( 'Cloudflare detected — Nginx real_ip module is already passing the real visitor IP through REMOTE_ADDR. No additional header reading needed.', 'ateculus-security' ); ?>
				<?php elseif ( $behind_cf ) : ?>
					<?php esc_html_e( 'Cloudflare detected — real visitor IPs are read from the CF-Connecting-IP header.', 'ateculus-security' ); ?>
				<?php else : ?>
					<?php esc_html_e( 'Cloudflare not detected — reading IP from REMOTE_ADDR directly.', 'ateculus-security' ); ?>
				<?php endif; ?>
				<?php
				$cf_updated = get_option( 'asec_cf_ips_updated', 0 );
				if ( $cf_updated ) {
					echo ' &mdash; <em style="font-size:12px;">';
					printf(
						esc_html__( 'Cloudflare IP ranges last synced: %s', 'ateculus-security' ),
						esc_html( human_time_diff( $cf_updated, current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'ateculus-security' ) )
					);
					echo '</em>';
				} else {
					echo ' &mdash; <em style="font-size:12px;">' . esc_html__( 'Cloudflare IP ranges not yet synced — using built-in defaults.', 'ateculus-security' ) . '</em>';
				}
				?>
				</span>
			</div>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="asec_save_settings" />
			<?php wp_nonce_field( 'asec_settings' ); ?>

			<!-- Login Protection -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Login Protection', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><label for="asec_max_attempts"><?php esc_html_e( 'Max Failed Attempts', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="number" id="asec_max_attempts" name="asec_max_attempts" value="<?php echo esc_attr( get_option( 'asec_max_attempts', 5 ) ); ?>" min="1" max="100" class="small-text" />
						<p class="description"><?php esc_html_e( 'Ban the IP after this many failed logins within the time window.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><label for="asec_window_minutes"><?php esc_html_e( 'Time Window (minutes)', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="number" id="asec_window_minutes" name="asec_window_minutes" value="<?php echo esc_attr( get_option( 'asec_window_minutes', 60 ) ); ?>" min="1" max="1440" class="small-text" />
						<p class="description"><?php esc_html_e( 'Rolling window to count failed attempts within.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><label for="asec_ban_duration_hours"><?php esc_html_e( 'Ban Duration (hours)', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="number" id="asec_ban_duration_hours" name="asec_ban_duration_hours" value="<?php echo esc_attr( get_option( 'asec_ban_duration_hours', 24 ) ); ?>" min="0" class="small-text" />
						<p class="description"><?php esc_html_e( 'How long the ban lasts. Set to 0 for permanent.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Login Honeypot', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_honeypot_enabled" value="1" <?php checked( get_option( 'asec_honeypot_enabled', 1 ) ); ?> />
						<?php esc_html_e( 'Add a hidden field to the login form — bots that auto-fill it are instantly banned', 'ateculus-security' ); ?></label>
					</td>
				</tr>
			</table>

			<!-- Block Scope -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Block Scope', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'What to Block', 'ateculus-security' ); ?></th>
					<td>
						<?php $scope = get_option( 'asec_block_scope', 'admin_only' ); ?>
						<label class="asec-radio">
							<input type="radio" name="asec_block_scope" value="admin_only" <?php checked( $scope, 'admin_only' ); ?> />
							<strong><?php esc_html_e( 'wp-admin &amp; wp-login only', 'ateculus-security' ); ?></strong>
							<span><?php esc_html_e( 'Banned IPs are blocked from logging in but can still view the public site.', 'ateculus-security' ); ?></span>
						</label>
						<label class="asec-radio">
							<input type="radio" name="asec_block_scope" value="entire_site" <?php checked( $scope, 'entire_site' ); ?> />
							<strong><?php esc_html_e( 'Entire site', 'ateculus-security' ); ?></strong>
							<span><?php esc_html_e( 'Banned IPs cannot access any page on the site. Make sure your IP is whitelisted.', 'ateculus-security' ); ?></span>
						</label>
					</td>
				</tr>
				<tr>
					<th><label for="asec_ban_message"><?php esc_html_e( 'Block Message', 'ateculus-security' ); ?></label></th>
					<td>
						<textarea id="asec_ban_message" name="asec_ban_message" rows="3" class="large-text"><?php echo esc_textarea( get_option( 'asec_ban_message', 'Access denied. Your IP address has been blocked. Please contact the site administrator if you believe this is an error.' ) ); ?></textarea>
					</td>
				</tr>
			</table>

			<!-- Hardening -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Security Hardening', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Block XML-RPC', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_block_xmlrpc" value="1" <?php checked( get_option( 'asec_block_xmlrpc', 1 ) ); ?> />
						<?php esc_html_e( 'Disable XML-RPC entirely (blocks brute-force via xmlrpc.php and removes X-Pingback header)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Block User Enumeration', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_block_user_enum" value="1" <?php checked( get_option( 'asec_block_user_enum', 1 ) ); ?> />
						<?php esc_html_e( 'Block ?author= scans that reveal WordPress usernames', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Hide WordPress Version', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_hide_wp_version" value="1" <?php checked( get_option( 'asec_hide_wp_version', 1 ) ); ?> />
						<?php esc_html_e( 'Remove the WordPress version number from page source and feeds', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Block Bad Bots', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_block_bad_bots" value="1" <?php checked( get_option( 'asec_block_bad_bots', 1 ) ); ?> />
						<?php esc_html_e( 'Auto-ban IPs using known scanner/attack tool user agents (sqlmap, Nikto, Nmap, Nuclei, etc.)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Restrict REST API', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_restrict_rest_api" value="1" <?php checked( get_option( 'asec_restrict_rest_api', 0 ) ); ?> />
						<?php esc_html_e( 'Block REST API access for non-logged-in users (may break some plugins/themes — use with care)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Security Headers', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_security_headers" value="1" <?php checked( get_option( 'asec_security_headers', 1 ) ); ?> />
						<?php esc_html_e( 'Send security headers on every response: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, and HSTS (on HTTPS)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Disable File Editing', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_disable_file_edit" value="1" <?php checked( get_option( 'asec_disable_file_edit', 0 ) ); ?> />
						<?php esc_html_e( 'Remove the theme and plugin file editors from wp-admin (DISALLOW_FILE_EDIT). Prevents attackers with admin access from modifying code in the browser.', 'ateculus-security' ); ?></label>
						<?php if ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT && ! get_option( 'asec_disable_file_edit', 0 ) ) : ?>
						<p class="description"><?php esc_html_e( 'DISALLOW_FILE_EDIT is already set in wp-config.php.', 'ateculus-security' ); ?></p>
						<?php endif; ?>
					</td>
				</tr>
			</table>

			<!-- Email Alerts -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Email Alerts', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Enable Ban Alerts', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_alerts_enabled" value="1" <?php checked( get_option( 'asec_alerts_enabled', 0 ) ); ?> />
						<?php esc_html_e( 'Send an email whenever an IP is banned (brute force, scan probe, honeypot, 404 flood, bad bot)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><label for="asec_alerts_email"><?php esc_html_e( 'Alert Email Address', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="email" id="asec_alerts_email" name="asec_alerts_email" value="<?php echo esc_attr( get_option( 'asec_alerts_email', '' ) ); ?>" class="regular-text" placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Leave blank to use the site admin email.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
			</table>

			<!-- 404 Protection -->
			<h2 class="asec-section-title"><?php esc_html_e( '404 Flood Protection', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><?php esc_html_e( 'Enable 404 Rate Limiting', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_404_enabled" value="1" <?php checked( get_option( 'asec_404_enabled', 1 ) ); ?> />
						<?php esc_html_e( 'Ban IPs that hit too many 404s in a short window (catches URL scanners)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><label for="asec_404_max"><?php esc_html_e( 'Max 404s', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="number" id="asec_404_max" name="asec_404_max" value="<?php echo esc_attr( get_option( 'asec_404_max', 20 ) ); ?>" min="1" max="500" class="small-text" />
						<label for="asec_404_window_minutes"> <?php esc_html_e( 'hits within', 'ateculus-security' ); ?>
						<input type="number" id="asec_404_window_minutes" name="asec_404_window_minutes" value="<?php echo esc_attr( get_option( 'asec_404_window_minutes', 10 ) ); ?>" min="1" max="1440" class="small-text" />
						<?php esc_html_e( 'minutes triggers a ban.', 'ateculus-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th><?php esc_html_e( 'Instant Ban for Probe Paths', 'ateculus-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="asec_404_instant_ban" value="1" <?php checked( get_option( 'asec_404_instant_ban', 1 ) ); ?> />
						<?php esc_html_e( 'Immediately ban IPs that request known credential/exploit paths (.aws/credentials, .env, docker-compose, _ignition, actuator, .ssh/id_rsa, etc.)', 'ateculus-security' ); ?></label>
					</td>
				</tr>
			</table>

			<!-- Hidden Login URL -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Hidden Login URL', 'ateculus-security' ); ?></h2>
			<?php
			$current_slug = ASEC_Login_URL::get_slug();
			$current_url  = $current_slug ? home_url( '/' . $current_slug . '/' ) : '';
			?>
			<?php if ( $current_slug ) : ?>
			<div class="asec-login-url-notice">
				<span class="dashicons dashicons-admin-links"></span>
				<?php esc_html_e( 'Your custom login URL:', 'ateculus-security' ); ?>
				<a href="<?php echo esc_url( $current_url ); ?>" target="_blank"><code><?php echo esc_html( $current_url ); ?></code></a>
				<strong><?php esc_html_e( 'Save this somewhere safe before leaving this page.', 'ateculus-security' ); ?></strong>
			</div>
			<?php endif; ?>
			<table class="form-table">
				<tr>
					<th><label for="asec_login_slug"><?php esc_html_e( 'Custom Login Slug', 'ateculus-security' ); ?></label></th>
					<td>
						<div class="asec-slug-wrap">
							<span class="asec-slug-prefix"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
							<input type="text" id="asec_login_slug" name="asec_login_slug" value="<?php echo esc_attr( $current_slug ); ?>" class="regular-text" placeholder="e.g. my-secure-portal" pattern="[a-z0-9\-_]+" />
						</div>
						<p class="description">
							<?php esc_html_e( 'Leave blank to use the default /wp-login.php. Once set, /wp-login.php and /wp-admin will return 404 for non-logged-in visitors.', 'ateculus-security' ); ?><br>
							<strong style="color:#dc3232;"><?php esc_html_e( 'WARNING: Bookmark your custom URL before saving. If you forget it, you will be locked out.', 'ateculus-security' ); ?></strong>
						</p>
					</td>
				</tr>
				<tr>
					<th><label for="asec_gate_cookie_days"><?php esc_html_e( 'Login Token Duration', 'ateculus-security' ); ?></label></th>
					<td>
						<input type="number" id="asec_gate_cookie_days" name="asec_gate_cookie_days" value="<?php echo esc_attr( get_option( 'asec_gate_cookie_days', 7 ) ); ?>" min="1" max="365" class="small-text" />
						<?php esc_html_e( 'days', 'ateculus-security' ); ?>
						<p class="description"><?php esc_html_e( 'How long the browser remembers you visited the custom login URL before requiring you to visit it again. Default: 7 days.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
			</table>

			<!-- Whitelist -->
			<h2 class="asec-section-title"><?php esc_html_e( 'Whitelist', 'ateculus-security' ); ?></h2>
			<table class="form-table">
				<tr>
					<th><label for="asec_whitelist_ips"><?php esc_html_e( 'Whitelisted IPs', 'ateculus-security' ); ?></label></th>
					<td>
						<textarea id="asec_whitelist_ips" name="asec_whitelist_ips" rows="6" class="large-text" placeholder="<?php esc_attr_e( 'One IP per line', 'ateculus-security' ); ?>"><?php echo esc_textarea( get_option( 'asec_whitelist_ips', '' ) ); ?></textarea>
						<p class="description"><?php esc_html_e( 'These IPs bypass all blocking rules. Always add your own IP here.', 'ateculus-security' ); ?></p>
					</td>
				</tr>
			</table>

			<?php submit_button( __( 'Save Settings', 'ateculus-security' ) ); ?>
		</form>
		<?php
	}

	private function render_bans() {
		$bans = ASEC_DB::get_bans();
		$now  = current_time( 'timestamp' );

		$reason_labels = array(
			'brute_force' => __( 'Brute Force',  'ateculus-security' ),
			'bad_bot'     => __( 'Bad Bot',      'ateculus-security' ),
			'manual'      => __( 'Manual Ban',   'ateculus-security' ),
			'scan_probe'  => __( 'Scan Probe',   'ateculus-security' ),
			'404_flood'   => __( '404 Flood',    'ateculus-security' ),
			'honeypot'    => __( 'Honeypot',     'ateculus-security' ),
		);
		?>
		<!-- Manual Ban Form -->
		<div class="asec-manual-ban">
			<h3><?php esc_html_e( 'Manually Ban an IP', 'ateculus-security' ); ?></h3>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;">
				<input type="hidden" name="action" value="asec_manual_ban" />
				<?php wp_nonce_field( 'asec_manual_ban' ); ?>
				<div>
					<label><?php esc_html_e( 'IP Address', 'ateculus-security' ); ?><br>
					<input type="text" name="ban_ip" placeholder="e.g. 192.168.1.1" class="regular-text" required /></label>
				</div>
				<div>
					<label><?php esc_html_e( 'Duration (hours, 0 = permanent)', 'ateculus-security' ); ?><br>
					<input type="number" name="ban_duration" value="24" min="0" class="small-text" /></label>
				</div>
				<div>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Ban IP', 'ateculus-security' ); ?></button>
				</div>
			</form>
		</div>

		<table class="wp-list-table widefat fixed striped asec-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'IP Address',  'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Reason',      'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Banned At',   'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Expires',     'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Attempts',    'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Status',      'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Action',      'ateculus-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $bans ) ) : ?>
				<tr><td colspan="7" class="asec-empty"><?php esc_html_e( 'No banned IPs.', 'ateculus-security' ); ?></td></tr>
				<?php else : foreach ( $bans as $ban ) :
					$expired = $ban->expires_at && strtotime( $ban->expires_at ) < $now;
				?>
				<tr>
					<td><code><?php echo esc_html( $ban->ip ); ?></code></td>
					<td><?php echo esc_html( $reason_labels[ $ban->reason ] ?? $ban->reason ); ?></td>
					<td><?php echo esc_html( $ban->banned_at ); ?></td>
					<td><?php echo $ban->expires_at ? esc_html( $ban->expires_at ) : '<strong>' . esc_html__( 'Permanent', 'ateculus-security' ) . '</strong>'; ?></td>
					<td><?php echo $ban->attempts > 0 ? esc_html( $ban->attempts ) : '—'; ?></td>
					<td><?php echo $expired ? '<span class="asec-badge asec-expired">' . esc_html__( 'Expired', 'ateculus-security' ) . '</span>' : '<span class="asec-badge asec-active">' . esc_html__( 'Active', 'ateculus-security' ) . '</span>'; ?></td>
					<td>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<input type="hidden" name="action" value="asec_unban" />
							<input type="hidden" name="ban_id" value="<?php echo esc_attr( $ban->id ); ?>" />
							<?php wp_nonce_field( 'asec_unban' ); ?>
							<button type="submit" class="button button-small"><?php esc_html_e( 'Unban', 'ateculus-security' ); ?></button>
						</form>
					</td>
				</tr>
				<?php endforeach; endif; ?>
			</tbody>
		</table>
		<?php
	}

	private function render_attempts() {
		$attempts = ASEC_DB::get_recent_attempts();
		?>
		<p class="description" style="margin:16px 0;"><?php esc_html_e( 'Failed login attempts grouped by IP (last 7 days, purged hourly).', 'ateculus-security' ); ?></p>
		<table class="wp-list-table widefat fixed striped asec-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'IP Address',     'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Total Attempts', 'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Last Attempt',   'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Status',         'ateculus-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $attempts ) ) : ?>
				<tr><td colspan="4" class="asec-empty"><?php esc_html_e( 'No failed attempts recorded.', 'ateculus-security' ); ?></td></tr>
				<?php else : foreach ( $attempts as $row ) :
					$banned = ASEC_DB::is_banned( $row->ip );
				?>
				<tr>
					<td><code><?php echo esc_html( $row->ip ); ?></code></td>
					<td><?php echo esc_html( $row->count ); ?></td>
					<td><?php echo esc_html( $row->last_attempt ); ?></td>
					<td><?php echo $banned ? '<span class="asec-badge asec-active">' . esc_html__( 'Banned', 'ateculus-security' ) . '</span>' : '<span class="asec-badge asec-watching">' . esc_html__( 'Watching', 'ateculus-security' ) . '</span>'; ?></td>
				</tr>
				<?php endforeach; endif; ?>
			</tbody>
		</table>
		<?php
	}

	private function render_404s() {
		$hits = ASEC_DB::get_recent_404_hits();
		?>
		<p class="description" style="margin:16px 0;"><?php esc_html_e( 'Last 300 404 hits (last 7 days). Probe paths trigger an instant ban; repeated hits trigger the flood ban.', 'ateculus-security' ); ?></p>
		<table class="wp-list-table widefat fixed striped asec-table">
			<thead>
				<tr>
					<th style="width:160px;"><?php esc_html_e( 'IP Address', 'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'URL', 'ateculus-security' ); ?></th>
					<th style="width:160px;"><?php esc_html_e( 'Date / Time', 'ateculus-security' ); ?></th>
					<th style="width:100px;"><?php esc_html_e( 'Action', 'ateculus-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $hits ) ) : ?>
				<tr><td colspan="4" class="asec-empty"><?php esc_html_e( 'No 404s recorded yet.', 'ateculus-security' ); ?></td></tr>
				<?php else : foreach ( $hits as $row ) :
					$banned = ASEC_DB::is_banned( $row->ip );
				?>
				<tr>
					<td><code><?php echo esc_html( $row->ip ); ?></code></td>
					<td style="word-break:break-all;"><code><?php echo esc_html( $row->uri ); ?></code></td>
					<td><?php echo esc_html( $row->hit_at ); ?></td>
					<td>
						<?php if ( $banned ) : ?>
							<span class="asec-badge asec-active"><?php esc_html_e( 'Banned', 'ateculus-security' ); ?></span>
						<?php else : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
								<input type="hidden" name="action"       value="asec_manual_ban" />
								<input type="hidden" name="ban_ip"       value="<?php echo esc_attr( $row->ip ); ?>" />
								<input type="hidden" name="ban_duration" value="<?php echo esc_attr( get_option( 'asec_ban_duration_hours', 24 ) ); ?>" />
								<?php wp_nonce_field( 'asec_manual_ban' ); ?>
								<button type="submit" class="button button-small"><?php esc_html_e( 'Ban IP', 'ateculus-security' ); ?></button>
							</form>
						<?php endif; ?>
					</td>
				</tr>
				<?php endforeach; endif; ?>
			</tbody>
		</table>
		<?php
	}

	private function render_help() {
		$cf_status  = ASEC_Guard::is_behind_cloudflare();
		$raw_ip     = $_SERVER['REMOTE_ADDR'] ?? '';
		$cf_header  = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
		$nginx_mode = ! empty( $cf_header ) && $cf_header === $raw_ip;
		?>
		<div style="max-width:860px;">

		<!-- Cloudflare -->
		<div class="asec-help-section">
			<h2><span class="dashicons dashicons-cloud"></span> <?php esc_html_e( 'Cloudflare & IP Detection', 'ateculus-security' ); ?></h2>
			<div class="asec-help-body">
				<?php if ( isset( $_GET['cf_refreshed'] ) ) : ?>
				<div class="notice notice-success inline" style="margin:0 0 12px;"><p><?php esc_html_e( 'Cloudflare IP ranges refreshed successfully.', 'ateculus-security' ); ?></p></div>
				<?php endif; ?>

				<p><?php esc_html_e( 'When your site sits behind Cloudflare, visitors connect to Cloudflare first. Cloudflare then forwards the request to your server. This means your server sees a Cloudflare IP as the connection source, not the real visitor IP — which would cause bans to target the wrong address.', 'ateculus-security' ); ?></p>
				<p><?php esc_html_e( 'This plugin handles this in two ways depending on your server setup:', 'ateculus-security' ); ?></p>
				<ul>
					<li><strong><?php esc_html_e( 'Direct (no proxy config):', 'ateculus-security' ); ?></strong> <?php esc_html_e( 'REMOTE_ADDR is a Cloudflare IP. The plugin detects this by checking against Cloudflare\'s published IP ranges, then reads the real visitor IP from the CF-Connecting-IP header that Cloudflare adds to every request.', 'ateculus-security' ); ?></li>
					<li><strong><?php esc_html_e( 'Nginx / Apache real_ip module:', 'ateculus-security' ); ?></strong> <?php esc_html_e( 'Some servers are configured to automatically replace REMOTE_ADDR with the real visitor IP before PHP runs. In this case REMOTE_ADDR is already correct and the plugin uses it directly.', 'ateculus-security' ); ?></li>
				</ul>

				<div class="asec-help-note">
					<strong><?php esc_html_e( 'Your current status:', 'ateculus-security' ); ?></strong>
					<?php if ( $cf_status && $nginx_mode ) : ?>
						<?php esc_html_e( 'Cloudflare detected via Nginx/Apache real_ip module. REMOTE_ADDR is already your real visitor IP.', 'ateculus-security' ); ?>
					<?php elseif ( $cf_status ) : ?>
						<?php esc_html_e( 'Cloudflare detected directly. Real IPs are read from CF-Connecting-IP.', 'ateculus-security' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Cloudflare not detected. IP is read from REMOTE_ADDR directly. If you are behind Cloudflare and see this, see the fix below.', 'ateculus-security' ); ?>
					<?php endif; ?>
				</div>

				<p><strong><?php esc_html_e( 'Cloudflare IP ranges — auto-synced:', 'ateculus-security' ); ?></strong></p>
				<?php
				$cf_updated  = get_option( 'asec_cf_ips_updated', 0 );
				$v4_ranges   = get_option( 'asec_cf_ips_v4', array() );
				$v6_ranges   = get_option( 'asec_cf_ips_v6', array() );
				$using_cache = ! empty( $v4_ranges );
				?>
				<p>
					<?php if ( $using_cache ) : ?>
						<?php printf( esc_html__( 'Using %d IPv4 and %d IPv6 ranges fetched from Cloudflare\'s official endpoints. Last synced %s ago.', 'ateculus-security' ), count( $v4_ranges ), count( $v6_ranges ), esc_html( human_time_diff( $cf_updated, current_time( 'timestamp' ) ) ) ); ?>
					<?php else : ?>
						<?php esc_html_e( 'Using built-in defaults. Ranges have not yet been synced from Cloudflare.', 'ateculus-security' ); ?>
					<?php endif; ?>
					<?php esc_html_e( 'Ranges are automatically refreshed daily from:', 'ateculus-security' ); ?>
					<code>https://www.cloudflare.com/ips-v4</code> <?php esc_html_e( 'and', 'ateculus-security' ); ?> <code>https://www.cloudflare.com/ips-v6</code>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:12px;">
					<input type="hidden" name="action" value="asec_refresh_cf_ips" />
					<?php wp_nonce_field( 'asec_refresh_cf_ips' ); ?>
					<button type="submit" class="button"><?php esc_html_e( 'Refresh Cloudflare IPs Now', 'ateculus-security' ); ?></button>
				</form>

				<p><strong><?php esc_html_e( 'If Cloudflare is active but shows as "not detected":', 'ateculus-security' ); ?></strong></p>
				<p><?php esc_html_e( 'This usually means your Cloudflare proxy is in DNS-only mode (grey cloud) rather than proxied mode (orange cloud). Check your Cloudflare DNS dashboard and make sure the orange cloud icon is enabled for your domain\'s A record.', 'ateculus-security' ); ?></p>

				<p><strong>Nginx — <?php esc_html_e( 'configure real_ip passthrough (recommended):', 'ateculus-security' ); ?></strong></p>
				<p><?php esc_html_e( 'Create the snippet below and include it in your site\'s server {} block. This tells Nginx to trust Cloudflare\'s IP ranges and replace REMOTE_ADDR with the real visitor IP automatically. Get the latest ranges from:', 'ateculus-security' ); ?> <a href="https://www.cloudflare.com/ips/" target="_blank">cloudflare.com/ips</a></p>
<pre>/etc/nginx/snippets/cloudflare-realip.conf

<?php
$v4 = ! empty( $v4_ranges ) ? $v4_ranges : array( '103.21.244.0/22', '103.22.200.0/22', '104.16.0.0/13', '172.64.0.0/13', '...' );
$v6 = ! empty( $v6_ranges ) ? $v6_ranges : array( '2400:cb00::/32', '2606:4700::/32', '...' );
echo "# Cloudflare IPv4\n";
foreach ( $v4 as $r ) echo esc_html( "set_real_ip_from {$r};\n" );
echo "\n# Cloudflare IPv6\n";
foreach ( $v6 as $r ) echo esc_html( "set_real_ip_from {$r};\n" );
echo "\nreal_ip_header CF-Connecting-IP;";
?></pre>
				<p><?php esc_html_e( 'Then in your site\'s server block:', 'ateculus-security' ); ?> <code>include snippets/cloudflare-realip.conf;</code></p>
				<p><?php esc_html_e( 'Reload Nginx after saving:', 'ateculus-security' ); ?> <code>sudo nginx -t && sudo systemctl reload nginx</code></p>

				<p><strong>Apache — <?php esc_html_e( 'configure real_ip passthrough:', 'ateculus-security' ); ?></strong></p>
				<p><?php esc_html_e( 'Enable mod_remoteip and add the following to your VirtualHost. Get the latest ranges from:', 'ateculus-security' ); ?> <a href="https://www.cloudflare.com/ips/" target="_blank">cloudflare.com/ips</a></p>
<pre>RemoteIPHeader CF-Connecting-IP
<?php foreach ( $v4 as $r ) echo esc_html( "RemoteIPTrustedProxy {$r}\n" ); ?></pre>
			</div>
		</div>

		<!-- Hidden Login URL -->
		<div class="asec-help-section">
			<h2><span class="dashicons dashicons-admin-links"></span> <?php esc_html_e( 'Hidden Login URL', 'ateculus-security' ); ?></h2>
			<div class="asec-help-body">
				<p><?php esc_html_e( 'When a custom login slug is set, visiting /wp-login.php or /wp-admin without the cookie redirects to the homepage. The plugin does not block or return 404 — it silently redirects, so attackers get no information about whether a login page exists.', 'ateculus-security' ); ?></p>
				<p><?php esc_html_e( 'How it works:', 'ateculus-security' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Visiting your custom slug (e.g. yoursite.com/my-portal) sets a secure HMAC cookie in your browser and redirects to the real wp-login.php.', 'ateculus-security' ); ?></li>
					<li><?php esc_html_e( 'The cookie is tied to your site\'s URL and a secret key stored in the database. It cannot be forged.', 'ateculus-security' ); ?></li>
					<li><?php esc_html_e( 'The cookie refreshes its expiry every time you visit the custom slug.', 'ateculus-security' ); ?></li>
				</ul>
				<div class="asec-help-warn">
					<strong><?php esc_html_e( 'Important:', 'ateculus-security' ); ?></strong> <?php esc_html_e( 'Bookmark your custom login URL before saving. If you forget it you will be locked out of wp-admin. To recover, disable the plugin via FTP by renaming the plugin folder, then re-enable it and clear the slug setting.', 'ateculus-security' ); ?>
				</div>
			</div>
		</div>

		<!-- Whitelist -->
		<div class="asec-help-section">
			<h2><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Whitelist — Add Your Own IP First', 'ateculus-security' ); ?></h2>
			<div class="asec-help-body">
				<p><?php esc_html_e( 'Before enabling aggressive settings (Entire Site blocking, low thresholds), always add your own IP address to the whitelist. Whitelisted IPs bypass all ban checks.', 'ateculus-security' ); ?></p>
				<p><?php esc_html_e( 'Your current detected IP is shown at the top of the Settings tab. If you connect over both IPv4 and IPv6, add both addresses — your browser may use either one depending on network conditions.', 'ateculus-security' ); ?></p>
				<p><?php esc_html_e( 'To find your IPv4 address, visit:', 'ateculus-security' ); ?> <code>https://ipv4.icanhazip.com</code> — <?php esc_html_e( 'and your IPv6:', 'ateculus-security' ); ?> <code>https://ipv6.icanhazip.com</code></p>
			</div>
		</div>

		<!-- WP-Cron -->
		<div class="asec-help-section">
			<h2><span class="dashicons dashicons-clock"></span> <?php esc_html_e( 'WP-Cron & Log Cleanup', 'ateculus-security' ); ?></h2>
			<div class="asec-help-body">
				<p><?php esc_html_e( 'This plugin schedules an hourly cleanup job via WP-Cron to remove old records:', 'ateculus-security' ); ?></p>
				<ul>
					<li><?php esc_html_e( 'Failed login attempts — purged after 7 days', 'ateculus-security' ); ?></li>
					<li><?php esc_html_e( '404 hits — purged after 7 days', 'ateculus-security' ); ?></li>
					<li><?php esc_html_e( 'Login log — purged after 90 days', 'ateculus-security' ); ?></li>
					<li><?php esc_html_e( 'Expired bans — removed after 30 days past expiry', 'ateculus-security' ); ?></li>
				</ul>
				<p><?php esc_html_e( 'WP-Cron only runs when someone visits your site, so on low-traffic sites cleanup may be delayed. If your host disables WP-Cron, set up a real server cron job instead:', 'ateculus-security' ); ?></p>
<pre>*/30 * * * * wget -q -O /dev/null "https://yoursite.com/wp-cron.php?doing_wp_cron" &>/dev/null</pre>
				<p><?php esc_html_e( 'Or if you have WP-CLI:', 'ateculus-security' ); ?></p>
<pre>*/30 * * * * cd /path/to/wordpress && wp cron event run --due-now --quiet</pre>
			</div>
		</div>

		<!-- Recovery -->
		<div class="asec-help-section">
			<h2><span class="dashicons dashicons-sos"></span> <?php esc_html_e( 'Recovery — If You Get Locked Out', 'ateculus-security' ); ?></h2>
			<div class="asec-help-body">
				<p><?php esc_html_e( 'If you are locked out of wp-admin, you have two options:', 'ateculus-security' ); ?></p>
				<ul>
					<li><strong><?php esc_html_e( 'Via database:', 'ateculus-security' ); ?></strong> <?php esc_html_e( 'Open phpMyAdmin or run the following SQL to remove your ban and clear the login slug:', 'ateculus-security' ); ?>
<pre>DELETE FROM wp_asec_bans WHERE ip = 'YOUR.IP.ADDRESS';
UPDATE wp_options SET option_value = '' WHERE option_name = 'asec_login_slug';</pre>
					</li>
					<li><strong><?php esc_html_e( 'Via FTP / file manager:', 'ateculus-security' ); ?></strong> <?php esc_html_e( 'Rename the plugin folder from', 'ateculus-security' ); ?> <code>ateculus-security</code> <?php esc_html_e( 'to', 'ateculus-security' ); ?> <code>ateculus-security-disabled</code>. <?php esc_html_e( 'This deactivates the plugin and restores normal access. Rename it back once you are in and clear your settings.', 'ateculus-security' ); ?></li>
				</ul>
			</div>
		</div>

		</div>
		<?php
	}

	private function render_logins() {
		$logins = ASEC_DB::get_recent_logins();
		?>
		<p class="description" style="margin:16px 0;"><?php esc_html_e( 'Successful logins (last 200, kept 90 days). Use this to spot unexpected access from unfamiliar IPs.', 'ateculus-security' ); ?></p>
		<table class="wp-list-table widefat fixed striped asec-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Username',  'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'IP Address', 'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Date / Time', 'ateculus-security' ); ?></th>
					<th><?php esc_html_e( 'Action', 'ateculus-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $logins ) ) : ?>
				<tr><td colspan="4" class="asec-empty"><?php esc_html_e( 'No logins recorded yet.', 'ateculus-security' ); ?></td></tr>
				<?php else : foreach ( $logins as $row ) :
					$banned = ASEC_DB::is_banned( $row->ip );
				?>
				<tr>
					<td><strong><?php echo esc_html( $row->username ); ?></strong></td>
					<td><code><?php echo esc_html( $row->ip ); ?></code></td>
					<td><?php echo esc_html( $row->logged_at ); ?></td>
					<td>
						<?php if ( $banned ) : ?>
							<span class="asec-badge asec-active"><?php esc_html_e( 'Banned', 'ateculus-security' ); ?></span>
						<?php else : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
								<input type="hidden" name="action" value="asec_manual_ban" />
								<input type="hidden" name="ban_ip" value="<?php echo esc_attr( $row->ip ); ?>" />
								<input type="hidden" name="ban_duration" value="<?php echo esc_attr( get_option( 'asec_ban_duration_hours', 24 ) ); ?>" />
								<?php wp_nonce_field( 'asec_manual_ban' ); ?>
								<button type="submit" class="button button-small"><?php esc_html_e( 'Ban IP', 'ateculus-security' ); ?></button>
							</form>
						<?php endif; ?>
					</td>
				</tr>
				<?php endforeach; endif; ?>
			</tbody>
		</table>
		<?php
	}
}
