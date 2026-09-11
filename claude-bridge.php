<?php
/**
 * Plugin Name:  Claude Bridge
 * Plugin URI:   https://github.com/adelsherif8/claude-bridge
 * Description:  REST API bridge for Claude Code. Token-only or Token+AppPass auth, WAF-safe base64 content, GitHub auto-updates.
 * Version:      1.1.2
 * Author:       Adel Emad
 * Author URI:   https://adelatya.com
 * License:      GPLv2 or later
 * Update URI:   false
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'CB_VERSION', '1.1.2' );
define( 'CB_NS',      'claude/v1' );
define( 'CB_FILE',    __FILE__ );

class Claude_Bridge {

	const OPT_TOKEN = 'claude_bridge_token';
	const OPT_MODE  = 'claude_bridge_auth_mode';    // 'token_only' | 'token_and_apppass'
	const OPT_REPO  = 'claude_bridge_github_repo';  // 'username/repo-name'

	const DEFAULT_REPO = 'adelsherif8/claude-bridge'; // auto-updates work out of the box
	/* ─── bootstrap ─── */

	public static function init() {
		add_action( 'rest_api_init', [ __CLASS__, 'routes' ] );
		add_action( 'admin_menu',    [ __CLASS__, 'admin_menu' ] );
		add_action( 'admin_init',    [ __CLASS__, 'admin_settings' ] );
		add_filter( 'pre_set_site_transient_update_plugins', [ __CLASS__, 'check_update' ] );
		add_filter( 'plugins_api',   [ __CLASS__, 'plugin_info' ], 10, 3 );
		add_filter( 'upgrader_post_install', [ __CLASS__, 'after_install' ], 10, 3 );
	}

	/* ─── token ─── */

	public static function token() {
		$t = get_option( self::OPT_TOKEN );
		if ( ! $t ) {
			$t = wp_generate_password( 40, false, false );
			update_option( self::OPT_TOKEN, $t, false );
		}
		return $t;
	}

	/* ─── auth ─── */

	public static function auth( WP_REST_Request $req ) {
		// Accept token from header or ?token= query param
		$sent = $req->get_header( 'x-claude-token' );
		if ( ! $sent ) { $sent = $req->get_param( 'token' ); }

		if ( ! $sent || ! hash_equals( self::token(), $sent ) ) {
			return new WP_Error( 'bad_token', 'Invalid or missing Claude token.', [ 'status' => 403 ] );
		}

		$mode = get_option( self::OPT_MODE, 'token_only' );

		if ( $mode === 'token_and_apppass' ) {
			// Also requires an administrator Application Password (HTTP Basic Auth)
			if ( ! current_user_can( 'manage_options' ) ) {
				return new WP_Error( 'forbidden', 'This site requires an administrator Application Password in addition to the token.', [ 'status' => 401 ] );
			}
		} else {
			// token_only — impersonate first admin so wp_insert_post etc. work
			if ( ! is_user_logged_in() ) {
				$admins = get_users( [ 'role' => 'administrator', 'number' => 1, 'fields' => 'ids' ] );
				if ( $admins ) { wp_set_current_user( $admins[0] ); }
			}
		}

		return true;
	}

	/* ─── routes ─── */

	public static function routes() {
		$a = [ __CLASS__, 'auth' ];
		register_rest_route( CB_NS, '/ping',              [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'ping' ] ] );
		register_rest_route( CB_NS, '/pages',             [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'list_pages' ] ] );
		register_rest_route( CB_NS, '/page/(?P<id>\d+)', [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'get_page' ] ] );
		register_rest_route( CB_NS, '/page/create',       [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'create_page' ] ] );
		register_rest_route( CB_NS, '/page/update',       [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'update_page' ] ] );
		register_rest_route( CB_NS, '/page/upsert',       [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'upsert_page' ] ] );
		register_rest_route( CB_NS, '/posts',             [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'list_posts' ] ] );
		register_rest_route( CB_NS, '/replace',           [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'replace' ] ] );
		register_rest_route( CB_NS, '/meta',              [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'set_meta' ] ] );
	}

	/* ─── handlers ─── */

	public static function ping() {
		return [
			'ok'      => true,
			'version' => CB_VERSION,
			'site'    => get_bloginfo( 'name' ),
			'home'    => home_url(),
			'wp'      => get_bloginfo( 'version' ),
			'mode'    => get_option( self::OPT_MODE, 'token_only' ),
		];
	}

	public static function list_pages() {
		$q   = new WP_Query( [ 'post_type' => 'page', 'post_status' => [ 'publish', 'draft', 'private', 'pending' ], 'posts_per_page' => 200, 'orderby' => 'title', 'order' => 'ASC' ] );
		$out = [];
		foreach ( $q->posts as $p ) {
			$out[] = [ 'id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status, 'link' => get_permalink( $p ) ];
		}
		return $out;
	}

	public static function get_page( WP_REST_Request $r ) {
		$p = get_post( (int) $r['id'] );
		if ( ! $p || $p->post_type !== 'page' ) { return new WP_Error( 'not_found', 'Page not found.', [ 'status' => 404 ] ); }
		return [ 'id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status, 'content' => $p->post_content, 'link' => get_permalink( $p ) ];
	}

	/** POST /page/create — body: { title, slug?, content|content_b64, status? } */
	public static function create_page( WP_REST_Request $r ) {
		$title  = sanitize_text_field( $r->get_param( 'title' ) );
		$slug   = sanitize_title( $r->get_param( 'slug' ) ?: $title );
		$status = self::safe_status( $r->get_param( 'status' ) );
		if ( ! $title ) { return new WP_Error( 'missing', 'title is required.', [ 'status' => 400 ] ); }
		$id = wp_insert_post( [ 'post_title' => $title, 'post_name' => $slug, 'post_content' => self::content( $r ), 'post_type' => 'page', 'post_status' => $status, 'post_author' => get_current_user_id() ], true );
		if ( is_wp_error( $id ) ) { return $id; }
		return [ 'ok' => true, 'action' => 'created', 'id' => $id, 'slug' => $slug, 'status' => $status, 'edit' => admin_url( 'post.php?post=' . $id . '&action=edit' ), 'link' => get_permalink( $id ) ];
	}

	/** POST /page/update — body: { id, content|content_b64, title?, status? } */
	public static function update_page( WP_REST_Request $r ) {
		$id = (int) $r->get_param( 'id' );
		$p  = get_post( $id );
		if ( ! $p || $p->post_type !== 'page' ) { return new WP_Error( 'not_found', 'Page not found.', [ 'status' => 404 ] ); }
		$args = [ 'ID' => $id ];
		$c = self::content( $r );
		if ( $c !== '' )                         { $args['post_content'] = $c; }
		if ( $r->get_param( 'title' ) )          { $args['post_title']  = sanitize_text_field( $r->get_param( 'title' ) ); }
		if ( $r->get_param( 'status' ) )         { $args['post_status'] = self::safe_status( $r->get_param( 'status' ) ); }
		$res = wp_update_post( $args, true );
		if ( is_wp_error( $res ) ) { return $res; }
		return [ 'ok' => true, 'action' => 'updated', 'id' => $id, 'title' => get_the_title( $id ), 'status' => get_post_status( $id ), 'link' => get_permalink( $id ) ];
	}

	/** POST /page/upsert — body: { title, slug, content|content_b64, status? } — create if slug missing, update if exists */
	public static function upsert_page( WP_REST_Request $r ) {
		$title    = sanitize_text_field( $r->get_param( 'title' ) );
		$slug     = sanitize_title( $r->get_param( 'slug' ) ?: $title );
		$status   = self::safe_status( $r->get_param( 'status' ) );
		$c        = self::content( $r );
		if ( ! $title ) { return new WP_Error( 'missing', 'title is required.', [ 'status' => 400 ] ); }
		$existing = get_page_by_path( $slug, OBJECT, 'page' );
		if ( $existing ) {
			wp_update_post( [ 'ID' => $existing->ID, 'post_title' => $title, 'post_content' => $c, 'post_status' => $status ] );
			return [ 'ok' => true, 'action' => 'updated', 'id' => $existing->ID, 'slug' => $slug, 'status' => $status, 'edit' => admin_url( 'post.php?post=' . $existing->ID . '&action=edit' ), 'link' => get_permalink( $existing->ID ) ];
		}
		$id = wp_insert_post( [ 'post_title' => $title, 'post_name' => $slug, 'post_content' => $c, 'post_type' => 'page', 'post_status' => $status, 'post_author' => get_current_user_id() ], true );
		if ( is_wp_error( $id ) ) { return $id; }
		return [ 'ok' => true, 'action' => 'created', 'id' => $id, 'slug' => $slug, 'status' => $status, 'edit' => admin_url( 'post.php?post=' . $id . '&action=edit' ), 'link' => get_permalink( $id ) ];
	}

	public static function list_posts( WP_REST_Request $r ) {
		$q = new WP_Query( [ 'post_type' => $r->get_param( 'type' ) ?: [ 'page', 'post', 'elementor_library' ], 'post_status' => [ 'publish', 'draft', 'private', 'pending' ], 'posts_per_page' => (int) ( $r->get_param( 'limit' ) ?: 100 ), 's' => $r->get_param( 'search' ) ?: '', 'orderby' => 'ID', 'order' => 'ASC' ] );
		$out = [];
		foreach ( $q->posts as $p ) {
			$out[] = [ 'id' => $p->ID, 'title' => $p->post_title, 'type' => $p->post_type, 'status' => $p->post_status, 'slug' => $p->post_name, 'link' => get_permalink( $p ) ];
		}
		return $out;
	}

	/** POST /replace — body: { ids:[12,34], pairs:{"old":"new"}, dry_run?:true } */
	public static function replace( WP_REST_Request $r ) {
		$ids   = (array) $r->get_param( 'ids' );
		$pairs = (array) $r->get_param( 'pairs' );
		$dry   = (bool)  $r->get_param( 'dry_run' );
		if ( ! $ids )   { return new WP_Error( 'no_ids',   'Provide ids[] — this endpoint never runs site-wide.', [ 'status' => 400 ] ); }
		if ( ! $pairs ) { return new WP_Error( 'no_pairs', 'Provide pairs{search:replace}.', [ 'status' => 400 ] ); }
		$report = [];
		foreach ( $ids as $id ) {
			$id  = (int) $id;
			$p   = get_post( $id );
			if ( ! $p ) { continue; }
			$hits  = 0;
			$new_c = $p->post_content;
			foreach ( $pairs as $s => $rep ) { $n = 0; $new_c = str_ireplace( $s, $rep, $new_c, $n ); $hits += $n; }
			if ( ! $dry && $new_c !== $p->post_content ) { wp_update_post( [ 'ID' => $id, 'post_content' => $new_c ] ); }
			foreach ( get_post_meta( $id ) as $key => $vals ) {
				$val   = maybe_unserialize( $vals[0] );
				if ( ! is_string( $val ) ) { continue; }
				$new_v = $val;
				foreach ( $pairs as $s => $rep ) { $n = 0; $new_v = str_ireplace( $s, $rep, $new_v, $n ); $hits += $n; }
				if ( ! $dry && $new_v !== $val ) { update_post_meta( $id, $key, wp_slash( $new_v ) ); }
			}
			$report[] = [ 'id' => $id, 'title' => $p->post_title, 'replacements' => $hits ];
		}
		return [ 'ok' => true, 'dry_run' => $dry, 'results' => $report ];
	}

	/** POST /meta — body: { id, key, value? } — omit value to read */
	public static function set_meta( WP_REST_Request $r ) {
		$id  = (int)    $r->get_param( 'id' );
		$key = (string) $r->get_param( 'key' );
		if ( ! get_post( $id ) || ! $key ) { return new WP_Error( 'bad', 'id and key required.', [ 'status' => 400 ] ); }
		if ( $r->get_param( 'value' ) === null ) { return [ 'id' => $id, 'key' => $key, 'value' => get_post_meta( $id, $key, true ) ]; }
		$val = $r->get_param( 'value' );
		update_post_meta( $id, $key, is_string( $val ) ? wp_slash( $val ) : $val );
		return [ 'ok' => true, 'id' => $id, 'key' => $key ];
	}

	/* ─── helpers ─── */

	/**
	 * Accepts HTML as base64 in content_b64 (bypasses WAF XSS detection),
	 * or falls back to raw content param.
	 */
	private static function content( WP_REST_Request $r ) {
		$b64 = $r->get_param( 'content_b64' );
		if ( $b64 ) {
			$decoded = base64_decode( $b64, true );
			return $decoded !== false ? wp_kses_post( $decoded ) : '';
		}
		return wp_kses_post( $r->get_param( 'content' ) ?: '' );
	}

	private static function safe_status( $s ) {
		return in_array( $s, [ 'publish', 'draft', 'private' ], true ) ? $s : 'draft';
	}

	/* ─── GitHub auto-updater ─── */

	private static function github_release() {
		$repo = trim( (string) get_option( self::OPT_REPO ) );
		if ( '' === $repo ) { $repo = self::DEFAULT_REPO; }
		$cached = get_transient( 'cb_github_release' );
		if ( $cached !== false ) { return $cached ?: null; }
		$resp = wp_remote_get( "https://api.github.com/repos/{$repo}/releases/latest", [
			'headers' => [ 'Accept' => 'application/vnd.github+json', 'User-Agent' => 'Claude-Bridge/' . CB_VERSION ],
			'timeout' => 10,
		] );
		if ( is_wp_error( $resp ) || 200 !== wp_remote_retrieve_response_code( $resp ) ) {
			set_transient( 'cb_github_release', '', 30 * MINUTE_IN_SECONDS );
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( empty( $data['tag_name'] ) ) { return null; }
		set_transient( 'cb_github_release', $data, 6 * HOUR_IN_SECONDS );
		return $data;
	}

	public static function check_update( $transient ) {
		if ( empty( $transient->checked ) ) { return $transient; }
		$release = self::github_release();
		if ( ! $release ) { return $transient; }
		$latest = ltrim( $release['tag_name'], 'v' );
		$slug   = plugin_basename( CB_FILE );
		if ( version_compare( $latest, CB_VERSION, '>' ) ) {
			$transient->response[ $slug ] = (object) [
				'slug'        => dirname( $slug ),
				'plugin'      => $slug,
				'new_version' => $latest,
				'url'         => $release['html_url'],
				'package'     => $release['zipball_url'],
			];
		}
		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( $action !== 'plugin_information' ) { return $result; }
		if ( $args->slug !== dirname( plugin_basename( CB_FILE ) ) ) { return $result; }
		$release = self::github_release();
		if ( ! $release ) { return $result; }
		return (object) [
			'name'          => 'Claude Bridge',
			'slug'          => dirname( plugin_basename( CB_FILE ) ),
			'version'       => ltrim( $release['tag_name'], 'v' ),
			'author'        => '<a href="https://adelatya.com">Adel Emad</a>',
			'homepage'      => $release['html_url'],
			'download_link' => $release['zipball_url'],
			'sections'      => [ 'description' => nl2br( esc_html( $release['body'] ?? 'REST API bridge for Claude Code.' ) ) ],
		];
	}

	public static function after_install( $response, $hook_extra, $result ) {
		global $wp_filesystem;
		if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== plugin_basename( CB_FILE ) ) { return $response; }
		$dest = WP_PLUGIN_DIR . '/' . dirname( plugin_basename( CB_FILE ) );
		$wp_filesystem->move( $result['destination'], $dest );
		$result['destination'] = $dest;
		activate_plugin( plugin_basename( CB_FILE ) );
		return $result;
	}

	/* ─── admin ─── */

	public static function admin_settings() {
		register_setting( 'claude_bridge_group', self::OPT_MODE );
		register_setting( 'claude_bridge_group', self::OPT_REPO );
	}

	public static function admin_menu() {
		add_management_page( 'Claude Bridge', 'Claude Bridge', 'manage_options', 'claude-bridge', [ __CLASS__, 'admin_page' ] );
	}

	public static function admin_page() {
		if ( isset( $_POST['cb_regen'] ) && check_admin_referer( 'cb_regen' ) ) {
			update_option( self::OPT_TOKEN, wp_generate_password( 40, false, false ), false );
			echo '<div class="notice notice-success"><p>Token regenerated.</p></div>';
		}
		settings_errors( 'claude_bridge_group' );
		$base    = rest_url( CB_NS );
		$token   = self::token();
		$mode    = get_option( self::OPT_MODE, 'token_only' );
		$repo    = trim( (string) get_option( self::OPT_REPO ) );
		if ( '' === $repo ) { $repo = self::DEFAULT_REPO; }
		$release = self::github_release();
		$latest  = $release ? ltrim( $release['tag_name'], 'v' ) : null;
		$has_upd = $latest && version_compare( $latest, CB_VERSION, '>' );
		?>
		<div class="wrap">
		<h1>
			Claude Bridge
			<span style="font-size:13px;color:#666;font-weight:400"> v<?php echo CB_VERSION; ?></span>
			<?php if ( $has_upd ) : ?>
				<span style="font-size:13px;color:#d63638;font-weight:400"> — Update available: v<?php echo esc_html( $latest ); ?> (<a href="<?php echo esc_url( $release['html_url'] ); ?>" target="_blank">View on GitHub</a>)</span>
			<?php endif; ?>
		</h1>

		<table class="form-table" style="max-width:820px">
		<tr><th style="width:160px">API base</th><td><code><?php echo esc_html( $base ); ?></code></td></tr>
		<tr><th>Token</th><td>
			<input type="text" readonly onclick="this.select()" style="width:100%;max-width:560px;font-family:monospace;padding:8px" value="<?php echo esc_attr( $token ); ?>"><br>
			<form method="post" style="margin-top:8px"><?php wp_nonce_field( 'cb_regen' ); ?>
				<button class="button" name="cb_regen" value="1">Regenerate token</button>
				<span style="color:#666;margin-left:10px">Regenerating immediately revokes the old token.</span>
			</form>
		</td></tr>
		</table>

		<form method="post" action="options.php" style="max-width:820px">
		<?php settings_fields( 'claude_bridge_group' ); ?>
		<table class="form-table">
		<tr>
			<th style="width:160px">Auth mode</th>
			<td>
				<label><input type="radio" name="<?php echo esc_attr( self::OPT_MODE ); ?>" value="token_only" <?php checked( $mode, 'token_only' ); ?>> <strong>Token only</strong></label>
				<p class="description" style="margin-left:22px">Just the X-Claude-Token header. Use when Application Passwords are disabled or blocked (GoDaddy, Sucuri WAF, etc.).</p>
				<br>
				<label><input type="radio" name="<?php echo esc_attr( self::OPT_MODE ); ?>" value="token_and_apppass" <?php checked( $mode, 'token_and_apppass' ); ?>> <strong>Token + Application Password</strong></label>
				<p class="description" style="margin-left:22px">More secure. Requires admin Application Password via HTTP Basic Auth, plus the token.</p>
			</td>
		</tr>
		<tr>
			<th>GitHub repo</th>
			<td>
				<input type="text" name="<?php echo esc_attr( self::OPT_REPO ); ?>" value="<?php echo esc_attr( $repo ); ?>" placeholder="username/claude-bridge" style="width:320px">
				<p class="description">
					Auto-updates are on by default from <code>adelsherif8/claude-bridge</code>.<br>
					Only change this to track a different fork — format: <code>username/repo</code>.
					<?php if ( $latest ) { echo '<br>Installed: v' . CB_VERSION . ' &nbsp;·&nbsp; GitHub latest: v' . esc_html( $latest ); } ?>
				</p>
			</td>
		</tr>
		</table>
		<?php submit_button( 'Save Settings' ); ?>
		</form>

		<hr style="max-width:820px">
		<h2 style="font-size:15px;margin-top:18px">Endpoints</h2>
		<table class="widefat" style="max-width:820px">
		<thead><tr><th>Method + URL</th><th>Body / Params</th><th>Action</th></tr></thead>
		<tbody>
		<tr><td><code>GET  /ping</code></td><td>—</td><td>Health check + version</td></tr>
		<tr><td><code>GET  /pages</code></td><td>—</td><td>List all pages (id, title, slug, status, link)</td></tr>
		<tr><td><code>GET  /page/{id}</code></td><td>—</td><td>Get full page content</td></tr>
		<tr><td><code>POST /page/create</code></td><td>title, slug?, content|content_b64, status?</td><td>Create a page (draft by default)</td></tr>
		<tr><td><code>POST /page/update</code></td><td>id, content|content_b64, title?, status?</td><td>Update existing page</td></tr>
		<tr><td><code>POST /page/upsert</code></td><td>title, slug, content|content_b64, status?</td><td>Create if slug missing, update if exists</td></tr>
		<tr><td><code>GET  /posts</code></td><td>?type=&amp;search=&amp;limit=</td><td>List posts / pages / elementor templates</td></tr>
		<tr><td><code>POST /replace</code></td><td>ids:[…], pairs:{old:new}, dry_run?</td><td>Scoped find/replace (content + meta)</td></tr>
		<tr><td><code>POST /meta</code></td><td>id, key, value? (omit to read)</td><td>Read or write any post meta key</td></tr>
		</tbody>
		</table>

		<p style="color:#666;max-width:820px;margin-top:14px">
			<strong>Auth:</strong> pass token as <code>X-Claude-Token: {token}</code> header, or append <code>?token={token}</code> to the URL.<br>
			<strong>WAF bypass:</strong> if GoDaddy/Sucuri blocks HTML in POST bodies, base64-encode the HTML and send it as <code>content_b64</code> instead of <code>content</code>. The plugin decodes it server-side.<br>
			<strong>Auto-update:</strong> when a GitHub repo is set, this plugin appears in the WordPress Updates screen like any other plugin.
		</p>
		<hr style="max-width:820px">
		<p style="color:#888">Deactivate this plugin at any time to immediately close all API access.</p>
		</div>
		<?php
	}
}

Claude_Bridge::init();
