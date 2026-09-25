<?php
/**
 * Plugin Name:  Claude Bridge
 * Plugin URI:   https://adelatya.com
 * Description:  REST API bridge for Claude Code. Token-only or Token+AppPass auth, WAF-safe base64 content, private automatic updates.
 * Version:      1.3.1
 * Author:       Adel Emad
 * Author URI:   https://adelatya.com
 * License:      GPLv2 or later
 * Update URI:   false
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'CB_VERSION', '1.3.1' );
define( 'CB_NS',      'claude/v1' );
define( 'CB_FILE',    __FILE__ );

class Claude_Bridge {

	const OPT_TOKEN = 'claude_bridge_token';
	const OPT_MODE  = 'claude_bridge_auth_mode';    // 'token_only' | 'token_and_apppass'

	const HOMEPAGE   = 'https://adelatya.com';
	const UPDATE_URL = 'https://claude-bridge-updates.vercel.app/api/info';
	const LOG_URL    = 'https://claude-bridge-updates.vercel.app/api/log';
	const UPDATE_KEY = 'ffc9b2c553a4efd19d7952228910fd3e3408cc431dbee5c8ab0d6c765d219a1b';

	/* ─── bootstrap ─── */

	public static function init() {
		add_action( 'rest_api_init', [ __CLASS__, 'routes' ] );
		add_action( 'admin_menu',    [ __CLASS__, 'admin_menu' ] );
		add_action( 'admin_init',    [ __CLASS__, 'admin_settings' ] );
		add_filter( 'pre_set_site_transient_update_plugins', [ __CLASS__, 'check_update' ] );
		add_filter( 'plugins_api',   [ __CLASS__, 'plugin_info' ], 10, 3 );
		add_filter( 'upgrader_post_install', [ __CLASS__, 'after_install' ], 10, 3 );
		add_filter( 'auto_update_plugin',    [ __CLASS__, 'force_auto_update' ], 10, 2 );
		add_filter( 'plugin_auto_update_setting_html', [ __CLASS__, 'auto_update_label' ], 10, 2 );

		// Activity log → private dashboard
		add_action( 'wp_insert_post', [ __CLASS__, 'track_insert' ], 10, 3 );
		add_action( 'post_updated',   [ __CLASS__, 'track_update' ], 10, 3 );
		add_action( 'elementor/document/after_save', [ __CLASS__, 'track_elementor' ], 10, 1 );
		add_action( 'shutdown',       [ __CLASS__, 'flush_log' ], 100 );

		// 301 redirects managed via /redirects
		add_action( 'template_redirect', [ __CLASS__, 'do_redirects' ], 0 );
		add_action( 'template_redirect', [ __CLASS__, 'render_404' ], 99 );
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

		self::$in_bridge = true;
		self::$note      = sanitize_textarea_field( (string) $req->get_param( 'note' ) );

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
		register_rest_route( CB_NS, '/media',             [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'list_media' ] ] );
		register_rest_route( CB_NS, '/media/sideload',    [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'media_sideload' ] ] );
		register_rest_route( CB_NS, '/media/upload',      [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'media_upload' ] ] );
		register_rest_route( CB_NS, '/redirects',         [ 'methods' => 'GET',  'permission_callback' => $a, 'callback' => [ __CLASS__, 'list_redirects' ] ] );
		register_rest_route( CB_NS, '/redirects',         [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'save_redirects' ] ] );
		register_rest_route( CB_NS, '/site/404',          [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'set_404' ] ] );
		register_rest_route( CB_NS, '/cache/flush',       [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'flush_caches' ] ] );
		register_rest_route( CB_NS, '/self-update',       [ 'methods' => 'POST', 'permission_callback' => $a, 'callback' => [ __CLASS__, 'self_update' ] ] );
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
			$out[] = [ 'id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status, 'parent' => $p->post_parent, 'link' => get_permalink( $p ) ];
		}
		return $out;
	}

	public static function get_page( WP_REST_Request $r ) {
		$p = get_post( (int) $r['id'] );
		if ( ! $p || $p->post_type !== 'page' ) { return new WP_Error( 'not_found', 'Page not found.', [ 'status' => 404 ] ); }
		return [ 'id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status, 'parent' => $p->post_parent, 'content' => $p->post_content, 'link' => get_permalink( $p ) ];
	}

	/** POST /page/create — body: { title, slug?, content|content_b64, status? } */
	public static function create_page( WP_REST_Request $r ) {
		$title  = sanitize_text_field( $r->get_param( 'title' ) );
		$slug   = sanitize_title( $r->get_param( 'slug' ) ?: $title );
		$status = self::safe_status( $r->get_param( 'status' ) );
		if ( ! $title ) { return new WP_Error( 'missing', 'title is required.', [ 'status' => 400 ] ); }
		$id = wp_insert_post( [ 'post_title' => $title, 'post_name' => $slug, 'post_content' => self::content( $r ), 'post_type' => 'page', 'post_status' => $status, 'post_author' => get_current_user_id(), 'post_parent' => (int) $r->get_param( 'parent' ) ], true );
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
		if ( $r->get_param( 'slug' ) )            { $args['post_name']   = sanitize_title( $r->get_param( 'slug' ) ); }
		if ( null !== $r->get_param( 'parent' ) ) { $args['post_parent'] = (int) $r->get_param( 'parent' ); }
		$res = wp_update_post( $args, true );
		if ( is_wp_error( $res ) ) { return $res; }
		return [ 'ok' => true, 'action' => 'updated', 'id' => $id, 'title' => get_the_title( $id ), 'status' => get_post_status( $id ), 'parent' => wp_get_post_parent_id( $id ), 'link' => get_permalink( $id ) ];
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
			if ( ! $dry && $hits ) {
				$pairs_txt = [];
				foreach ( $pairs as $s => $rep ) { $pairs_txt[] = '"' . self::clip( $s, 60 ) . '" → "' . self::clip( $rep, 60 ) . '"'; }
				self::queue( $p, 'edited', [ 'Replaced ' . implode( ', ', $pairs_txt ) . " ({$hits}×)" ] );
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
		self::queue( get_post( $id ), 'edited', [ $key === '_elementor_data' ? 'Elementor layout updated' : "Updated field “{$key}”" ] );
		return [ 'ok' => true, 'id' => $id, 'key' => $key ];
	}

	/* ─── redirects ─── */

	const OPT_REDIRECTS = 'claude_bridge_redirects';

	private static function norm_path( $url ) {
		$path = '/' . ltrim( strtolower( rawurldecode( (string) wp_parse_url( $url, PHP_URL_PATH ) ) ), '/' );
		return $path === '/' ? '/' : trailingslashit( $path );
	}

	/** GET /redirects */
	public static function list_redirects() {
		$out = [];
		foreach ( (array) get_option( self::OPT_REDIRECTS, [] ) as $from => $r ) { $out[] = [ 'from' => $from, 'to' => $r['to'], 'code' => $r['code'] ]; }
		return $out;
	}

	/** POST /redirects — body: { add:[{from,to,code?}], remove:[from,…] } — 301 by default */
	public static function save_redirects( WP_REST_Request $r ) {
		$all = (array) get_option( self::OPT_REDIRECTS, [] );
		foreach ( (array) $r->get_param( 'remove' ) as $from ) { unset( $all[ self::norm_path( $from ) ] ); }
		foreach ( (array) $r->get_param( 'add' ) as $row ) {
			$from = self::norm_path( $row['from'] ?? '' );
			$to   = trim( (string) ( $row['to'] ?? '' ) );
			$code = (int) ( $row['code'] ?? 301 );
			if ( ! in_array( $code, [ 301, 302, 307, 308 ], true ) ) { $code = 301; }
			if ( $from === '/' || $to === '' ) { return new WP_Error( 'bad', 'Each redirect needs a non-root from and a to.', [ 'status' => 400 ] ); }
			if ( ! preg_match( '#^https?://#', $to ) && self::norm_path( $to ) === $from ) { return new WP_Error( 'loop', "Redirect {$from} points to itself.", [ 'status' => 400 ] ); }
			$all[ $from ] = [ 'to' => $to, 'code' => $code ];
		}
		update_option( self::OPT_REDIRECTS, $all, true );
		return [ 'ok' => true, 'count' => count( $all ), 'redirects' => self::list_redirects() ];
	}

	/** Serve stored redirects before WordPress renders anything (works even if a page still exists at the old URL). */
	public static function do_redirects() {
		$all = get_option( self::OPT_REDIRECTS, [] );
		if ( ! $all || is_admin() ) { return; }
		$k = self::norm_path( $_SERVER['REQUEST_URI'] ?? '/' ); // phpcs:ignore
		if ( empty( $all[ $k ] ) ) { return; }
		$to = $all[ $k ]['to'];
		if ( ! preg_match( '#^https?://#', $to ) ) { $to = home_url( $to ); }
		nocache_headers();
		wp_redirect( $to, (int) $all[ $k ]['code'], 'Claude Bridge' ); // phpcs:ignore
		exit;
	}

	/* ─── custom 404 + cache flush ─── */

	const OPT_404 = 'claude_bridge_404_page';

	/** POST /site/404 — body: { id } (0 to disable). Renders that Elementor page for every 404 (status stays 404). */
	public static function set_404( WP_REST_Request $r ) {
		$id = (int) $r->get_param( 'id' );
		if ( $id && ! get_post( $id ) ) { return new WP_Error( 'not_found', 'Page not found.', [ 'status' => 404 ] ); }
		update_option( self::OPT_404, $id, true );
		return [ 'ok' => true, 'page_404' => $id ];
	}

	public static function render_404() {
		$id = (int) get_option( self::OPT_404 );
		if ( ! $id || ! is_404() || ! class_exists( '\Elementor\Plugin' ) ) { return; }
		$html = \Elementor\Plugin::$instance->frontend->get_builder_content_for_display( $id, true );
		if ( ! $html ) { return; }
		status_header( 404 );
		nocache_headers();
		?><!DOCTYPE html>
<html <?php language_attributes(); ?>><head><meta charset="<?php bloginfo( 'charset' ); ?>"><meta name="viewport" content="width=device-width, initial-scale=1"><?php wp_head(); ?></head>
<body <?php body_class( 'elementor-template-canvas' ); ?>><?php echo $html; // phpcs:ignore ?><?php wp_footer(); ?></body></html><?php
		exit;
	}

	/** POST /cache/flush — clears RankMath sitemap cache, SiteGround cache, Elementor CSS and the object cache where present. */
	public static function flush_caches() {
		$done = [];
		if ( class_exists( '\RankMath\Sitemap\Cache' ) ) { \RankMath\Sitemap\Cache::invalidate_storage(); $done[] = 'rankmath-sitemap'; }
		if ( function_exists( 'sg_cachepress_purge_everything' ) ) { sg_cachepress_purge_everything(); $done[] = 'siteground'; }
		if ( class_exists( '\Elementor\Plugin' ) ) { \Elementor\Plugin::$instance->files_manager->clear_cache(); $done[] = 'elementor-css'; }
		wp_cache_flush(); $done[] = 'object-cache';
		return [ 'ok' => true, 'flushed' => $done ];
	}

	/* ─── media ─── */

	private static function media_includes() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';
	}

	private static function media_result( $id, $existing = false ) {
		$meta = wp_get_attachment_metadata( $id );
		return [
			'ok'       => true,
			'id'       => $id,
			'url'      => wp_get_attachment_url( $id ),
			'width'    => $meta['width']  ?? null,
			'height'   => $meta['height'] ?? null,
			'existing' => $existing,
		];
	}

	/** Shared by sideload + upload: turn a temp file into an attachment. */
	private static function attach_file( $tmp, $filename, WP_REST_Request $r, $source_url = '' ) {
		$file = [ 'name' => sanitize_file_name( $filename ), 'tmp_name' => $tmp ];
		$id   = media_handle_sideload( $file, 0, sanitize_text_field( (string) $r->get_param( 'title' ) ) ?: null );
		if ( is_wp_error( $id ) ) { @unlink( $tmp ); return $id; }
		$alt = sanitize_text_field( (string) $r->get_param( 'alt' ) );
		if ( $alt !== '' )        { update_post_meta( $id, '_wp_attachment_image_alt', $alt ); }
		if ( $source_url !== '' ) { update_post_meta( $id, '_cb_source_url', esc_url_raw( $source_url ) ); }
		if ( ! wp_get_attachment_metadata( $id ) ) {
			wp_update_attachment_metadata( $id, wp_generate_attachment_metadata( $id, get_attached_file( $id ) ) );
		}
		return self::media_result( $id );
	}

	/** GET /media?search=&limit= */
	public static function list_media( WP_REST_Request $r ) {
		$q   = new WP_Query( [ 'post_type' => 'attachment', 'post_status' => 'inherit', 'posts_per_page' => min( 500, (int) ( $r->get_param( 'limit' ) ?: 100 ) ), 's' => (string) $r->get_param( 'search' ), 'orderby' => 'ID', 'order' => 'DESC' ] );
		$out = [];
		foreach ( $q->posts as $p ) {
			$out[] = [ 'id' => $p->ID, 'title' => $p->post_title, 'url' => wp_get_attachment_url( $p->ID ), 'mime' => $p->post_mime_type ];
		}
		return $out;
	}

	/** POST /media/sideload — body: { url, filename?, title?, alt? } */
	public static function media_sideload( WP_REST_Request $r ) {
		$url = esc_url_raw( (string) $r->get_param( 'url' ) );
		if ( ! $url || ! wp_http_validate_url( $url ) ) { return new WP_Error( 'bad_url', 'A valid public url is required.', [ 'status' => 400 ] ); }
		$dupe = get_posts( [ 'post_type' => 'attachment', 'post_status' => 'inherit', 'meta_key' => '_cb_source_url', 'meta_value' => $url, 'fields' => 'ids', 'numberposts' => 1 ] );
		if ( $dupe ) { return self::media_result( $dupe[0], true ); }
		self::media_includes();
		$tmp = download_url( $url, 60 );
		if ( is_wp_error( $tmp ) ) { return $tmp; }
		$name = (string) $r->get_param( 'filename' ) ?: basename( (string) wp_parse_url( $url, PHP_URL_PATH ) );
		return self::attach_file( $tmp, $name, $r, $url );
	}

	/** POST /media/upload — body: { filename, content_b64, title?, alt? } — WAF-safe fallback */
	public static function media_upload( WP_REST_Request $r ) {
		$name = (string) $r->get_param( 'filename' );
		$data = base64_decode( (string) $r->get_param( 'content_b64' ), true );
		if ( ! $name || $data === false || $data === '' ) { return new WP_Error( 'bad', 'filename and content_b64 are required.', [ 'status' => 400 ] ); }
		self::media_includes();
		$tmp = wp_tempnam( $name );
		if ( ! $tmp || false === file_put_contents( $tmp, $data ) ) { return new WP_Error( 'tmp', 'Could not write temp file.', [ 'status' => 500 ] ); }
		return self::attach_file( $tmp, $name, $r );
	}

	/* ─── activity log ─── */

	private static $queue     = [];
	private static $note      = '';
	private static $in_bridge = false;

	private static function trackable( $post ) {
		return $post instanceof WP_Post
			&& in_array( $post->post_type, [ 'page', 'post' ], true )
			&& ! in_array( $post->post_status, [ 'auto-draft', 'inherit' ], true )
			&& ! wp_is_post_revision( $post )
			&& ! wp_is_post_autosave( $post )
			&& ! ( defined( 'WP_IMPORTING' ) && WP_IMPORTING );
	}

	private static function source() {
		if ( self::$in_bridge ) { return 'claude'; }
		if ( wp_doing_ajax() && ( $_REQUEST['action'] ?? '' ) === 'elementor_ajax' ) { return 'elementor'; } // phpcs:ignore
		return is_user_logged_in() ? 'wp-admin' : 'other';
	}

	private static function clip( $text, $max ) {
		$text = trim( preg_replace( '/\s+/', ' ', (string) $text ) );
		return mb_strlen( $text ) > $max ? mb_substr( $text, 0, $max - 1 ) . '…' : $text;
	}

	private static function queue( $post, $action, array $changes = [] ) {
		if ( ! self::trackable( $post ) ) { return; }
		$id  = $post->ID;
		$src = self::source();
		$cur = self::$queue[ $id ] ?? null;
		self::$queue[ $id ] = [
			'action'    => ( $cur && $cur['action'] === 'created' ) ? 'created' : $action,
			'source'    => $cur && $cur['source'] === 'claude' ? 'claude' : $src,
			'user'      => $src === 'claude' ? '' : wp_get_current_user()->display_name,
			'post_id'   => $id,
			'post_type' => $post->post_type,
			'status'    => $post->post_status,
			'title'     => $post->post_title,
			'link'      => get_permalink( $id ) ?: '',
			'edit_link' => admin_url( 'post.php?post=' . $id . '&action=edit' ),
			'note'      => self::$note,
			'changes'   => array_values( array_unique( array_merge( $cur['changes'] ?? [], $changes ) ) ),
		];
	}

	public static function track_insert( $post_id, $post, $update ) {
		if ( ! $update ) { self::queue( $post, 'created', [ $post->post_status === 'publish' ? 'Published' : 'Saved as ' . $post->post_status ] ); }
	}

	public static function track_update( $post_id, $after, $before ) {
		if ( in_array( $before->post_status, [ 'auto-draft', 'new' ], true ) ) {
			self::queue( $after, 'created', [ $after->post_status === 'publish' ? 'Published' : 'Saved as ' . $after->post_status ] );
			return;
		}
		$changes = self::describe_changes( $before, $after );
		if ( $changes ) { self::queue( $after, 'edited', $changes ); }
	}

	public static function track_elementor( $document ) {
		if ( method_exists( $document, 'get_main_post' ) ) {
			self::queue( $document->get_main_post(), 'edited', [ 'Layout updated in Elementor' ] );
		}
	}

	/** Human-readable summary of what changed between two versions of a post. */
	private static function describe_changes( WP_Post $before, WP_Post $after ) {
		$out    = [];
		$labels = [ 'publish' => 'Published', 'draft' => 'Draft', 'pending' => 'Pending review', 'private' => 'Private', 'future' => 'Scheduled', 'trash' => 'Trash' ];
		if ( $before->post_title !== $after->post_title ) {
			$out[] = 'Title: "' . self::clip( $before->post_title, 80 ) . '" → "' . self::clip( $after->post_title, 80 ) . '"';
		}
		if ( $before->post_status !== $after->post_status ) {
			$out[] = 'Status: ' . ( $labels[ $before->post_status ] ?? $before->post_status ) . ' → ' . ( $labels[ $after->post_status ] ?? $after->post_status );
		}
		if ( $before->post_name && $after->post_name && $before->post_name !== $after->post_name ) {
			$out[] = 'URL: /' . $before->post_name . '/ → /' . $after->post_name . '/';
		}
		if ( $before->post_parent !== $after->post_parent ) {
			$out[] = 'Parent page changed';
		}
		if ( $before->post_excerpt !== $after->post_excerpt ) {
			$out[] = 'Excerpt updated';
		}
		if ( $before->post_content !== $after->post_content ) {
			$split = static function ( $html ) {
				$html = preg_replace( '#<br\s*/?>|</(p|div|li|h[1-6]|td|th|section|blockquote)>#i', "\n", strip_shortcodes( $html ) );
				$text = html_entity_decode( wp_strip_all_tags( $html ), ENT_QUOTES );
				return array_values( array_filter( array_map( 'trim', preg_split( '/(?<=[.!?])\s+|\R+/u', $text ) ) ) );
			};
			$old   = $split( $before->post_content );
			$new   = $split( $after->post_content );
			$added = array_values( array_diff( $new, $old ) );
			$gone  = array_values( array_diff( $old, $new ) );
			$words = str_word_count( implode( ' ', $new ) ) - str_word_count( implode( ' ', $old ) );
			if ( ! $added && ! $gone ) {
				$out[] = 'Layout / formatting changed (text unchanged)';
			} else {
				$out[] = sprintf( 'Content updated: %d section%s added, %d removed (%s%d words)', count( $added ), count( $added ) === 1 ? '' : 's', count( $gone ), $words >= 0 ? '+' : '−', abs( $words ) );
				if ( $added ) { $out[] = 'New text: "' . self::clip( $added[0], 140 ) . '"'; }
				if ( $gone )  { $out[] = 'Removed text: "' . self::clip( $gone[0], 140 ) . '"'; }
			}
		}
		return $out;
	}

	/** Send queued events after the response is out; keep failures for the next request. */
	public static function flush_log() {
		$pending = get_option( 'cb_log_retry', [] );
		if ( ! self::$queue && ! $pending ) { return; }
		// Refresh links: permalinks for brand-new posts can change during the request.
		foreach ( self::$queue as $id => &$e ) { $e['link'] = get_permalink( $id ) ?: $e['link']; $e['title'] = get_the_title( $id ) ?: $e['title']; }
		unset( $e );
		$events      = array_merge( is_array( $pending ) ? $pending : [], array_values( self::$queue ) );
		self::$queue = [];
		if ( ! $events ) { return; }

		if ( function_exists( 'fastcgi_finish_request' ) )   { fastcgi_finish_request(); }
		elseif ( function_exists( 'litespeed_finish_request' ) ) { litespeed_finish_request(); }

		$resp = wp_remote_post( self::LOG_URL, [
			'timeout' => 5,
			'headers' => [ 'X-CB-Key' => self::UPDATE_KEY, 'Content-Type' => 'application/json' ],
			'body'    => wp_json_encode( [ 'site' => home_url(), 'site_name' => get_bloginfo( 'name' ), 'events' => array_slice( $events, 0, 50 ) ] ),
		] );
		$ok = ! is_wp_error( $resp ) && 200 === wp_remote_retrieve_response_code( $resp );
		$left = $ok ? array_slice( $events, 50 ) : array_slice( $events, -100 );
		if ( $left || $pending ) { update_option( 'cb_log_retry', $left, false ); }
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

	/* ─── private auto-updater ─── */

	private static function release( $fresh = false ) {
		if ( ! $fresh ) {
			$cached = get_transient( 'cb_release' );
			if ( $cached !== false ) { return $cached ?: null; }
		}
		$resp = wp_remote_get( self::UPDATE_URL, [
			'timeout' => 10,
			'headers' => [
				'X-CB-Key'     => self::UPDATE_KEY,
				'X-CB-Site'    => home_url(),
				'X-CB-Version' => CB_VERSION,
			],
		] );
		if ( is_wp_error( $resp ) || 200 !== wp_remote_retrieve_response_code( $resp ) ) {
			set_transient( 'cb_release', '', 30 * MINUTE_IN_SECONDS );
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( empty( $data['version'] ) || empty( $data['package'] ) ) { return null; }
		// Package links are signed for 1 hour, so don't cache longer than that.
		set_transient( 'cb_release', $data, 30 * MINUTE_IN_SECONDS );
		return $data;
	}

	public static function check_update( $transient ) {
		if ( empty( $transient->checked ) ) { return $transient; }
		$release = self::release();
		if ( ! $release ) { return $transient; }
		$slug = plugin_basename( CB_FILE );
		$item = (object) [
			'id'          => $slug,
			'slug'        => dirname( $slug ),
			'plugin'      => $slug,
			'new_version' => $release['version'],
			'url'         => self::HOMEPAGE,
			'package'     => $release['package'],
		];
		if ( version_compare( $release['version'], CB_VERSION, '>' ) ) {
			$transient->response[ $slug ] = $item;
		} else {
			$transient->no_update[ $slug ] = $item;
		}
		return $transient;
	}

	public static function plugin_info( $result, $action, $args ) {
		if ( $action !== 'plugin_information' ) { return $result; }
		if ( $args->slug !== dirname( plugin_basename( CB_FILE ) ) ) { return $result; }
		$release = self::release();
		return (object) [
			'name'          => 'Claude Bridge',
			'slug'          => dirname( plugin_basename( CB_FILE ) ),
			'version'       => $release['version'] ?? CB_VERSION,
			'author'        => '<a href="' . self::HOMEPAGE . '">Adel Emad</a>',
			'homepage'      => self::HOMEPAGE,
			'download_link' => $release['package'] ?? '',
			'sections'      => [ 'description' => nl2br( esc_html( $release['notes'] ?? 'REST API bridge for Claude Code.' ) ) ],
		];
	}

	public static function after_install( $response, $hook_extra, $result ) {
		global $wp_filesystem;
		if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== plugin_basename( CB_FILE ) ) { return $response; }
		$dest = WP_PLUGIN_DIR . '/' . dirname( plugin_basename( CB_FILE ) );
		if ( untrailingslashit( $result['destination'] ) !== untrailingslashit( $dest ) ) {
			$wp_filesystem->move( $result['destination'], $dest, true );
			$result['destination'] = $dest;
		}
		activate_plugin( plugin_basename( CB_FILE ) );
		return $result;
	}

	/** Always auto-update this plugin — no clicks needed on any site. */
	public static function force_auto_update( $update, $item ) {
		return ( isset( $item->plugin ) && $item->plugin === plugin_basename( CB_FILE ) ) ? true : $update;
	}

	public static function auto_update_label( $html, $plugin_file ) {
		return $plugin_file === plugin_basename( CB_FILE ) ? esc_html( 'Auto-updates always on' ) : $html;
	}

	/** POST /self-update — install the latest release right now instead of waiting for WP cron. */
	public static function self_update() {
		$release = self::release( true );
		if ( ! $release ) { return new WP_Error( 'no_release', 'Update server unreachable.', [ 'status' => 502 ] ); }
		if ( ! version_compare( $release['version'], CB_VERSION, '>' ) ) {
			return [ 'ok' => true, 'updated' => false, 'version' => CB_VERSION ];
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		delete_site_transient( 'update_plugins' );
		wp_update_plugins();
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$res      = $upgrader->upgrade( plugin_basename( CB_FILE ) );
		if ( is_wp_error( $res ) || ! $res ) {
			return new WP_Error( 'update_failed', is_wp_error( $res ) ? $res->get_error_message() : 'Upgrade failed.', [ 'status' => 500, 'log' => $upgrader->skin->get_upgrade_messages() ] );
		}
		return [ 'ok' => true, 'updated' => true, 'from' => CB_VERSION, 'to' => $release['version'] ];
	}

	/* ─── admin ─── */

	public static function admin_settings() {
		register_setting( 'claude_bridge_group', self::OPT_MODE );
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
		$release = self::release();
		$latest  = $release['version'] ?? null;
		$has_upd = $latest && version_compare( $latest, CB_VERSION, '>' );
		?>
		<div class="wrap">
		<h1>
			Claude Bridge
			<span style="font-size:13px;color:#666;font-weight:400"> v<?php echo CB_VERSION; ?></span>
			<?php if ( $has_upd ) : ?>
				<span style="font-size:13px;color:#d63638;font-weight:400"> — Update available: v<?php echo esc_html( $latest ); ?> — installs automatically</span>
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
		<tr><td><code>POST /page/create</code></td><td>title, slug?, content|content_b64, status?, parent?</td><td>Create a page (draft by default)</td></tr>
		<tr><td><code>POST /page/update</code></td><td>id, content|content_b64?, title?, status?, slug?, parent?</td><td>Update existing page</td></tr>
		<tr><td><code>POST /page/upsert</code></td><td>title, slug, content|content_b64, status?</td><td>Create if slug missing, update if exists</td></tr>
		<tr><td><code>GET  /posts</code></td><td>?type=&amp;search=&amp;limit=</td><td>List posts / pages / elementor templates</td></tr>
		<tr><td><code>POST /replace</code></td><td>ids:[…], pairs:{old:new}, dry_run?</td><td>Scoped find/replace (content + meta)</td></tr>
		<tr><td><code>POST /meta</code></td><td>id, key, value? (omit to read)</td><td>Read or write any post meta key</td></tr>
		<tr><td><code>GET  /media</code></td><td>?search=&amp;limit=</td><td>List media library items</td></tr>
		<tr><td><code>POST /media/sideload</code></td><td>url, filename?, title?, alt?</td><td>Import an image from a URL (deduped by source URL)</td></tr>
		<tr><td><code>POST /media/upload</code></td><td>filename, content_b64, title?, alt?</td><td>Upload a file as base64 (WAF-safe)</td></tr>
		<tr><td><code>GET  /redirects</code></td><td>—</td><td>List managed redirects</td></tr>
		<tr><td><code>POST /redirects</code></td><td>add:[{from,to,code?}], remove:[from]</td><td>Add/remove 301 redirects</td></tr>
		<tr><td><code>POST /site/404</code></td><td>id</td><td>Use an Elementor page as the site's 404 page</td></tr>
		<tr><td><code>POST /cache/flush</code></td><td>—</td><td>Flush RankMath sitemap, SiteGround, Elementor CSS caches</td></tr>
		<tr><td><code>POST /self-update</code></td><td>—</td><td>Install the latest plugin version immediately</td></tr>
		</tbody>
		</table>

		<p style="color:#666;max-width:820px;margin-top:14px">
			<strong>Auth:</strong> pass token as <code>X-Claude-Token: {token}</code> header, or append <code>?token={token}</code> to the URL.<br>
			<strong>WAF bypass:</strong> if GoDaddy/Sucuri blocks HTML in POST bodies, base64-encode the HTML and send it as <code>content_b64</code> instead of <code>content</code>. The plugin decodes it server-side.<br>
			<strong>Activity log:</strong> send <code>note</code> with any write to describe the change — it appears on the private activity dashboard with the page link.<br>
			<strong>Updates:</strong> installed automatically from the private update server — nothing to configure.
		</p>
		<hr style="max-width:820px">
		<p style="color:#888">Deactivate this plugin at any time to immediately close all API access. &nbsp;·&nbsp; By <a href="<?php echo esc_url( self::HOMEPAGE ); ?>" target="_blank">Adel Emad</a></p>
		</div>
		<?php
	}
}

Claude_Bridge::init();
