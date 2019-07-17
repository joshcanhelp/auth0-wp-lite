<?php
/**
 * WordPress hooks used by the plugin.
 *
 * @package Auth0Lite
 */

/**
 * Add the Auth0 tenant domain to the redirect whitelist.
 *
 * @param array $hosts Existing whitelisted redirect hosts.
 *
 * @return array
 */
function auth0_lite_filter_allowed_redirect_hosts( array $hosts ) {
	$hosts[] = constant( 'AUTH0_LITE_DOMAIN' );
	return $hosts;
}
add_filter( 'allowed_redirect_hosts', 'auth0_lite_filter_allowed_redirect_hosts' );

/**
 * Redirect to the Auth0 login page if conditions are met.
 */
function auth0_lite_handle_login_redirect() {
	if ( ! auth0_lite_is_ready() ) {
		return;
	}

	$current_action = isset( $_GET['action'] ) ? $_GET['action'] : null;
	if ( in_array( $current_action, [ 'logout', 'postpass' ] ) ) {
		return;
	}

	if ( is_user_logged_in() ) {
		wp_safe_redirect( home_url() );
		exit;
	}

	$nonce = bin2hex( random_bytes( 32 ) );
	setcookie( AUTH0_LITE_NONCE_COOKIE, $nonce, time() + HOUR_IN_SECONDS, '/' );
	wp_safe_redirect( auth0_lite_get_authorize_url( $nonce ) );
	exit;
}
add_action( 'login_init', 'auth0_lite_handle_login_redirect' );

/**
 * Redirect to Auth0 to logout when logging out of WordPress.
 */
function auth0_lite_handle_logout() {
	if ( ! auth0_lite_is_ready() ) {
		return;
	}

	$params     = [
		'client_id' => constant( 'AUTH0_LITE_CLIENT_ID' ),
		'returnTo'  => rawurlencode( home_url() ),
	];
	$logout_url = add_query_arg( $params, auth0_lite_get_tenant_url( '/v2/logout' ) );
	wp_safe_redirect( $logout_url );
	exit;
}
add_action( 'wp_logout', 'auth0_lite_handle_logout' );

/**
 * Handle the callback from Auth0 login.
 */
function auth0_lite_handle_callback() {
	if ( empty( $_GET['auth0'] ) || 'callback' !== $_GET['auth0'] ) {
		return;
	}

	if ( ! auth0_lite_is_ready() ) {
		return;
	}

	if ( ! empty( $_REQUEST['error'] ) || ! empty( $_REQUEST['error_description'] ) ) {
		$error_msg = sanitize_text_field( rawurldecode( $_REQUEST['error_description'] ?: $_REQUEST['error'] ) );
		auth0_lite_wp_die( $error_msg );
	}

	if ( is_user_logged_in() ) {
		wp_safe_redirect( home_url() );
		exit;
	}

	if ( empty( $_POST['id_token'] ) ) {
		auth0_lite_wp_die( __( 'No ID token found', 'auth0-lite' ) );
	}

	$id_token = auth0_lite_validate_id_token( $_POST['id_token'] );

	$wp_users = auth0_lite_get_user_by_sub( $id_token->getClaim( 'sub' ) );
	if ( count( $wp_users ) > 1 ) {
		auth0_lite_wp_die( __( 'More than 1 user found with this user ID', 'auth0-lite' ) );
	}

	if ( empty( $wp_users ) ) {
		$wp_user = auth0_lite_get_or_create_user( $id_token->getClaim( 'email' ), $id_token->getClaim( 'sub' ) );
	} else {
		$wp_user = reset( $wp_users );
	}

	if ( ! $wp_user ) {
		auth0_lite_wp_die( __( 'Error finding or creating a user', 'auth0-lite' ) );
	}

	$session_expire = $id_token->getClaim( 'exp' ) - time();
	add_filter(
		'auth_cookie_expiration',
		function( $value, $user_id, $remember ) use ( $session_expire ) {
			return $session_expire;
		},
		100,
		3
	);

	$secure_cookie = apply_filters(
		'secure_signon_cookie',
		is_ssl(),
		[
			'user_login'    => $wp_user->user_login,
			'user_password' => null,
			'remember'      => false,
		]
	);

	wp_set_auth_cookie( $wp_user->ID, false, $secure_cookie );
	wp_safe_redirect( home_url() );
	exit;
}
add_action( 'template_redirect', 'auth0_lite_handle_callback' );
