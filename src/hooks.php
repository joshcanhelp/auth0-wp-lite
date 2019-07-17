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

	// Need to pass through logout actions and post password check.
	$current_action = isset( $_GET['action'] ) ? $_GET['action'] : null;
	if ( in_array( $current_action, [ 'logout', 'postpass' ] ) ) {
		return;
	}

	if ( is_user_logged_in() ) {
		wp_safe_redirect( home_url() );
		exit;
	}

	// Generate and store a nonce to validate the ID token on return.
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
	$id_token_sub = $id_token->getClaim( 'sub' );
	$id_token_email = $id_token->getClaim( 'email' );
	$id_token_exp = $id_token->getClaim( 'exp' );

	$wp_users = auth0_lite_get_user_by_sub( $id_token_sub );

	// More than one user in the database with the same Auth0 is not a recoverable condition.
	if ( count( $wp_users ) > 1 ) {
		auth0_lite_wp_die( __( 'More than 1 user found with this user ID', 'auth0-lite' ) );
	}

	$wp_user = reset( $wp_users );

	if ( ! $wp_user ) {
		$wp_user = auth0_lite_get_or_create_user( $id_token_email, $id_token_sub );
	}

	if ( ! $wp_user ) {
		auth0_lite_wp_die( __( 'Error finding or creating a user', 'auth0-lite' ) );
	}

	// Set the session expiration to the ID token expiration.
	add_filter(
		'auth_cookie_expiration',
		function( $value, $user_id, $remember ) use ( $id_token_exp ) {
			return $id_token_exp - time();
		},
		100,
		3
	);

	wp_set_auth_cookie( $wp_user->ID, false );
	wp_safe_redirect( home_url() );
	exit;
}
add_action( 'template_redirect', 'auth0_lite_handle_callback' );
