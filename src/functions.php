<?php
/**
 * Global functions for the plugin.
 *
 * @package Auth0Lite
 */

/**
 * Check if the plugin is ready to process logins.
 *
 * @return bool
 */
function auth0_lite_is_ready() {
	return defined( 'AUTH0_LITE_DOMAIN' ) && defined( 'AUTH0_LITE_CLIENT_ID' );
}

/**
 * Kill the process with a message and a login link.
 *
 * @param string $message Message to display on output.
 */
function auth0_lite_wp_die( $message ) {
	wp_die(
		sprintf(
			'%s <p><a href="%s">%s</a></p>',
			$message,
			wp_login_url(),
			__( 'Login', 'auth0-lite' )
		)
	);
}

/**
 * Get the callback URL for login processing.
 *
 * @return string
 */
function auth0_lite_get_callback_url() {
	return add_query_arg( 'auth0', 'callback', site_url( 'index.php' ) );
}

/**
 * Generate the authorize URL for login.
 *
 * @param string $nonce ID token nonce to add to the URL.
 *
 * @return string
 */
function auth0_lite_get_authorize_url( $nonce ) {
	$params = [
		'scope'         => 'openid email',
		'response_type' => 'id_token',
		'response_mode' => 'form_post',
		'redirect_uri'  => auth0_lite_get_callback_url(),
		'client_id'     => constant( 'AUTH0_LITE_CLIENT_ID' ),
		'nonce'         => $nonce,
	];
	$params = array_map( 'rawurlencode', $params );
	return add_query_arg( $params, auth0_lite_get_tenant_url( '/authorize' ) );
}

/**
 * Get the tenant URL.
 *
 * @param string $path Path to append to the tenant URL.
 *
 * @return string
 */
function auth0_lite_get_tenant_url( $path = '/' ) {
	return 'https://' . constant( 'AUTH0_LITE_DOMAIN' ) . $path;
}

/**
 * Get a WordPress user with an Auth0 user ID.
 *
 * @param string $sub Auth0 user ID.
 *
 * @return array
 */
function auth0_lite_get_user_by_sub( $sub ) {
	return get_users(
		[
			'meta_key'   => 'auth0_sub',
			'meta_value' => $sub,
		]
	);
}

/**
 * Get an existing user via email or create a new one if one cannot be found.
 *
 * @param string $email User email.
 * @param string $sub Auth0 user ID.
 *
 * @return false|null|WP_User
 */
function auth0_lite_get_or_create_user( $email, $sub ) {
	$wp_user = get_user_by( 'email', $email );
	if ( ! $wp_user ) {
		$wp_user_id = wp_create_user( $email, $email, wp_generate_password() );
		$wp_user    = is_wp_error( $wp_user_id ) ? null : get_user_by( 'id', $wp_user_id );
	}

	if ( $wp_user instanceof WP_User ) {
		update_user_meta( $wp_user->ID, 'auth0_sub', $sub );
	}

	return $wp_user;
}

/**
 * Validate the ID token.
 *
 * @param string $id_token Incoming ID token.
 *
 * @return \Lcobucci\JWT\Token
 */
function auth0_lite_validate_id_token( $id_token ) {

	$id_token_parsed = ( new \Lcobucci\JWT\Parser() )->parse( $id_token );

	$valid_data = new \Lcobucci\JWT\ValidationData();
	$valid_data->setIssuer( auth0_lite_get_tenant_url() );
	$valid_data->setAudience( constant( 'AUTH0_LITE_CLIENT_ID' ) );

	if ( ! $id_token_parsed->validate( $valid_data ) ) {
		auth0_lite_wp_die( __( 'Invalid ID token', 'auth0-lite' ) );
	}

	$stored_nonce = $_COOKIE[ AUTH0_LITE_NONCE_COOKIE ];
	setcookie( AUTH0_LITE_NONCE_COOKIE, '' );
	if ( rawurldecode( $id_token_parsed->getClaim( 'nonce' ) ) !== $stored_nonce ) {
		auth0_lite_wp_die( __( 'Invalid nonce', 'auth0-lite' ) );
	}

	if ( ! $id_token_parsed->getClaim( 'sub' ) ) {
		auth0_lite_wp_die( __( 'No user ID (sub) found', 'auth0-lite' ) );
	}

	if ( ! $id_token_parsed->getClaim( 'email' ) ) {
		auth0_lite_wp_die( __( 'No email address returned', 'auth0-lite' ) );
	}

	if ( ! $id_token_parsed->getClaim( 'email_verified' ) ) {
		auth0_lite_wp_die( __( 'Email address is not verified', 'auth0-lite' ) );
	}

	return $id_token_parsed;
}
