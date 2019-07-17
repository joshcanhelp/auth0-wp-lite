<?php
function auth0_lite_is_ready() {
	return defined( 'AUTH0_LITE_DOMAIN' ) && defined( 'AUTH0_LITE_CLIENT_ID' );
}

function auth0_lite_is_allowed_wp_login_action() {
	$current_action = isset( $_GET['action'] ) ? $_GET['action'] : null;
	return in_array( $current_action, [ 'logout', 'postpass' ] );
}

function auth0_lite_get_callback_url() {
	return add_query_arg( 'auth0', 'callback', site_url( 'index.php' ) );
}

function auth0_lite_get_authorize_url( $nonce ) {
	$params = [
		'scope' => 'openid email',
		'response_type' => 'id_token',
		'response_mode' => 'form_post',
		'redirect_uri' => auth0_lite_get_callback_url(),
		'client_id' => constant( 'AUTH0_LITE_CLIENT_ID' ),
		'nonce' => $nonce
	];
	$params = array_map( 'rawurlencode', $params );
	return add_query_arg( $params, auth0_lite_get_tenant_url( '/authorize' ) );
}

function auth0_lite_get_tenant_url( $path = '/' ) {
	return 'https://' . constant( 'AUTH0_LITE_DOMAIN' ) . $path;
}

function auth0_lite_get_user_by_sub( $sub ) {
	return get_users( [ 'meta_key' => 'auth0_sub', 'meta_value' => $sub ] );
}

function auth0_lite_get_or_create_user( $claims ) {
	$wp_user = get_user_by( 'email', $claims->email );
	if ( ! $wp_user ) {
		$wp_user_id = wp_create_user( $claims->email, $claims->email, wp_generate_password() );
		$wp_user = is_wp_error( $wp_user_id ) ? null : get_user_by( 'id', $wp_user_id );
	}

	if ( $wp_user instanceof WP_User) {
		update_user_meta( $wp_user->ID, 'auth0_sub', $claims->sub );
	}

	return $wp_user;
}

function auth0_lite_validate_id_token( $id_token ) {

	// TODO: Add ID token validation
	$id_token_payload = explode( '.', $id_token )[1];
	$id_token_claims = base64_decode( $id_token_payload );
	$id_token_claims = json_decode( $id_token_claims );

	if ( ! isset( $id_token_claims->iss ) || auth0_lite_get_tenant_url() !== $id_token_claims->iss ) {
		wp_die( __( 'Invalid token iss', 'auth0-lite' ) );
	}

	if ( ! isset( $id_token_claims->aud ) || constant( 'AUTH0_LITE_CLIENT_ID' ) !== $id_token_claims->aud ) {
		wp_die( __( 'Invalid token aud', 'auth0-lite' ) );
	}

	// TODO: Add ID token nonce check

	if ( empty( $id_token_claims->sub ) ) {
		wp_die( __( 'No user ID (sub) found', 'auth0-lite' ) );
	}

	if ( empty( $id_token_claims->email ) ) {
		wp_die( __( 'No email address returned', 'auth0-lite' ) );
	}

	if ( empty( $id_token_claims->email_verified ) ) {
		wp_die( __( 'Email address is not verified', 'auth0-lite' ) );
	}

	return $id_token_claims;
}
