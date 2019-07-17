<?php
/**
 * Plugin Name: Login by Auth0 - Lite
 * Description: Lightweight Auth0 implementation.
 * Version: 0.1.0
 * Author: Josh Cunningham <josh@joshcanhelp.com>
 * Author URI: https://joshcanhelp.com
 * Text Domain: auth0-lite
 *
 * @package Auth0Lite
 */

define( 'AUTH0_LITE_VERSION', '0.1.0' );
define( 'AUTH0_LITE_NONCE_COOKIE', 'auth0_id_token_nonce' );

require 'vendor/autoload.php';

require 'src/functions.php';
require 'src/hooks.php';



