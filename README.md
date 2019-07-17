# Auth0 Lite

This is a quick experiment with adding the simplest possible Auth0 integration to WordPress.

**Important:** This is code NOT tested, reviewed, or security checked and should NOT be used in production! 

## Getting Started

1. Create a new Application in [Auth0](https://manage.auth0.com/#/applications).
2. Give it a name and select **Regular Web Application**.
3. Set your **Allowed Callback URLs** to `[SITE URL]/index.php?auth0=callback`.
4. Set your **Allowed Logout URLs** to WordPress home page URL.
5. Set your **JWT Expiration (seconds)** to the session length you want for WordPress.
6. Click **Show Advanced Settings** then **Grant Types** and turn everything off except **Implicit**
7. Click **Save Changes**.
8. In your `wp-config.php` file, add the following lines using the Client ID and Domain from your Application:

```php
define( 'AUTH0_LITE_DOMAIN', 'YOUR_TENANT_DOMAIN' );
define( 'AUTH0_LITE_CLIENT_ID', 'YOUR_APPLICATION_CLIENT_ID' );
``` 
