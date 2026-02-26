# MaiExpoWP WordPress Plugin - Agent Context

This WordPress plugin provides REST API endpoints for mobile apps using the maiexpowp React Native library.

## CRITICAL: App-Agnostic Rule

**This plugin MUST remain app-agnostic.** It is a shared library used by multiple apps (QwikCoach, etc.).

**NEVER add:**
- App-specific business logic (e.g., `is_peopletak`, `qc_*` anything)
- Hardcoded IDs specific to one app
- App-specific user flags or checks

**ALWAYS use filters** to allow apps to extend functionality in their own mu-plugins files:
- `maiexpowp_user_profile_data` - extend profile response
- `maiexpowp_user_membership_data` - add custom membership flags
- `maiexpowp_allowed_user_meta_keys` - allow app-specific meta keys

**Example - WRONG (in maiexpowp-plugin):**
```php
$is_peopletak = in_array( 7176, $plan_ids ); // NO! App-specific
```

**Example - CORRECT (in app's mu-plugins):**
```php
add_filter( 'maiexpowp_user_membership_data', function( $data, $user_id, $plan_ids ) {
    $data['is_peopletak'] = in_array( 7176, $plan_ids );
    return $data;
}, 10, 3 );
```

## REST API Namespace

All endpoints are under: `/wp-json/maiexpowp/v1/`

## Authentication

Uses custom Bearer token authentication (not JWT). Tokens are stored in user meta with selector/validator pattern.

**Important:** The `determine_current_user` filter in `Auth::init()` sets up WordPress user context from Bearer tokens. This makes `get_current_user_id()` work correctly for all REST requests. The `permission_callback` simply checks `get_current_user_id() > 0` — it does NOT re-verify the token.

## Key Endpoints

### POST /login
Returns token + user data.

### POST /register
Creates user, sets meta/terms, returns token.

### POST /social-login/apple
Verifies Apple identity token, finds or creates user, returns token.

### GET /user/profile
Returns user profile with optional meta fields.

**Query Parameters:**
- `meta_keys` - Array of meta keys to include. Accepts both formats:
  - `?meta_keys[]=key1&meta_keys[]=key2` (array notation)
  - `?meta_keys=key1,key2` (comma-separated)

### POST /user/meta
Update user meta. Only keys in `maiexpowp_allowed_user_meta_keys` filter are accepted.

**Body:** `{ "meta": { "key": "value" } }`

### GET /user/meta
Read user meta. Only keys in `maiexpowp_allowed_user_meta_read_keys` filter are returned (defaults to the write allowlist).

**Query Parameters:** `?keys[]=key1&keys[]=key2`

### POST /user/terms & GET /user/terms
Set/get user taxonomy terms. Only taxonomies in `maiexpowp_allowed_user_taxonomies` filter are accepted for both reading and writing.

### POST /user/password-reset-request
Public endpoint. Sends password reset email. Always returns success (prevents email enumeration).

**Body:** `{ "email": "user@example.com" }`

### POST /user/password-reset
Public endpoint. Validates reset key, sets new password, invalidates all API tokens.

**Body:** `{ "email": "user@example.com", "key": "reset_key", "password": "new_password" }`

### POST /user/delete-account
Authenticated endpoint. Soft-deletes app connection (invalidates all API tokens). Does NOT delete the WordPress account. Requires `confirm: true`.

**Body:** `{ "confirm": true }`

### POST /auto-login-token
Generates a one-time, short-lived token for auto-logging into the website from the app.

### WordPress Core Alternative
User meta can also be updated via WordPress core:
`POST /wp/v2/users/{id}` with `{ "meta": { "key": "value" } }`

Requires `register_meta()` with `show_in_rest => true` for each meta key.

## Filters

### maiexpowp_allowed_user_meta_keys
Allowlist of meta keys that can be written via the API.

```php
add_filter('maiexpowp_allowed_user_meta_keys', function($keys) {
    return array_merge($keys, ['qc_persona', 'custom_field']);
});
```

### maiexpowp_allowed_user_meta_read_keys
Allowlist of meta keys that can be read via `GET /user/meta`. Defaults to the write allowlist. Use to expose read-only keys (e.g., keys set by webhooks).

```php
add_filter('maiexpowp_allowed_user_meta_read_keys', function($keys) {
    return array_merge($keys, ['qc_access_status', 'qc_access_expires']);
});
```

### maiexpowp_allowed_user_taxonomies
Allowlist of taxonomies for reading and writing user terms. Default: `['user-group']`

### maiexpowp_user_profile_data
Extend the user profile response with app-specific data.

```php
add_filter('maiexpowp_user_profile_data', function($data, $user_id) {
    $data['access'] = [
        'status' => get_user_meta($user_id, 'qc_access_status', true),
        'can_access' => my_app_check_access($user_id),
    ];
    return $data;
}, 10, 2);
```

### maiexpowp_user_membership_data
Add custom flags to membership data based on plan IDs.

```php
add_filter('maiexpowp_user_membership_data', function($data, $user_id, $plan_ids) {
    $data['is_premium'] = in_array(123, $plan_ids);
    return $data;
}, 10, 3);
```

### maiexpowp_password_reset_url
Customize the password reset URL in the email (e.g., for app deep links).

```php
add_filter('maiexpowp_password_reset_url', function($url, $user, $key) {
    return 'myapp://reset-password?key=' . $key . '&login=' . rawurlencode($user->user_login);
}, 10, 3);
```

### maiexpowp_password_reset_message
Customize the password reset email message.

### maiexpowp_before_delete_account (action)
Fires before soft account deletion. Use to clean up app-specific data.

```php
add_action('maiexpowp_before_delete_account', function($user_id) {
    wp_remove_object_terms($user_id, 'my-app', 'user-group');
    delete_user_meta($user_id, 'my_app_persona');
});
```

## Common Issues

### "Not allowed to edit this user" (401)
The `determine_current_user` filter must be registered to set up user context from Bearer token. Check that `Auth::init()` is called in plugin initialization.

### Meta not returned in profile
1. Check `meta_keys` parameter is being sent correctly
2. Verify `sanitize_string_array` handles both string and array formats
3. Ensure meta key is in `maiexpowp_allowed_user_meta_keys` filter

### GET /user/meta returns "no allowed keys"
The requested keys must be in the `maiexpowp_allowed_user_meta_read_keys` filter (defaults to the write allowlist).

### Token format
`{user_id}.{selector}.{validator}` - The user_id prefix allows direct DB lookup without scanning all users.

## File Structure

- `class-auth.php` - Token generation, verification, `determine_current_user` filter, permission callback
- `class-social-auth.php` - Apple Sign In token verification and user management
- `class-rest-api.php` - All REST endpoint handlers
- `class-plugin.php` - Activation, meta registration
- `class-membership-manager.php` - Membership provider abstraction
- `class-membership-provider.php` - Base membership provider interface
- `membership-providers/` - Concrete membership providers (WooCommerce, RCP)
- `class-logger.php` - Logging utility
