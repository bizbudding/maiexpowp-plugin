<?php
/**
 * MaiExpoWP Auth class.
 *
 * Handles authentication token generation and verification.
 * Uses selector/validator pattern for secure token storage.
 *
 * Token format: {user_id}.{selector}.{validator}
 * - user_id: For direct database lookup (not secret)
 * - selector: Identifies which token (stored plain)
 * - validator: The secret (only SHA-256 hash is stored)
 *
 * @since 0.1.0
 *
 * @package MaiExpoWP
 */

namespace MaiExpoWP;

use MaiExpoWP\Logger;

// Exit if accessed directly.
defined( 'ABSPATH' ) || exit;

/**
 * Auth class.
 *
 * @since 0.1.0
 */
class Auth {

	/**
	 * Meta key for storing auth tokens.
	 *
	 * @since 0.1.0
	 */
	const TOKEN_META_KEY = 'maiexpowp_auth_tokens';

	/**
	 * Initialize auth hooks.
	 *
	 * @since 0.1.0
	 *
	 * @return void
	 */
	public static function init(): void {
		add_filter( 'determine_current_user', [ __CLASS__, 'authenticate_token' ], 20 );
	}

	/**
	 * Authenticate user from Bearer token for REST API requests.
	 *
	 * This filter runs early and sets up the WordPress user context,
	 * making get_current_user_id() work correctly for authenticated requests.
	 *
	 * @since 0.1.0
	 *
	 * @param int|false $user_id Current user ID or false.
	 *
	 * @return int|false User ID if token valid, original value otherwise.
	 */
	public static function authenticate_token( $user_id ) {
		// Don't override if already authenticated.
		if ( $user_id ) {
			return $user_id;
		}

		// Only process REST API requests.
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST ) {
			return $user_id;
		}

		// Get Authorization header.
		$auth_header = isset( $_SERVER['HTTP_AUTHORIZATION'] )
			? $_SERVER['HTTP_AUTHORIZATION']
			: ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : '' );

		if ( ! $auth_header || ! preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			return $user_id;
		}

		$token            = $matches[1];
		$verified_user_id = self::verify_token( $token );

		if ( $verified_user_id ) {
			wp_set_current_user( $verified_user_id );
			return $verified_user_id;
		}

		return $user_id;
	}

	/**
	 * Token expiry duration in days.
	 *
	 * @since 0.1.0
	 */
	const TOKEN_EXPIRY_DAYS = 30;

	/**
	 * Validate an auth token format string.
	 *
	 * Format: {user_id}.{selector}.{validator}
	 * - user_id: numeric
	 * - selector: 16 hex chars
	 * - validator: 64 hex chars
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $value The value to validate.
	 *
	 * @return bool True if valid auth token format.
	 */
	public static function validate_token_format( $value ): bool {
		return is_string( $value ) && (bool) preg_match( '/^\d+\.[a-f0-9]{16}\.[a-f0-9]{64}$/', $value );
	}

	/**
	 * Validate a JWT format string.
	 *
	 * Three base64url-encoded segments separated by dots.
	 * Used for Apple Sign In identity tokens and any other JWT verification.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $value The value to validate.
	 *
	 * @return bool True if valid JWT format.
	 */
	public static function validate_jwt_format( $value ): bool {
		return is_string( $value ) && (bool) preg_match( '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $value );
	}

	/**
	 * Sanitize an auth token string.
	 *
	 * Trims whitespace. The token is only cryptographically verified,
	 * never stored or rendered, so no further transformation is needed.
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $value The value to sanitize.
	 *
	 * @return string Trimmed token.
	 */
	public static function sanitize_token( $value ): string {
		return is_string( $value ) ? trim( $value ) : '';
	}

	/**
	 * Generate a unique username from an email address.
	 *
	 * Takes the local part of the email, sanitizes it, and appends
	 * a numeric suffix if the username is already taken.
	 *
	 * @since 0.1.0
	 *
	 * @param string $email The email address.
	 *
	 * @return string A unique username.
	 */
	public static function generate_username_from_email( string $email ): string {
		$username = sanitize_user( current( explode( '@', $email ) ), true );
		$original = $username;
		$counter  = 1;

		while ( username_exists( $username ) ) {
			$username = $original . $counter;
			$counter++;
		}

		return $username;
	}

	/**
	 * Generate an auth token for a user.
	 *
	 * @since 0.1.0
	 *
	 * @param int    $user_id     The user ID.
	 * @param string $device_name Optional. Device identifier for session management.
	 *
	 * @return string The auth token (plain text, send to client once).
	 */
	public static function generate_token( int $user_id, string $device_name = '' ): string {
		// Generate selector (8 bytes = 16 hex chars) and validator (32 bytes = 64 hex chars).
		$selector  = bin2hex( random_bytes( 8 ) );
		$validator = bin2hex( random_bytes( 32 ) );

		// SHA-256 is appropriate for high-entropy random tokens.
		$validator_hash = hash( 'sha256', $validator );

		// Get existing tokens (supports multi-device).
		$tokens = get_user_meta( $user_id, self::TOKEN_META_KEY, true );

		if ( ! is_array( $tokens ) ) {
			$tokens = [];
		}

		// Prune expired tokens.
		$now    = time();
		$tokens = array_filter( $tokens, fn( $t ) => isset( $t['expires'] ) && $t['expires'] > $now );

		// Add new token.
		$tokens[ $selector ] = [
			'hash'    => $validator_hash,
			'created' => $now,
			'expires' => $now + ( self::TOKEN_EXPIRY_DAYS * DAY_IN_SECONDS ),
			'device'  => sanitize_text_field( $device_name ),
		];

		update_user_meta( $user_id, self::TOKEN_META_KEY, $tokens );

		// Return token: user_id.selector.validator
		return $user_id . '.' . $selector . '.' . $validator;
	}

	/**
	 * Verify a token and return the user ID.
	 *
	 * @since 0.1.0
	 *
	 * @param string $token The plain text token.
	 *
	 * @return int|false User ID if valid, false otherwise.
	 */
	public static function verify_token( string $token ) {
		$logger = Logger::get_instance();

		if ( ! self::validate_token_format( $token ) ) {
			$logger->warning( 'Token verification failed: invalid token format' );
			return false;
		}

		[ $user_id, $selector, $validator ] = explode( '.', $token, 3 );
		$user_id = absint( $user_id );

		if ( ! $user_id ) {
			$logger->warning( 'Token verification failed: invalid user ID in token' );
			return false;
		}

		// Direct lookup by user_id - no scanning.
		$tokens = get_user_meta( $user_id, self::TOKEN_META_KEY, true );

		if ( ! is_array( $tokens ) || ! isset( $tokens[ $selector ] ) ) {
			$logger->warning( sprintf( 'Token verification failed: selector not found for user ID %d', $user_id ) );
			return false;
		}

		$token_data = $tokens[ $selector ];

		// Check expiry.
		if ( ! isset( $token_data['expires'] ) || time() > $token_data['expires'] ) {
			$logger->warning( sprintf( 'Token verification failed: token expired for user ID %d', $user_id ) );
			unset( $tokens[ $selector ] );
			update_user_meta( $user_id, self::TOKEN_META_KEY, $tokens );
			return false;
		}

		// Constant-time comparison (critical for security).
		$validator_hash = hash( 'sha256', $validator );

		if ( ! hash_equals( $token_data['hash'], $validator_hash ) ) {
			$logger->warning( sprintf( 'Token verification failed: invalid validator for user ID %d', $user_id ) );
			return false;
		}

		return $user_id;
	}

	/**
	 * Invalidate a specific token (logout current device).
	 *
	 * @since 0.1.0
	 *
	 * @param int    $user_id The user ID.
	 * @param string $token   The token to invalidate.
	 *
	 * @return void
	 */
	public static function invalidate_token( int $user_id, string $token ): void {
		if ( ! self::validate_token_format( $token ) ) {
			return;
		}

		$selector = explode( '.', $token, 3 )[1];
		$tokens   = get_user_meta( $user_id, self::TOKEN_META_KEY, true );

		if ( is_array( $tokens ) && isset( $tokens[ $selector ] ) ) {
			unset( $tokens[ $selector ] );
			update_user_meta( $user_id, self::TOKEN_META_KEY, $tokens );
		}
	}

	/**
	 * Invalidate all tokens for a user (logout all devices).
	 *
	 * @since 0.1.0
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return void
	 */
	public static function invalidate_all_tokens( int $user_id ): void {
		delete_user_meta( $user_id, self::TOKEN_META_KEY );
	}

	/**
	 * Get active sessions for a user.
	 *
	 * @since 0.1.0
	 *
	 * @param int $user_id The user ID.
	 *
	 * @return array List of active sessions.
	 */
	public static function get_sessions( int $user_id ): array {
		$tokens = get_user_meta( $user_id, self::TOKEN_META_KEY, true );

		if ( ! is_array( $tokens ) ) {
			return [];
		}

		$now      = time();
		$sessions = [];

		foreach ( $tokens as $selector => $data ) {
			if ( isset( $data['expires'] ) && $data['expires'] > $now ) {
				$sessions[] = [
					'selector' => $selector,
					'device'   => $data['device'] ?? '',
					'created'  => $data['created'] ?? 0,
					'expires'  => $data['expires'],
				];
			}
		}

		return $sessions;
	}

	/**
	 * Extract token from Authorization header.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return string|false Token if found, false otherwise.
	 */
	public static function get_token_from_request( \WP_REST_Request $request ) {
		$auth_header = $request->get_header( 'Authorization' );

		if ( ! $auth_header ) {
			return false;
		}

		// Extract token from "Bearer <token>" format.
		if ( preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			return $matches[1];
		}

		return false;
	}

	/**
	 * Get user ID from request token.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return int|false User ID or false if invalid.
	 */
	public static function get_user_id_from_request( \WP_REST_Request $request ) {
		$token = self::get_token_from_request( $request );

		if ( ! $token ) {
			return false;
		}

		return self::verify_token( $token );
	}

	/**
	 * Permission callback for authenticated endpoints.
	 *
	 * Relies on the `determine_current_user` filter (authenticate_token)
	 * which already verified the token and called wp_set_current_user().
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return bool|\WP_Error True if valid, WP_Error otherwise.
	 */
	public static function permission_callback( \WP_REST_Request $request ) {
		if ( get_current_user_id() > 0 ) {
			return true;
		}

		$logger = Logger::get_instance();
		$logger->warning( sprintf( 'Permission denied: invalid token for route %s', $request->get_route() ) );

		return new \WP_Error(
			'maiexpowp_invalid_token',
			__( 'Invalid or expired token.', 'maiexpowp' ),
			[ 'status' => 401 ]
		);
	}

	/**
	 * Build user data array for API responses.
	 *
	 * @since 0.1.0
	 *
	 * @param int   $user_id The user ID.
	 * @param array $args {
	 *     Optional. Arguments for user data retrieval.
	 *
	 *     @type array $meta_keys   Array of meta keys to include in response.
	 *     @type int   $avatar_size Avatar size in pixels. Default 200.
	 * }
	 *
	 * @return array|null User data array or null if user not found.
	 */
	public static function get_user_data( int $user_id, array $args = [] ): ?array {
		$args = wp_parse_args( $args, [
			'meta_keys'   => [],
			'avatar_size' => 200,
		] );

		$user = get_userdata( $user_id );

		if ( ! $user ) {
			return null;
		}

		$data = [
			'user_id'         => $user_id,
			'email'           => $user->user_email,
			'username'        => $user->user_login,
			'display_name'    => $user->display_name,
			'avatar'          => get_avatar_url( $user_id, [ 'size' => $args['avatar_size'] ] ),
			'user_registered' => $user->user_registered,
		];

		// Add requested meta values.
		foreach ( $args['meta_keys'] as $key ) {
			$data[ $key ] = get_user_meta( $user_id, $key, true ) ?: null;
		}

		return $data;
	}
}
