<?php
/**
 * MaiExpoWP Social Auth class.
 *
 * Handles social login verification and user management.
 * Currently supports Apple Sign In with identity token verification.
 *
 * @since 0.1.0
 *
 * @package MaiExpoWP
 */

namespace MaiExpoWP;

// Exit if accessed directly.
defined( 'ABSPATH' ) || exit;

/**
 * Social_Auth class.
 *
 * @since 0.1.0
 */
class Social_Auth {

	/**
	 * User meta key for Apple user ID.
	 *
	 * @since 0.1.0
	 */
	const APPLE_USER_ID_META = 'maiexpowp_apple_user_id';

	/**
	 * Transient key for cached Apple public keys.
	 *
	 * @since 0.1.0
	 */
	const APPLE_KEYS_TRANSIENT = 'maiexpowp_apple_public_keys';

	/**
	 * Cache duration for Apple public keys (24 hours).
	 *
	 * @since 0.1.0
	 */
	const APPLE_KEYS_CACHE_SECONDS = DAY_IN_SECONDS;

	/**
	 * Instance.
	 *
	 * @since 0.1.0
	 *
	 * @var Social_Auth|null
	 */
	private static ?Social_Auth $instance = null;

	/**
	 * Get instance.
	 *
	 * @since 0.1.0
	 *
	 * @return Social_Auth
	 */
	public static function get_instance(): Social_Auth {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @since 0.1.0
	 */
	private function __construct() {}



	/**
	 * Verify an Apple identity token.
	 *
	 * Decodes the JWT, fetches Apple's public keys, verifies the signature,
	 * and validates the claims (issuer, audience, expiration).
	 *
	 * @since 0.1.0
	 *
	 * @param string $identity_token The Apple identity token (JWT).
	 *
	 * @return array|\WP_Error Decoded payload on success, WP_Error on failure.
	 */
	public function verify_apple_identity_token( string $identity_token ) {
		$logger = Logger::get_instance();

		// Validate JWT format (three base64url segments separated by dots).
		if ( ! Auth::validate_jwt_format( $identity_token ) ) {
			$logger->warning( 'Apple token verification failed: invalid JWT format' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Invalid identity token format.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		[ $header_b64, $payload_b64, $signature_b64 ] = explode( '.', $identity_token );

		// Decode the header.
		$header = json_decode( $this->base64url_decode( $header_b64 ), true );

		if ( ! $header || empty( $header['kid'] ) || empty( $header['alg'] ) ) {
			$logger->warning( 'Apple token verification failed: invalid JWT header' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Invalid identity token header.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Verify algorithm is RS256.
		if ( 'RS256' !== $header['alg'] ) {
			$logger->warning( sprintf( 'Apple token verification failed: unexpected algorithm %s', $header['alg'] ) );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Unsupported token algorithm.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Fetch Apple's public keys and find matching key by kid.
		$pem = $this->get_apple_public_key_pem( $header['kid'] );

		if ( is_wp_error( $pem ) ) {
			return $pem;
		}

		// Verify the signature.
		$data      = $header_b64 . '.' . $payload_b64;
		$signature = $this->base64url_decode( $signature_b64 );

		$verify_result = openssl_verify( $data, $signature, $pem, OPENSSL_ALGO_SHA256 );

		if ( 1 !== $verify_result ) {
			$logger->warning( 'Apple token verification failed: invalid signature' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Identity token signature verification failed.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		// Decode the payload.
		$payload = json_decode( $this->base64url_decode( $payload_b64 ), true );

		if ( ! $payload ) {
			$logger->warning( 'Apple token verification failed: invalid payload' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Invalid identity token payload.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Validate claims.
		$claims_error = $this->validate_apple_claims( $payload );

		if ( is_wp_error( $claims_error ) ) {
			return $claims_error;
		}

		return $payload;
	}

	/**
	 * Validate Apple JWT claims.
	 *
	 * @since 0.1.0
	 *
	 * @param array $payload The decoded JWT payload.
	 *
	 * @return true|\WP_Error True on success, WP_Error on failure.
	 */
	private function validate_apple_claims( array $payload ) {
		$logger = Logger::get_instance();

		// Validate issuer.
		if ( empty( $payload['iss'] ) || 'https://appleid.apple.com' !== $payload['iss'] ) {
			$logger->warning( 'Apple token verification failed: invalid issuer' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Invalid token issuer.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		// Validate audience against allowed client IDs.
		/**
		 * Filter the allowed Apple client IDs (bundle identifiers).
		 *
		 * Each app using this plugin should add its bundle ID via this filter.
		 *
		 * @since 0.1.0
		 *
		 * @param array $client_ids Array of allowed Apple client IDs.
		 */
		$allowed_client_ids = apply_filters( 'maiexpowp_apple_client_ids', [] );

		if ( empty( $allowed_client_ids ) ) {
			$logger->error( 'No Apple client IDs configured. Hook into "maiexpowp_apple_client_ids" filter to add your bundle ID.' );
		}

		if ( empty( $payload['aud'] ) || ! in_array( $payload['aud'], $allowed_client_ids, true ) ) {
			$logger->warning( sprintf(
				'Apple token verification failed: invalid audience %s (allowed: %s)',
				$payload['aud'] ?? 'none',
				implode( ', ', $allowed_client_ids )
			) );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Invalid token audience.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		// Validate expiration.
		if ( empty( $payload['exp'] ) || time() > $payload['exp'] ) {
			$logger->warning( 'Apple token verification failed: token expired' );

			return new \WP_Error(
				'maiexpowp_token_expired',
				__( 'Identity token has expired.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		// Validate subject (Apple user ID) is present.
		if ( empty( $payload['sub'] ) ) {
			$logger->warning( 'Apple token verification failed: missing subject' );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Identity token missing user identifier.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		return true;
	}

	/**
	 * Get the PEM-encoded public key for a given Apple key ID.
	 *
	 * Fetches from cache first, falls back to Apple's JWKS endpoint.
	 * If the key ID is not found, busts cache and retries once (key rotation).
	 *
	 * @since 0.1.0
	 *
	 * @param string $kid The key ID from the JWT header.
	 *
	 * @return string|\WP_Error PEM-encoded public key or WP_Error.
	 */
	private function get_apple_public_key_pem( string $kid ) {
		// Try cached keys first.
		$keys = $this->get_apple_public_keys( false );

		if ( is_wp_error( $keys ) ) {
			return $keys;
		}

		$jwk = $this->find_key_by_kid( $keys, $kid );

		// Key not found — bust cache and retry once (Apple may have rotated keys).
		if ( ! $jwk ) {
			$keys = $this->get_apple_public_keys( true );

			if ( is_wp_error( $keys ) ) {
				return $keys;
			}

			$jwk = $this->find_key_by_kid( $keys, $kid );
		}

		if ( ! $jwk ) {
			$logger = Logger::get_instance();
			$logger->warning( sprintf( 'Apple token verification failed: key ID %s not found', $kid ) );

			return new \WP_Error(
				'maiexpowp_invalid_token',
				__( 'Unable to find matching public key.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		return $this->jwk_to_pem( $jwk );
	}

	/**
	 * Find a key by key ID in the JWKS key set.
	 *
	 * @since 0.1.0
	 *
	 * @param array  $keys The JWKS keys array.
	 * @param string $kid  The key ID to find.
	 *
	 * @return array|null The matching JWK or null.
	 */
	private function find_key_by_kid( array $keys, string $kid ): ?array {
		foreach ( $keys as $key ) {
			if ( isset( $key['kid'] ) && $key['kid'] === $kid ) {
				return $key;
			}
		}

		return null;
	}

	/**
	 * Fetch Apple's public keys from their JWKS endpoint.
	 *
	 * @since 0.1.0
	 *
	 * @param bool $bust_cache Whether to bypass the transient cache.
	 *
	 * @return array|\WP_Error Array of JWK keys or WP_Error.
	 */
	private function get_apple_public_keys( bool $bust_cache = false ) {
		$logger = Logger::get_instance();

		if ( ! $bust_cache ) {
			$cached = get_transient( self::APPLE_KEYS_TRANSIENT );

			if ( false !== $cached && is_array( $cached ) ) {
				return $cached;
			}
		}

		$response = wp_remote_get( 'https://appleid.apple.com/auth/keys', [
			'timeout' => 10,
		] );

		if ( is_wp_error( $response ) ) {
			$logger->error( sprintf( 'Failed to fetch Apple public keys: %s', $response->get_error_message() ) );

			return new \WP_Error(
				'maiexpowp_apple_keys_fetch_failed',
				__( 'Unable to verify identity token. Please try again.', 'maiexpowp' ),
				[ 'status' => 502 ]
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['keys'] ) || ! is_array( $body['keys'] ) ) {
			$logger->error( 'Apple public keys response has unexpected format' );

			return new \WP_Error(
				'maiexpowp_apple_keys_invalid',
				__( 'Unable to verify identity token. Please try again.', 'maiexpowp' ),
				[ 'status' => 502 ]
			);
		}

		// Cache keys for 24 hours.
		set_transient( self::APPLE_KEYS_TRANSIENT, $body['keys'], self::APPLE_KEYS_CACHE_SECONDS );

		return $body['keys'];
	}

	/**
	 * Convert a JWK (JSON Web Key) to PEM format.
	 *
	 * Apple's keys are RSA public keys in JWK format. PHP's openssl_verify()
	 * requires PEM format, so we manually encode the key components.
	 *
	 * @since 0.1.0
	 *
	 * @param array $jwk The JWK key data with 'n' (modulus) and 'e' (exponent).
	 *
	 * @return string|\WP_Error PEM-encoded public key or WP_Error.
	 */
	private function jwk_to_pem( array $jwk ) {
		if ( empty( $jwk['n'] ) || empty( $jwk['e'] ) ) {
			return new \WP_Error(
				'maiexpowp_invalid_jwk',
				__( 'Invalid public key data.', 'maiexpowp' ),
				[ 'status' => 500 ]
			);
		}

		$modulus  = $this->base64url_decode( $jwk['n'] );
		$exponent = $this->base64url_decode( $jwk['e'] );

		// Encode as ASN.1 DER.
		$mod_integer = $this->asn1_integer( $modulus );
		$exp_integer = $this->asn1_integer( $exponent );

		// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
		$rsa_public_key = $this->asn1_sequence( $mod_integer . $exp_integer );

		// Wrap in BIT STRING.
		$bit_string = $this->asn1_bit_string( $rsa_public_key );

		// AlgorithmIdentifier for RSA: OID 1.2.840.113549.1.1.1 + NULL.
		$algorithm_identifier = $this->asn1_sequence(
			"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . // OID
			"\x05\x00" // NULL
		);

		// SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
		$subject_public_key_info = $this->asn1_sequence( $algorithm_identifier . $bit_string );

		// Encode to PEM.
		$pem = "-----BEGIN PUBLIC KEY-----\n"
			. chunk_split( base64_encode( $subject_public_key_info ), 64, "\n" )
			. "-----END PUBLIC KEY-----";

		return $pem;
	}

	/**
	 * Encode data as an ASN.1 SEQUENCE.
	 *
	 * @since 0.1.0
	 *
	 * @param string $data The data to wrap.
	 *
	 * @return string ASN.1 SEQUENCE.
	 */
	private function asn1_sequence( string $data ): string {
		return "\x30" . $this->asn1_length( strlen( $data ) ) . $data;
	}

	/**
	 * Encode data as an ASN.1 INTEGER.
	 *
	 * Prepends a 0x00 byte if the high bit is set (to indicate positive number).
	 *
	 * @since 0.1.0
	 *
	 * @param string $data The integer bytes.
	 *
	 * @return string ASN.1 INTEGER.
	 */
	private function asn1_integer( string $data ): string {
		// Prepend 0x00 if the high bit is set (positive integer in ASN.1).
		if ( ord( $data[0] ) & 0x80 ) {
			$data = "\x00" . $data;
		}

		return "\x02" . $this->asn1_length( strlen( $data ) ) . $data;
	}

	/**
	 * Encode data as an ASN.1 BIT STRING.
	 *
	 * @since 0.1.0
	 *
	 * @param string $data The data to wrap.
	 *
	 * @return string ASN.1 BIT STRING.
	 */
	private function asn1_bit_string( string $data ): string {
		// BIT STRING: 0x03 + length + 0x00 (no unused bits) + data.
		$content = "\x00" . $data;

		return "\x03" . $this->asn1_length( strlen( $content ) ) . $content;
	}

	/**
	 * Encode an ASN.1 length.
	 *
	 * Uses short form for lengths < 128, long form otherwise.
	 *
	 * @since 0.1.0
	 *
	 * @param int $length The length to encode.
	 *
	 * @return string Encoded length bytes.
	 */
	private function asn1_length( int $length ): string {
		if ( $length < 0x80 ) {
			return chr( $length );
		}

		$bytes = '';
		$temp  = $length;

		while ( $temp > 0 ) {
			$bytes = chr( $temp & 0xFF ) . $bytes;
			$temp >>= 8;
		}

		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}

	/**
	 * Decode a base64url-encoded string.
	 *
	 * @since 0.1.0
	 *
	 * @param string $data The base64url-encoded string.
	 *
	 * @return string Decoded data.
	 */
	private function base64url_decode( string $data ): string {
		$remainder = strlen( $data ) % 4;

		if ( $remainder ) {
			$data .= str_repeat( '=', 4 - $remainder );
		}

		return base64_decode( strtr( $data, '-_', '+/' ) );
	}

	/**
	 * Find or create a WordPress user from Apple Sign In payload.
	 *
	 * Lookup order:
	 * 1. By Apple user ID (stored in user meta) — returning user
	 * 2. By email — existing WordPress user, link Apple ID
	 * 3. Not found — create new user
	 *
	 * @since 0.1.0
	 *
	 * @param array $apple_payload The verified Apple JWT payload.
	 * @param array $user_info {
	 *     Optional. User info from Apple (only provided on first sign-in).
	 *
	 *     @type string $given_name  User's first name.
	 *     @type string $family_name User's last name.
	 * }
	 *
	 * @return array|\WP_Error {
	 *     @type int  $user_id The WordPress user ID.
	 *     @type bool $is_new  Whether the user was newly created.
	 * }
	 */
	public function find_or_create_user( array $apple_payload, array $user_info = [] ) {
		$logger       = Logger::get_instance();
		$apple_sub    = $apple_payload['sub'];
		$apple_email  = $apple_payload['email'] ?? '';

		// 1. Lookup by Apple user ID in user meta.
		$existing_users = get_users( [
			'meta_key'   => self::APPLE_USER_ID_META,
			'meta_value' => $apple_sub,
			'number'     => 1,
			'fields'     => 'ID',
		] );

		if ( ! empty( $existing_users ) ) {
			$user_id = (int) $existing_users[0];
			$logger->info( sprintf( 'Apple Sign In: returning user %d (Apple ID: %s)', $user_id, $apple_sub ) );

			return [
				'user_id' => $user_id,
				'is_new'  => false,
			];
		}

		// 2. Lookup by email.
		if ( $apple_email ) {
			$existing_user_id = email_exists( $apple_email );

			if ( $existing_user_id ) {
				// Link Apple ID to existing user.
				update_user_meta( $existing_user_id, self::APPLE_USER_ID_META, $apple_sub );

				$logger->info( sprintf( 'Apple Sign In: linked Apple ID to existing user %d (email: %s)', $existing_user_id, $apple_email ) );

				/**
				 * Fires when an Apple user ID is linked to an existing WordPress user.
				 *
				 * @since 0.1.0
				 *
				 * @param int    $user_id   The WordPress user ID.
				 * @param string $apple_sub The Apple user ID.
				 */
				do_action( 'maiexpowp_social_user_linked', $existing_user_id, $apple_sub );

				return [
					'user_id' => (int) $existing_user_id,
					'is_new'  => false,
				];
			}
		}

		// 3. Create new user.
		if ( ! $apple_email ) {
			$logger->warning( 'Apple Sign In: cannot create user without email' );

			return new \WP_Error(
				'maiexpowp_no_email',
				__( 'Email address is required to create an account.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Generate username from email.
		$username = Auth::generate_username_from_email( $apple_email );

		// Build display name from user_info if available.
		$given_name  = sanitize_text_field( $user_info['given_name'] ?? '' );
		$family_name = sanitize_text_field( $user_info['family_name'] ?? '' );
		$display_name = trim( $given_name . ' ' . $family_name );

		if ( ! $display_name ) {
			$display_name = $username;
		}

		// Create user with random password (they'll use Apple Sign In to authenticate).
		$user_id = wp_create_user( $username, wp_generate_password( 32, true, true ), $apple_email );

		if ( is_wp_error( $user_id ) ) {
			$logger->error( sprintf( 'Apple Sign In: failed to create user for %s: %s', $apple_email, $user_id->get_error_message() ) );

			return new \WP_Error(
				'maiexpowp_user_creation_failed',
				$user_id->get_error_message(),
				[ 'status' => 500 ]
			);
		}

		// Set display name and name fields.
		wp_update_user( [
			'ID'           => $user_id,
			'display_name' => $display_name,
			'first_name'   => $given_name,
			'last_name'    => $family_name,
		] );

		// Store Apple user ID.
		update_user_meta( $user_id, self::APPLE_USER_ID_META, $apple_sub );

		$logger->info( sprintf( 'Apple Sign In: created new user %d (email: %s, Apple ID: %s)', $user_id, $apple_email, $apple_sub ) );

		/**
		 * Fires when a new user is created via Apple Sign In.
		 *
		 * @since 0.1.0
		 *
		 * @param int    $user_id   The WordPress user ID.
		 * @param string $apple_sub The Apple user ID.
		 */
		do_action( 'maiexpowp_social_user_created', $user_id, $apple_sub );

		return [
			'user_id' => $user_id,
			'is_new'  => true,
		];
	}
}
