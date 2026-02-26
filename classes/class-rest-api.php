<?php
/**
 * MaiExpoWP REST API class.
 *
 * Registers and handles REST API endpoints.
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
 * REST_API class.
 *
 * @since 0.1.0
 */
class REST_API {

	/**
	 * REST API namespace.
	 *
	 * @since 0.1.0
	 */
	const NAMESPACE = 'maiexpowp/v1';

	/**
	 * Instance.
	 *
	 * @since 0.1.0
	 *
	 * @var REST_API|null
	 */
	private static ?REST_API $instance = null;

	/**
	 * Get instance.
	 *
	 * @since 0.1.0
	 *
	 * @return REST_API
	 */
	public static function get_instance(): REST_API {
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
	private function __construct() {
		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 0.1.0
	 *
	 * @return void
	 */
	private function hooks(): void {
		add_action( 'rest_api_init', [ $this, 'register_routes' ] );
	}

	/**
	 * Register REST routes.
	 *
	 * @since 0.1.0
	 *
	 * @return void
	 */
	public function register_routes(): void {
		// POST /register - User registration.
		register_rest_route(
			self::NAMESPACE,
			'/register',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_register' ],
				'permission_callback' => '__return_true',
				'args'                => $this->get_register_args(),
			]
		);

		// POST /login - User login.
		register_rest_route(
			self::NAMESPACE,
			'/login',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_login' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'username' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'password' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'device_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'default'           => '',
					],
				],
			]
		);

		// POST /logout - Logout current device.
		register_rest_route(
			self::NAMESPACE,
			'/logout',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_logout' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
			]
		);

		// POST /logout-all - Logout all devices.
		register_rest_route(
			self::NAMESPACE,
			'/logout-all',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_logout_all' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
			]
		);

		// GET /user/sessions - Get active sessions.
		register_rest_route(
			self::NAMESPACE,
			'/user/sessions',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_sessions' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
			]
		);

		// GET /user/profile - Get user profile.
		register_rest_route(
			self::NAMESPACE,
			'/user/profile',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_profile' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'meta_keys' => [
						'required'          => false,
						'type'              => 'array',
						'items'             => [ 'type' => 'string' ],
						'sanitize_callback' => [ $this, 'sanitize_string_array' ],
					],
					'avatar_size' => [
						'required'          => false,
						'type'              => 'integer',
						'sanitize_callback' => 'absint',
					],
				],
			]
		);

		// POST /user/meta - Update user meta.
		register_rest_route(
			self::NAMESPACE,
			'/user/meta',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_update_meta' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'meta' => [
						'required'          => true,
						'type'              => 'object',
						'additionalProperties' => true,
					],
				],
			]
		);

		// GET /user/meta - Get user meta.
		register_rest_route(
			self::NAMESPACE,
			'/user/meta',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_meta' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'keys' => [
						'required'          => true,
						'type'              => 'array',
						'items'             => [ 'type' => 'string' ],
						'sanitize_callback' => [ $this, 'sanitize_string_array' ],
					],
				],
			]
		);

		// POST /user/terms - Set user taxonomy terms.
		register_rest_route(
			self::NAMESPACE,
			'/user/terms',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_set_terms' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'taxonomy' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'terms'    => [
						'required'          => true,
						'type'              => 'array',
						'items'             => [ 'type' => 'string' ],
						'sanitize_callback' => [ $this, 'sanitize_string_array' ],
					],
					'append'   => [
						'required'          => false,
						'type'              => 'boolean',
						'default'           => false,
					],
				],
			]
		);

		// GET /user/terms - Get user taxonomy terms.
		register_rest_route(
			self::NAMESPACE,
			'/user/terms',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_terms' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'taxonomy' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
				],
			]
		);

		// GET /user/memberships - Get user memberships.
		register_rest_route(
			self::NAMESPACE,
			'/user/memberships',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_memberships' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
			]
		);

		// GET /resolve-url - Resolve URL to post ID.
		register_rest_route(
			self::NAMESPACE,
			'/resolve-url',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_resolve_url' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'url' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'esc_url_raw',
					],
				],
			]
		);

		// POST /social-login/apple - Apple Sign In.
		register_rest_route(
			self::NAMESPACE,
			'/social-login/apple',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_apple_login' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'identity_token' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => [ Auth::class, 'sanitize_token' ],
						'validate_callback' => [ Auth::class, 'validate_jwt_format' ],
					],
					'user_info' => [
						'required'             => false,
						'type'                 => 'object',
						'additionalProperties' => true,
					],
					'device_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'default'           => '',
					],
				],
			]
		);

		// POST /auto-login-token - Generate one-time auto-login token.
		register_rest_route(
			self::NAMESPACE,
			'/auto-login-token',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_generate_autologin_token' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'redirect_url' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'esc_url_raw',
					],
				],
			]
		);
	}

	/**
	 * Get registration endpoint arguments.
	 *
	 * @since 0.1.0
	 *
	 * @return array
	 */
	private function get_register_args(): array {
		return [
			'email'        => [
				'required'          => true,
				'type'              => 'string',
				'format'            => 'email',
				'sanitize_callback' => 'sanitize_email',
			],
			'password'     => [
				'required'          => true,
				'type'              => 'string',
				'minLength'         => 8,
				'sanitize_callback' => 'sanitize_text_field',
			],
			'display_name' => [
				'required'          => true,
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
			],
			'meta'         => [
				'required'             => false,
				'type'                 => 'object',
				'additionalProperties' => true,
			],
			'terms'        => [
				'required'             => false,
				'type'                 => 'object',
				'additionalProperties' => true,
			],
		];
	}

	/**
	 * Sanitize an array of strings.
	 *
	 * Accepts both array and comma-separated string formats:
	 * - ?param[]=a&param[]=b (array notation)
	 * - ?param=a,b (comma-separated string)
	 *
	 * @since 0.1.0
	 *
	 * @param mixed $value The value to sanitize.
	 *
	 * @return array
	 */
	public function sanitize_string_array( $value ): array {
		// Handle comma-separated string.
		if ( is_string( $value ) ) {
			$value = array_map( 'trim', explode( ',', $value ) );
			$value = array_filter( $value ); // Remove empty strings.
		}

		if ( ! is_array( $value ) ) {
			return [];
		}

		return array_map( 'sanitize_text_field', $value );
	}

	/**
	 * Handle user registration.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_register( \WP_REST_Request $request ) {
		$logger       = Logger::get_instance();
		$email        = $request->get_param( 'email' );
		$password     = $request->get_param( 'password' );
		$display_name = $request->get_param( 'display_name' );
		$meta         = $request->get_param( 'meta' ) ?: [];
		$terms        = $request->get_param( 'terms' ) ?: [];

		// Check if email already exists.
		if ( email_exists( $email ) ) {
			$logger->warning( sprintf( 'Registration attempt with existing email: %s', $email ) );

			return new \WP_Error(
				'maiexpowp_email_exists',
				__( 'An account with this email already exists.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Generate username from email.
		$username = Auth::generate_username_from_email( $email );

		// Create the user.
		$user_id = wp_create_user( $username, $password, $email );

		if ( is_wp_error( $user_id ) ) {
			$logger->error( sprintf( 'Registration failed for %s: %s', $email, $user_id->get_error_message() ) );

			return new \WP_Error(
				'maiexpowp_registration_failed',
				$user_id->get_error_message(),
				[ 'status' => 400 ]
			);
		}

		// Update display name.
		wp_update_user(
			[
				'ID'           => $user_id,
				'display_name' => $display_name,
				'first_name'   => $display_name,
			]
		);

		// Set user meta if provided.
		if ( ! empty( $meta ) && is_array( $meta ) ) {
			$allowed_meta = $this->get_allowed_meta_keys( $meta );

			foreach ( $allowed_meta as $key => $value ) {
				update_user_meta( $user_id, sanitize_key( $key ), sanitize_text_field( $value ) );
			}
		}

		// Set taxonomy terms if provided.
		if ( ! empty( $terms ) && is_array( $terms ) ) {
			$allowed_taxonomies = $this->get_allowed_taxonomies();

			foreach ( $terms as $taxonomy => $term_values ) {
				$taxonomy = sanitize_key( $taxonomy );

				if ( ! in_array( $taxonomy, $allowed_taxonomies, true ) ) {
					continue;
				}

				if ( ! taxonomy_exists( $taxonomy ) ) {
					continue;
				}

				$term_values = is_array( $term_values ) ? $term_values : [ $term_values ];
				$term_values = array_map( 'sanitize_text_field', $term_values );

				wp_set_object_terms( $user_id, $term_values, $taxonomy );
			}
		}

		// Generate auth token.
		$token = Auth::generate_token( $user_id );

		// Get user data.
		$user_data = Auth::get_user_data( $user_id );

		return new \WP_REST_Response(
			array_merge(
				[ 'success' => true, 'token' => $token ],
				$user_data
			),
			201
		);
	}

	/**
	 * Handle user login.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_login( \WP_REST_Request $request ) {
		$logger      = Logger::get_instance();
		$username    = $request->get_param( 'username' );
		$password    = $request->get_param( 'password' );
		$device_name = $request->get_param( 'device_name' );

		// Authenticate user.
		$user = wp_authenticate( $username, $password );

		if ( is_wp_error( $user ) ) {
			$logger->warning( sprintf( 'Failed login attempt for: %s', $username ) );

			return new \WP_Error(
				'maiexpowp_invalid_credentials',
				__( 'Invalid username or password.', 'maiexpowp' ),
				[ 'status' => 401 ]
			);
		}

		// Generate auth token with device name.
		$token = Auth::generate_token( $user->ID, $device_name );

		// Get user data.
		$user_data = Auth::get_user_data( $user->ID );

		return new \WP_REST_Response(
			array_merge(
				[ 'success' => true, 'token' => $token ],
				$user_data
			),
			200
		);
	}

	/**
	 * Handle Apple Sign In login.
	 *
	 * Verifies the Apple identity token, finds or creates a user,
	 * generates an auth token, and returns the standard auth response.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_apple_login( \WP_REST_Request $request ) {
		$logger         = Logger::get_instance();
		$identity_token = $request->get_param( 'identity_token' );
		$user_info      = $request->get_param( 'user_info' ) ?: [];
		$device_name    = $request->get_param( 'device_name' );
		$social_auth    = Social_Auth::get_instance();

		// Verify the Apple identity token.
		$apple_payload = $social_auth->verify_apple_identity_token( $identity_token );

		if ( is_wp_error( $apple_payload ) ) {
			return $apple_payload;
		}

		// Find or create user.
		$result = $social_auth->find_or_create_user( $apple_payload, $user_info );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$user_id = $result['user_id'];
		$is_new  = $result['is_new'];

		// Generate auth token.
		$token = Auth::generate_token( $user_id, $device_name );

		// Get user data.
		$user_data = Auth::get_user_data( $user_id );

		$status_code = $is_new ? 201 : 200;

		return new \WP_REST_Response(
			array_merge(
				[ 'success' => true, 'token' => $token, 'is_new_user' => $is_new ],
				$user_data
			),
			$status_code
		);
	}

	/**
	 * Handle logout.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_logout( \WP_REST_Request $request ) {
		$user_id = Auth::get_user_id_from_request( $request );
		$token   = Auth::get_token_from_request( $request );

		// Invalidate only the current token (single device logout).
		Auth::invalidate_token( $user_id, $token );

		return new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'Logged out successfully.', 'maiexpowp' ),
			],
			200
		);
	}

	/**
	 * Handle logout all devices.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_logout_all( \WP_REST_Request $request ) {
		$user_id = Auth::get_user_id_from_request( $request );

		// Invalidate all tokens for this user.
		Auth::invalidate_all_tokens( $user_id );

		return new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'Logged out from all devices.', 'maiexpowp' ),
			],
			200
		);
	}

	/**
	 * Handle get active sessions.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_get_sessions( \WP_REST_Request $request ) {
		$user_id  = Auth::get_user_id_from_request( $request );
		$sessions = Auth::get_sessions( $user_id );

		return new \WP_REST_Response(
			[
				'user_id'  => $user_id,
				'sessions' => $sessions,
			],
			200
		);
	}

	/**
	 * Handle get user profile.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_get_profile( \WP_REST_Request $request ) {
		$logger      = Logger::get_instance();
		$user_id     = Auth::get_user_id_from_request( $request );
		$meta_keys   = $request->get_param( 'meta_keys' ) ?: [];
		$avatar_size = $request->get_param( 'avatar_size' );
		$user        = get_userdata( $user_id );

		if ( ! $user ) {
			$logger->warning( sprintf( 'Profile request for non-existent user ID: %d', $user_id ) );

			return new \WP_Error(
				'maiexpowp_user_not_found',
				__( 'User not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		// Build args for user data.
		$args = [ 'meta_keys' => $meta_keys ];
		if ( $avatar_size ) {
			$args['avatar_size'] = $avatar_size;
		}

		// Get user data with requested meta.
		$user_data = Auth::get_user_data( $user_id, $args );

		// Get memberships.
		$membership_data = Membership_Manager::get_instance()->get_user_memberships( $user_id );

		// Get all user taxonomies.
		$user_terms      = [];
		$user_taxonomies = $this->get_allowed_taxonomies();

		foreach ( $user_taxonomies as $taxonomy ) {
			if ( ! taxonomy_exists( $taxonomy ) ) {
				continue;
			}

			$terms = wp_get_object_terms( $user_id, $taxonomy, [ 'fields' => 'slugs' ] );

			if ( ! is_wp_error( $terms ) ) {
				$user_terms[ $taxonomy ] = $terms;
			}
		}

		$response_data = array_merge(
			$user_data,
			$membership_data,
			[
				'terms' => $user_terms,
			]
		);

		/**
		 * Filter the user profile response data.
		 *
		 * Allows apps to add custom data to the profile response.
		 *
		 * @since 0.1.0
		 *
		 * @param array $response_data The profile response data.
		 * @param int   $user_id       The user ID.
		 */
		$response_data = apply_filters( 'maiexpowp_user_profile_data', $response_data, $user_id );

		return new \WP_REST_Response( $response_data, 200 );
	}

	/**
	 * Handle update user meta.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_update_meta( \WP_REST_Request $request ) {
		$logger  = Logger::get_instance();
		$user_id = Auth::get_user_id_from_request( $request );
		$meta    = $request->get_param( 'meta' );

		if ( ! is_array( $meta ) || empty( $meta ) ) {
			$logger->warning( sprintf( 'Invalid meta update request from user ID: %d', $user_id ) );

			return new \WP_Error(
				'maiexpowp_invalid_meta',
				__( 'Meta must be a non-empty object.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		$allowed_meta = $this->get_allowed_meta_keys( $meta );

		if ( empty( $allowed_meta ) ) {
			$logger->warning( sprintf( 'No allowed meta keys in update request from user ID: %d. Requested keys: %s', $user_id, implode( ', ', array_keys( $meta ) ) ) );

			return new \WP_Error(
				'maiexpowp_no_allowed_keys',
				__( 'None of the provided meta keys are allowed.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		$updated = [];

		foreach ( $allowed_meta as $key => $value ) {
			$sanitized_key   = sanitize_key( $key );
			$sanitized_value = sanitize_text_field( $value );

			update_user_meta( $user_id, $sanitized_key, $sanitized_value );
			$updated[ $sanitized_key ] = $sanitized_value;
		}

		return new \WP_REST_Response(
			[
				'success' => true,
				'updated' => $updated,
			],
			200
		);
	}

	/**
	 * Handle get user meta.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_get_meta( \WP_REST_Request $request ) {
		$user_id = Auth::get_user_id_from_request( $request );
		$keys    = $request->get_param( 'keys' );

		$meta = [];

		foreach ( $keys as $key ) {
			$sanitized_key      = sanitize_key( $key );
			$meta[ $sanitized_key ] = get_user_meta( $user_id, $sanitized_key, true ) ?: null;
		}

		return new \WP_REST_Response(
			[
				'user_id' => $user_id,
				'meta'    => $meta,
			],
			200
		);
	}

	/**
	 * Handle set user taxonomy terms.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_set_terms( \WP_REST_Request $request ) {
		$logger   = Logger::get_instance();
		$user_id  = Auth::get_user_id_from_request( $request );
		$taxonomy = $request->get_param( 'taxonomy' );
		$terms    = $request->get_param( 'terms' );
		$append   = $request->get_param( 'append' );

		// Check if taxonomy is allowed.
		$allowed_taxonomies = $this->get_allowed_taxonomies();

		if ( ! in_array( $taxonomy, $allowed_taxonomies, true ) ) {
			$logger->warning( sprintf( 'Attempt to set terms on disallowed taxonomy "%s" by user ID: %d', $taxonomy, $user_id ) );

			return new \WP_Error(
				'maiexpowp_taxonomy_not_allowed',
				__( 'This taxonomy is not allowed.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Check if taxonomy exists.
		if ( ! taxonomy_exists( $taxonomy ) ) {
			$logger->warning( sprintf( 'Attempt to set terms on non-existent taxonomy "%s" by user ID: %d', $taxonomy, $user_id ) );

			return new \WP_Error(
				'maiexpowp_taxonomy_not_found',
				__( 'Taxonomy not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		// Set terms.
		$result = wp_set_object_terms( $user_id, $terms, $taxonomy, $append );

		if ( is_wp_error( $result ) ) {
			$logger->error( sprintf( 'Failed to set terms for user ID %d on taxonomy "%s": %s', $user_id, $taxonomy, $result->get_error_message() ) );

			return new \WP_Error(
				'maiexpowp_terms_failed',
				$result->get_error_message(),
				[ 'status' => 400 ]
			);
		}

		// Get updated terms.
		$updated_terms = wp_get_object_terms( $user_id, $taxonomy, [ 'fields' => 'slugs' ] );

		return new \WP_REST_Response(
			[
				'success'  => true,
				'taxonomy' => $taxonomy,
				'terms'    => is_wp_error( $updated_terms ) ? [] : $updated_terms,
			],
			200
		);
	}

	/**
	 * Handle get user taxonomy terms.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_get_terms( \WP_REST_Request $request ) {
		$user_id  = Auth::get_user_id_from_request( $request );
		$taxonomy = $request->get_param( 'taxonomy' );

		// Check if taxonomy exists.
		if ( ! taxonomy_exists( $taxonomy ) ) {
			return new \WP_Error(
				'maiexpowp_taxonomy_not_found',
				__( 'Taxonomy not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		$terms = wp_get_object_terms( $user_id, $taxonomy, [ 'fields' => 'all' ] );

		if ( is_wp_error( $terms ) ) {
			return new \WP_Error(
				'maiexpowp_terms_failed',
				$terms->get_error_message(),
				[ 'status' => 400 ]
			);
		}

		$term_data = array_map(
			function( $term ) {
				return [
					'term_id' => $term->term_id,
					'name'    => $term->name,
					'slug'    => $term->slug,
				];
			},
			$terms
		);

		return new \WP_REST_Response(
			[
				'user_id'  => $user_id,
				'taxonomy' => $taxonomy,
				'terms'    => $term_data,
			],
			200
		);
	}

	/**
	 * Handle get user memberships.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_get_memberships( \WP_REST_Request $request ) {
		$user_id = Auth::get_user_id_from_request( $request );

		$membership_data = Membership_Manager::get_instance()->get_user_memberships( $user_id );

		return new \WP_REST_Response(
			array_merge(
				[ 'user_id' => $user_id ],
				$membership_data
			),
			200
		);
	}

	/**
	 * Handle resolve URL to post ID.
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_resolve_url( \WP_REST_Request $request ) {
		$url     = $request->get_param( 'url' );
		$post_id = $url ? url_to_postid( $url ) : 0;

		if ( ! $post_id ) {
			return new \WP_Error(
				'maiexpowp_not_found',
				__( 'Post not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		return new \WP_REST_Response(
			[
				'id'   => $post_id,
				'type' => get_post_type( $post_id ),
			],
			200
		);
	}

	/**
	 * Handle generate auto-login token.
	 *
	 * Creates a one-time, short-lived token that can be used to automatically
	 * log a user into the website when they click a link from the mobile app.
	 *
	 * Security measures:
	 * - Token is 32 random characters (impossible to guess)
	 * - Token expires in 5 minutes
	 * - Token is single-use (deleted after use)
	 * - Requires authenticated user to generate
	 *
	 * @since 0.1.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_generate_autologin_token( \WP_REST_Request $request ) {
		$user_id      = Auth::get_user_id_from_request( $request );
		$redirect_url = $request->get_param( 'redirect_url' );

		// Generate a cryptographically secure random token.
		$token = wp_generate_password( 32, false, false );

		// Store token data as a transient (expires in 5 minutes).
		set_transient(
			'maiexpowp_autologin_' . $token,
			[
				'user_id'      => $user_id,
				'redirect_url' => $redirect_url,
				'created'      => time(),
			],
			5 * MINUTE_IN_SECONDS
		);

		// Build the auto-login URL.
		$autologin_url = add_query_arg( 'maiexpowp_autologin', $token, $redirect_url );

		return new \WP_REST_Response(
			[
				'success' => true,
				'url'     => $autologin_url,
			],
			200
		);
	}

	/**
	 * Get allowed meta keys.
	 *
	 * Filters the provided meta array to only include allowed keys.
	 *
	 * @since 0.1.0
	 *
	 * @param array $meta The meta array to filter.
	 *
	 * @return array Filtered meta array with only allowed keys.
	 */
	private function get_allowed_meta_keys( array $meta ): array {
		/**
		 * Filter the allowed user meta keys.
		 *
		 * @since 0.1.0
		 *
		 * @param array $allowed_keys Array of allowed meta key names.
		 */
		$allowed_keys = apply_filters( 'maiexpowp_allowed_user_meta_keys', [] );

		if ( empty( $allowed_keys ) ) {
			return [];
		}

		return array_intersect_key( $meta, array_flip( $allowed_keys ) );
	}

	/**
	 * Get allowed user taxonomies.
	 *
	 * @since 0.1.0
	 *
	 * @return array Array of allowed taxonomy names.
	 */
	private function get_allowed_taxonomies(): array {
		/**
		 * Filter the allowed user taxonomies.
		 *
		 * @since 0.1.0
		 *
		 * @param array $taxonomies Array of allowed taxonomy names.
		 */
		return apply_filters( 'maiexpowp_allowed_user_taxonomies', [ 'user-group' ] );
	}
}
