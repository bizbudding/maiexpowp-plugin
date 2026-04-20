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
						'required' => true,
						'type'     => 'string',
					],
					'device_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
						'default'           => '',
					],
					'terms' => [
						'required'             => false,
						'type'                 => 'object',
						'additionalProperties' => true,
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

		// GET /user - Get current user profile.
		register_rest_route(
			self::NAMESPACE,
			'/user',
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle_get_user' ],
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

		// POST /user - Update current user profile.
		register_rest_route(
			self::NAMESPACE,
			'/user',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_update_user' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'display_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'first_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'last_name' => [
						'required'          => false,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'meta' => [
						'required'             => false,
						'type'                 => 'object',
						'additionalProperties' => true,
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
					'terms' => [
						'required'             => false,
						'type'                 => 'object',
						'additionalProperties' => true,
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

		// POST /user/password-reset-request - Request password reset email.
		register_rest_route(
			self::NAMESPACE,
			'/user/password-reset-request',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_password_reset_request' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'email' => [
						'required'          => true,
						'type'              => 'string',
						'format'            => 'email',
						'sanitize_callback' => 'sanitize_email',
					],
				],
			]
		);

		// POST /user/password-reset - Reset password with 6-digit code.
		register_rest_route(
			self::NAMESPACE,
			'/user/password-reset',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_password_reset' ],
				'permission_callback' => '__return_true',
				'args'                => [
					'email' => [
						'required'          => true,
						'type'              => 'string',
						'format'            => 'email',
						'sanitize_callback' => 'sanitize_email',
					],
					'code' => [
						'required'          => true,
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					],
					'password' => [
						'required' => true,
						'type'     => 'string',
					],
				],
			]
		);

		// POST /user/change-password - Change password for authenticated user.
		register_rest_route(
			self::NAMESPACE,
			'/user/change-password',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_change_password' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'current_password' => [
						'required' => true,
						'type'     => 'string',
					],
					'new_password' => [
						'required' => true,
						'type'     => 'string',
					],
				],
			]
		);

		// POST /user/delete-account - Account deletion (App Store requirement).
		// Defaults to soft delete (tokens invalidated, WP user preserved).
		// Pass `hard` => true to also call wp_delete_user() and remove the WP account entirely.
		register_rest_route(
			self::NAMESPACE,
			'/user/delete-account',
			[
				'methods'             => 'POST',
				'callback'            => [ $this, 'handle_delete_account' ],
				'permission_callback' => [ Auth::class, 'permission_callback' ],
				'args'                => [
					'confirm' => [
						'required' => true,
						'type'     => 'boolean',
					],
					'hard'    => [
						'required' => false,
						'type'     => 'boolean',
						'default'  => false,
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
				'required'  => true,
				'type'      => 'string',
				'minLength' => 8,
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
			$this->process_user_terms( $user_id, $terms );
		}

		return $this->auth_response( $user_id, '', 201 );
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
		$terms       = $request->get_param( 'terms' ) ?: [];

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

		// Set taxonomy terms if provided.
		if ( ! empty( $terms ) && is_array( $terms ) ) {
			$this->process_user_terms( $user->ID, $terms );
		}

		return $this->auth_response( $user->ID, $device_name );
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
		$terms          = $request->get_param( 'terms' ) ?: [];
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

		// Set taxonomy terms if provided.
		if ( ! empty( $terms ) && is_array( $terms ) ) {
			$this->process_user_terms( $user_id, $terms );
		}

		return $this->auth_response( $user_id, $device_name, $is_new ? 201 : 200, [ 'is_new_user' => $is_new ] );
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
		$user_id = get_current_user_id();
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
		$user_id = get_current_user_id();

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
		$user_id  = get_current_user_id();
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
	public function handle_get_user( \WP_REST_Request $request ) {
		$logger      = Logger::get_instance();
		$user_id     = get_current_user_id();
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
	 * Handle update current user profile.
	 *
	 * Updates core user fields (display_name, first_name, last_name) and/or
	 * meta fields via the existing allowlist, then returns the full profile.
	 *
	 * @since 2.0.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_update_user( \WP_REST_Request $request ) {
		$user_id = get_current_user_id();

		// Update core user fields if provided.
		$core_fields = [];
		foreach ( [ 'display_name', 'first_name', 'last_name' ] as $field ) {
			$value = $request->get_param( $field );
			if ( null !== $value ) {
				$core_fields[ $field ] = $value;
			}
		}

		if ( ! empty( $core_fields ) ) {
			$core_fields['ID'] = $user_id;
			$result = wp_update_user( $core_fields );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		// Update meta if provided (reuse existing allowlist logic).
		$meta = $request->get_param( 'meta' );
		if ( ! empty( $meta ) && is_array( $meta ) ) {
			$allowed_meta = $this->get_allowed_meta_keys( $meta );

			if ( empty( $allowed_meta ) && ! empty( $meta ) ) {
				return new \WP_Error(
					'maiexpowp_no_allowed_keys',
					__( 'None of the provided meta keys are allowed.', 'maiexpowp' ),
					[ 'status' => 400 ]
				);
			}

			foreach ( $allowed_meta as $key => $value ) {
				update_user_meta( $user_id, sanitize_key( $key ), sanitize_text_field( $value ) );
			}
		}

		// Return the full updated profile (reuse GET handler logic).
		return $this->handle_get_user( $request );
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
		$user_id  = get_current_user_id();
		$taxonomy = $request->get_param( 'taxonomy' );
		$terms    = $request->get_param( 'terms' );
		$append   = $request->get_param( 'append' );

		// Validate taxonomy is allowed and exists.
		$valid = $this->validate_taxonomy( $taxonomy, $user_id );

		if ( is_wp_error( $valid ) ) {
			return $valid;
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
		$user_id  = get_current_user_id();
		$taxonomy = $request->get_param( 'taxonomy' );

		// Validate taxonomy is allowed and exists.
		$valid = $this->validate_taxonomy( $taxonomy, $user_id );

		if ( is_wp_error( $valid ) ) {
			return $valid;
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
		$user_id = get_current_user_id();

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
		$user_id      = get_current_user_id();
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
	 * Handle password reset request.
	 *
	 * Sends a password reset email. Always returns success to prevent
	 * email enumeration attacks.
	 *
	 * @since 0.2.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_password_reset_request( \WP_REST_Request $request ) {
		$logger = Logger::get_instance();
		$email  = $request->get_param( 'email' );
		$user   = get_user_by( 'email', $email );

		// Always return success to prevent email enumeration.
		$success_response = new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'If an account exists with this email, a password reset code has been sent.', 'maiexpowp' ),
			],
			200
		);

		if ( ! $user ) {
			$logger->info( sprintf( 'Password reset requested for non-existent email: %s', $email ) );
			return $success_response;
		}

		// Generate 6-digit reset code.
		$code = str_pad( random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );

		// Store hashed code, expiry (15 minutes), and reset attempt counter.
		update_user_meta( $user->ID, '_password_reset_code', wp_hash_password( $code ) );
		update_user_meta( $user->ID, '_password_reset_code_expires', time() + 900 );
		update_user_meta( $user->ID, '_password_reset_code_attempts', 0 );

		$site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );

		$message = sprintf(
			/* translators: 1: Site name, 2: Reset code */
			__( "Someone has requested a password reset for your %1\$s account.\n\nYour password reset code is:\n\n%2\$s\n\nThis code expires in 15 minutes.\n\nIf you did not request this, you can safely ignore this email.", 'maiexpowp' ),
			$site_name,
			$code
		);

		/**
		 * Filter the password reset email message.
		 *
		 * @since 0.2.0
		 * @since 0.3.0 Changed from URL-based to 6-digit code. $code replaces $key, $url removed.
		 *
		 * @param string   $message The email message.
		 * @param \WP_User $user    The user requesting the reset.
		 * @param string   $code    The 6-digit reset code (plain text, for inclusion in message).
		 */
		$message = apply_filters( 'maiexpowp_password_reset_message', $message, $user, $code );

		/* translators: %s: Site name */
		$title = sprintf( __( '[%s] Password Reset', 'maiexpowp' ), $site_name );

		$sent = wp_mail( $user->user_email, $title, $message );

		if ( ! $sent ) {
			$logger->error( sprintf( 'Failed to send password reset email to user ID %d', $user->ID ) );
		}

		return $success_response;
	}

	/**
	 * Handle password reset with 6-digit code.
	 *
	 * Validates the code against the hashed value stored in user meta,
	 * enforces a 3-attempt limit and 15-minute expiry, then sets the
	 * new password and invalidates all API tokens.
	 *
	 * @since 0.2.0
	 * @since 0.3.0 Changed from WP reset key to 6-digit hashed code with attempt limiting.
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_password_reset( \WP_REST_Request $request ) {
		$logger   = Logger::get_instance();
		$email    = $request->get_param( 'email' );
		$code     = $request->get_param( 'code' );
		$password = $request->get_param( 'password' );

		$user = get_user_by( 'email', $email );

		if ( ! $user ) {
			return new \WP_Error(
				'maiexpowp_invalid_reset',
				__( 'Invalid password reset request.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		$stored_hash = get_user_meta( $user->ID, '_password_reset_code', true );
		$expires     = (int) get_user_meta( $user->ID, '_password_reset_code_expires', true );
		$attempts    = (int) get_user_meta( $user->ID, '_password_reset_code_attempts', true );

		// Check if a code was ever requested.
		if ( ! $stored_hash ) {
			return new \WP_Error(
				'maiexpowp_no_reset_code',
				__( 'No password reset code has been requested.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Check expiry.
		if ( time() > $expires ) {
			// Clean up expired code.
			delete_user_meta( $user->ID, '_password_reset_code' );
			delete_user_meta( $user->ID, '_password_reset_code_expires' );
			delete_user_meta( $user->ID, '_password_reset_code_attempts' );

			return new \WP_Error(
				'maiexpowp_reset_code_expired',
				__( 'Reset code has expired. Please request a new one.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Check attempt limit (3 max).
		if ( $attempts >= 3 ) {
			// Invalidate the code after too many attempts.
			delete_user_meta( $user->ID, '_password_reset_code' );
			delete_user_meta( $user->ID, '_password_reset_code_expires' );
			delete_user_meta( $user->ID, '_password_reset_code_attempts' );

			$logger->warning( sprintf( 'Password reset code invalidated for user ID %d: too many attempts', $user->ID ) );

			return new \WP_Error(
				'maiexpowp_too_many_attempts',
				__( 'Too many incorrect attempts. Please request a new code.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Validate the code.
		if ( ! wp_check_password( $code, $stored_hash ) ) {
			// Increment attempt counter.
			update_user_meta( $user->ID, '_password_reset_code_attempts', $attempts + 1 );

			$logger->warning( sprintf( 'Invalid password reset code for user ID %d (attempt %d of 3)', $user->ID, $attempts + 1 ) );

			return new \WP_Error(
				'maiexpowp_invalid_reset_code',
				__( 'Invalid reset code.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Validate new password length.
		if ( strlen( $password ) < 8 ) {
			return new \WP_Error(
				'maiexpowp_password_too_short',
				__( 'New password must be at least 8 characters.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Code is valid — reset the password.
		reset_password( $user, $password );

		// Clean up reset code meta.
		delete_user_meta( $user->ID, '_password_reset_code' );
		delete_user_meta( $user->ID, '_password_reset_code_expires' );
		delete_user_meta( $user->ID, '_password_reset_code_attempts' );

		// Invalidate all API tokens (password changed = force re-login).
		Auth::invalidate_all_tokens( $user->ID );

		$logger->info( sprintf( 'Password reset completed for user ID %d, all API tokens invalidated', $user->ID ) );

		return new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'Password has been reset. Please log in with your new password.', 'maiexpowp' ),
			],
			200
		);
	}

	/**
	 * Handle password change for authenticated user.
	 *
	 * Validates the current password, sets the new one, invalidates all
	 * existing tokens, and returns a fresh token for the current session.
	 *
	 * @since 0.3.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_change_password( \WP_REST_Request $request ) {
		$logger           = Logger::get_instance();
		$user_id          = get_current_user_id();
		$user             = get_userdata( $user_id );
		$current_password = $request->get_param( 'current_password' );
		$new_password     = $request->get_param( 'new_password' );

		if ( ! $user ) {
			return new \WP_Error(
				'maiexpowp_user_not_found',
				__( 'User not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		// Validate current password.
		if ( ! wp_check_password( $current_password, $user->user_pass, $user_id ) ) {
			return new \WP_Error(
				'maiexpowp_invalid_password',
				__( 'Current password is incorrect.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Validate new password length.
		if ( strlen( $new_password ) < 8 ) {
			return new \WP_Error(
				'maiexpowp_password_too_short',
				__( 'New password must be at least 8 characters.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		// Set new password.
		wp_set_password( $new_password, $user_id );

		// Invalidate all existing tokens.
		Auth::invalidate_all_tokens( $user_id );

		// Issue a fresh token for the current session.
		$device_name = $request->get_header( 'X-Device-Name' ) ?: '';
		$token       = Auth::generate_token( $user_id, $device_name );

		$logger->info( sprintf( 'Password changed for user ID %d', $user_id ) );

		return new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'Password changed successfully.', 'maiexpowp' ),
				'token'   => $token,
			],
			200
		);
	}

	/**
	 * Handle soft account deletion.
	 *
	 * Severs the app connection by invalidating all API tokens.
	 * Does NOT delete the WordPress account — preserves website access,
	 * WooCommerce memberships, and order history.
	 *
	 * Fires `maiexpowp_before_delete_account` so apps can clean up
	 * app-specific data (taxonomy terms, meta, etc.) via mu-plugin.
	 *
	 * @since 0.2.0
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function handle_delete_account( \WP_REST_Request $request ) {
		$logger  = Logger::get_instance();
		$user_id = get_current_user_id();
		$confirm = $request->get_param( 'confirm' );
		$hard    = (bool) $request->get_param( 'hard' );

		if ( ! $confirm ) {
			return new \WP_Error(
				'maiexpowp_confirmation_required',
				__( 'You must confirm account deletion by setting confirm to true.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		/**
		 * Fires before an account is deleted from the app.
		 *
		 * Use this to clean up app-specific data: remove taxonomy terms,
		 * clear app meta, revoke app-specific access, delete third-party
		 * records (e.g. RevenueCat subscriber), etc. Runs for both soft
		 * and hard deletes so you can count on $user_id being queryable.
		 *
		 * @since 0.2.0
		 *
		 * @param int $user_id The user ID being deleted.
		 */
		do_action( 'maiexpowp_before_delete_account', $user_id );

		// Invalidate all API tokens (user can no longer auth from app).
		Auth::invalidate_all_tokens( $user_id );

		if ( $hard ) {
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $user_id, null );

			/**
			 * Fires after a user has been hard-deleted via wp_delete_user().
			 *
			 * At this point the $user_id no longer corresponds to a row in
			 * wp_users — use this only for cleanup that does not require
			 * querying user-owned data (those cleanups belong in
			 * `maiexpowp_before_delete_account`).
			 *
			 * @since 2.1.0
			 *
			 * @param int $user_id The ID of the user that was deleted.
			 */
			do_action( 'maiexpowp_after_delete_account', $user_id );

			$logger->info( sprintf( 'Account hard-deleted for user ID %d: WP user removed and all API tokens invalidated', $user_id ) );

			return new \WP_REST_Response(
				[
					'success' => true,
					'message' => __( 'Your account has been deleted.', 'maiexpowp' ),
				],
				200
			);
		}

		$logger->info( sprintf( 'Account soft-deleted for user ID %d: all API tokens invalidated', $user_id ) );

		return new \WP_REST_Response(
			[
				'success' => true,
				'message' => __( 'Your app account has been deleted. Your website account remains active.', 'maiexpowp' ),
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
	 * Get allowed meta keys for reading.
	 *
	 * Defaults to the write allowlist, but can be extended via filter
	 * to include read-only keys (e.g., keys set by webhooks).
	 *
	 * @since 0.2.0
	 *
	 * @return array Array of allowed meta key names for reading.
	 */
	private function get_allowed_meta_read_keys(): array {
		$write_keys = apply_filters( 'maiexpowp_allowed_user_meta_keys', [] );

		/**
		 * Filter the allowed user meta keys for reading.
		 *
		 * Defaults to the write allowlist. Add keys here that should be
		 * readable but not writable (e.g., keys managed by webhooks).
		 *
		 * @since 0.2.0
		 *
		 * @param array $allowed_keys Array of allowed meta key names for reading.
		 */
		return apply_filters( 'maiexpowp_allowed_user_meta_read_keys', $write_keys );
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
		return apply_filters( 'maiexpowp_allowed_user_taxonomies', [] );
	}

	/**
	 * Build a standard auth response (token + user data).
	 *
	 * Used by login, register, and social login handlers.
	 *
	 * @since 0.2.0
	 *
	 * @param int    $user_id     The authenticated user ID.
	 * @param string $device_name Optional. Device identifier for session management.
	 * @param int    $status_code HTTP status code. Default 200.
	 * @param array  $extra       Additional fields to merge into the response.
	 *
	 * @return \WP_REST_Response
	 */
	private function auth_response( int $user_id, string $device_name = '', int $status_code = 200, array $extra = [] ): \WP_REST_Response {
		$token     = Auth::generate_token( $user_id, $device_name );
		$user_data = Auth::get_user_data( $user_id );

		return new \WP_REST_Response(
			array_merge(
				[ 'success' => true, 'token' => $token ],
				$user_data,
				$extra
			),
			$status_code
		);
	}

	/**
	 * Validate a taxonomy is allowed and exists.
	 *
	 * @since 0.2.0
	 *
	 * @param string $taxonomy The taxonomy name.
	 * @param int    $user_id  Optional. User ID for log context.
	 *
	 * @return true|\WP_Error True if valid, WP_Error otherwise.
	 */
	/**
	 * Process taxonomy terms for a user.
	 *
	 * Idempotent - safe to call on every auth request.
	 * Uses wp_set_object_terms which replaces terms for each taxonomy.
	 *
	 * @since 0.3.0
	 *
	 * @param int   $user_id The user ID.
	 * @param array $terms   Associative array of taxonomy => term values.
	 *
	 * @return void
	 */
	private function process_user_terms( int $user_id, array $terms ): void {
		foreach ( $terms as $taxonomy => $term_values ) {
			$taxonomy = sanitize_key( $taxonomy );

			if ( is_wp_error( $this->validate_taxonomy( $taxonomy, $user_id ) ) ) {
				continue;
			}

			$term_values = is_array( $term_values ) ? $term_values : [ $term_values ];
			$term_values = array_map( 'sanitize_text_field', $term_values );

			wp_set_object_terms( $user_id, $term_values, $taxonomy );
		}
	}

	private function validate_taxonomy( string $taxonomy, int $user_id = 0 ) {
		$logger = Logger::get_instance();

		if ( ! in_array( $taxonomy, $this->get_allowed_taxonomies(), true ) ) {
			$logger->warning( sprintf( 'Disallowed taxonomy "%s" requested by user ID: %d', $taxonomy, $user_id ) );

			return new \WP_Error(
				'maiexpowp_taxonomy_not_allowed',
				__( 'This taxonomy is not allowed.', 'maiexpowp' ),
				[ 'status' => 400 ]
			);
		}

		if ( ! taxonomy_exists( $taxonomy ) ) {
			$logger->warning( sprintf( 'Non-existent taxonomy "%s" requested by user ID: %d', $taxonomy, $user_id ) );

			return new \WP_Error(
				'maiexpowp_taxonomy_not_found',
				__( 'Taxonomy not found.', 'maiexpowp' ),
				[ 'status' => 404 ]
			);
		}

		return true;
	}
}
