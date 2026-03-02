<?php
/**
 * Plugin Name:       MaiExpoWP
 * Plugin URI:        https://bizbudding.com
 * Description:       WordPress companion plugin for maiexpowp React Native library.
 * Version:           0.2.1
 * Requires at least: 6.9
 * Requires PHP:      8.1
 * Text Domain:       maiexpowp
 * Author:            BizBudding
 * Author URI:        https://bizbudding.com
 *
 * @package MaiExpoWP
 */

defined( 'ABSPATH' ) || exit;

// Plugin constants.
define( 'MAIEXPOWP_VERSION', '0.2.1' );
define( 'MAIEXPOWP_DIR', plugin_dir_path( __FILE__ ) );
define( 'MAIEXPOWP_URL', plugin_dir_url( __FILE__ ) );

// Include core classes.
require_once MAIEXPOWP_DIR . 'classes/class-logger.php';
require_once MAIEXPOWP_DIR . 'classes/class-plugin.php';
require_once MAIEXPOWP_DIR . 'classes/class-auth.php';
require_once MAIEXPOWP_DIR . 'classes/class-social-auth.php';
require_once MAIEXPOWP_DIR . 'classes/class-rest-api.php';
require_once MAIEXPOWP_DIR . 'classes/class-membership-provider.php';
require_once MAIEXPOWP_DIR . 'classes/class-membership-manager.php';

// Include membership providers.
require_once MAIEXPOWP_DIR . 'classes/membership-providers/class-woocommerce-memberships.php';
require_once MAIEXPOWP_DIR . 'classes/membership-providers/class-restrict-content-pro.php';

// Activation/deactivation hooks.
register_activation_hook( __FILE__, [ 'MaiExpoWP\\Plugin', 'activate' ] );
register_deactivation_hook( __FILE__, [ 'MaiExpoWP\\Plugin', 'deactivate' ] );

add_action( 'plugins_loaded', 'maiexpowp_init' );
/**
 * Initialize the plugin.
 *
 * @since 0.1.0
 *
 * @return void
 */
function maiexpowp_init() {
	// Initialize auth (sets up current user from Bearer token).
	MaiExpoWP\Auth::init();

	// Initialize core plugin (handles meta registration, upgrades).
	MaiExpoWP\Plugin::get_instance();

	// Initialize REST API.
	MaiExpoWP\REST_API::get_instance();

	// Initialize Membership Manager (auto-detects available providers).
	MaiExpoWP\Membership_Manager::get_instance();
}
