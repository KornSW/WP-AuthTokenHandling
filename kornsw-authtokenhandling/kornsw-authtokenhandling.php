<?php
/**
 * Plugin Name:       KornSW AuthTokenHandling
 * Plugin URI:        https://github.com/KornSW/WP-AuthTokenHandling
 * Description:       Zentrale Token-Source-Runtime für WordPress mit OAuth/OIDC, Session-Bindung und öffentlicher Plugin-API.
 * Version:           1.2.1
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            KornSW
 * License:           GPL-2.0-or-later
 * Update URI:        https://github.com/KornSW/WP-AuthTokenHandling
 * Text Domain:       kornsw-authtokenhandling
 */

if (!defined('ABSPATH')) {
    exit;
}

define('KORNSW_ATH_VERSION', '1.2.1');
define('KORNSW_ATH_FILE', __FILE__);
define('KORNSW_ATH_DIR', plugin_dir_path(__FILE__));
define('KORNSW_ATH_URL', plugin_dir_url(__FILE__));

require_once KORNSW_ATH_DIR . 'includes/class-config-repository.php';
require_once KORNSW_ATH_DIR . 'includes/class-crypto.php';
require_once KORNSW_ATH_DIR . 'includes/class-storage.php';
require_once KORNSW_ATH_DIR . 'includes/class-jwt-helper.php';
require_once KORNSW_ATH_DIR . 'includes/class-oauth-server-scopes.php';
require_once KORNSW_ATH_DIR . 'includes/class-oauth-server-config.php';
require_once KORNSW_ATH_DIR . 'includes/providers/interface-oauth-operations-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-provider-base.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-generic-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-google-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-github-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-microsoft-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-apple-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-facebook-provider.php';
require_once KORNSW_ATH_DIR . 'includes/providers/class-remote-wordpress-provider.php';
require_once KORNSW_ATH_DIR . 'includes/class-provider-registry.php';
require_once KORNSW_ATH_DIR . 'includes/issuers/interface-access-token-issuer.php';
require_once KORNSW_ATH_DIR . 'includes/issuers/class-local-jwt-issuer.php';
require_once KORNSW_ATH_DIR . 'includes/introspection/interface-access-token-introspector.php';
require_once KORNSW_ATH_DIR . 'includes/introspection/class-introspector-factory.php';
require_once KORNSW_ATH_DIR . 'includes/class-token-manager.php';
require_once KORNSW_ATH_DIR . 'includes/class-oauth-flow.php';
require_once KORNSW_ATH_DIR . 'includes/class-session-guard.php';
require_once KORNSW_ATH_DIR . 'includes/class-admin.php';
require_once KORNSW_ATH_DIR . 'includes/class-shortcodes.php';
require_once KORNSW_ATH_DIR . 'includes/class-oauth-server.php';
require_once KORNSW_ATH_DIR . 'includes/class-oauth-server-admin.php';
require_once KORNSW_ATH_DIR . 'includes/api.php';
require_once KORNSW_ATH_DIR . 'includes/class-plugin.php';

register_activation_hook(__FILE__, array('KornSW_ATH_Plugin', 'activate'));
KornSW_ATH_Plugin::instance()->boot();
