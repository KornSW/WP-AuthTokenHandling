<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Session_Guard {
    public static function register_hooks() {
        add_filter('login_redirect', array(__CLASS__, 'login_redirect'), 20, 3);
        add_action('init', array(__CLASS__, 'enforce_login_source'), 1);
        add_action('login_footer', array(__CLASS__, 'render_oauth_login'));
        add_action('login_init', array(__CLASS__, 'handle_login_actions'));
        add_action('login_enqueue_scripts', array(__CLASS__, 'enqueue_login_assets'));
        add_action('admin_post_kornsw_ath_admin_bypass', array(__CLASS__, 'admin_bypass'));
    }

    public static function enqueue_login_assets() {
        wp_enqueue_style('kornsw-ath-login', KORNSW_ATH_URL . 'assets/login.css', array(), KORNSW_ATH_VERSION);
    }

    public static function login_redirect($redirect_to, $requested, $user) {
        if (!($user instanceof WP_User)) { return $redirect_to; }
        $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
        if (!$profiles) { return $redirect_to; }
        $return = $requested ?: $redirect_to;
        if (in_array('administrator', (array) $user->roles, true) || count($profiles) > 1) {
            return self::choice_url($return);
        }
        return self::source_start_url((string) $profiles[0]['TokenSourceUid'], $return);
    }

    private static function choice_url($return) {
        return add_query_arg(array('action' => 'kornsw_ath_login_choice', 'return' => $return), wp_login_url());
    }

    private static function source_start_url($source_uid, $return) {
        return admin_url('admin-post.php?action=kornsw_ath_oauth_start&source=' . rawurlencode($source_uid) . '&purpose=login&return=' . rawurlencode($return));
    }

    public static function handle_login_actions() {
        $action = (string) ($_REQUEST['action'] ?? '');
        if ($action === 'kornsw_ath_oauth_login') {
            $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
            if (!$profiles) { wp_die('Keine WordPress-Login-Token-Source konfiguriert.'); }
            $return = esc_url_raw(wp_unslash($_REQUEST['redirect_to'] ?? admin_url()));
            if (count($profiles) > 1) { wp_safe_redirect(self::choice_url($return)); exit; }
            KornSW_ATH_OAuth_Flow::start((string) $profiles[0]['TokenSourceUid'], $return, 'login');
        }
        if ($action === 'kornsw_ath_login_choice' || $action === 'kornsw_ath_admin_choice') {
            self::render_login_choice();
        }
    }

    private static function render_login_choice() {
        $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
        $return = esc_url_raw(wp_unslash($_GET['return'] ?? $_GET['redirect_to'] ?? admin_url()));
        $user = wp_get_current_user();
        $is_admin = $user->ID && in_array('administrator', (array) $user->roles, true);
        $site_name = get_bloginfo('name');
        ?><!doctype html>
        <html lang="de">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <title><?php echo esc_html('Anmeldung – ' . $site_name); ?></title>
            <link rel="stylesheet" href="<?php echo esc_url(KORNSW_ATH_URL . 'assets/login.css?ver=' . rawurlencode(KORNSW_ATH_VERSION)); ?>">
        </head>
        <body class="kornsw-ath-auth-page">
            <main class="kornsw-ath-auth-shell">
                <div class="kornsw-ath-auth-site"><span class="kornsw-ath-auth-site__name"><?php echo esc_html($site_name); ?></span></div>
                <section class="kornsw-ath-auth-card">
                    <h1>Authentifizierung wählen</h1>
                    <p class="kornsw-ath-auth-card__lead"><?php echo esc_html(count($profiles) > 1 ? 'Wähle aus, mit welchem Konto diese Sitzung authentifiziert werden soll.' : 'Für diese Sitzung ist eine zusätzliche Authentifizierung erforderlich.'); ?></p>
                    <?php if (!$profiles) { ?>
                        <p>Es ist keine aktive WordPress-Login-Token-Source verfügbar.</p>
                    <?php } else { ?>
                        <div class="kornsw-ath-login-grid">
                            <?php foreach ($profiles as $profile) { echo self::login_tile_html($profile, $return); } ?>
                        </div>
                    <?php } ?>
                    <?php if ($is_admin) { ?>
                        <div class="kornsw-ath-auth-card__separator"></div>
                        <form class="kornsw-ath-auth-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <input type="hidden" name="action" value="kornsw_ath_admin_bypass">
                            <input type="hidden" name="return" value="<?php echo esc_attr($return); ?>">
                            <?php wp_nonce_field('kornsw_ath_admin_bypass'); ?>
                            <button type="submit" class="secondary">Nur WordPress-Passwort für diese Sitzung</button>
                        </form>
                        <p class="kornsw-ath-note">Der lokale Administratorzugang umgeht die Token-Pflicht ausschließlich für diese konkrete Sitzung.</p>
                    <?php } ?>
                </section>
            </main>
        </body>
        </html><?php
        exit;
    }

    public static function admin_bypass() {
        check_admin_referer('kornsw_ath_admin_bypass');
        $user = wp_get_current_user();
        if (!$user->ID || !in_array('administrator', (array) $user->roles, true)) { wp_die('Nicht erlaubt.', 403); }
        KornSW_ATH_Storage::set_binding($user->ID, '', true);
        wp_safe_redirect(wp_unslash($_POST['return'] ?? admin_url()));
        exit;
    }

    public static function enforce_login_source() {
        if (!is_user_logged_in() || self::is_own_flow()) { return; }
        $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
        if (!$profiles) { return; }
        $user = wp_get_current_user();
        $binding = KornSW_ATH_Storage::get_binding($user->ID);
        if ($binding && !empty($binding['bypass_primary']) && in_array('administrator', (array) $user->roles, true)) { return; }

        $source_uid = $binding ? (string) $binding['source_uid'] : '';
        if ($source_uid !== '' && KornSW_ATH_Config_Repository::is_login_source($source_uid)) {
            $result = KornSW_ATH_Token_Manager::try_get_access_token($source_uid, $user->ID);
            if (($result['status'] ?? '') === 'SUCCESS') { return; }
            self::terminate_current_session('Login token validation failed: ' . ($result['status'] ?? 'UNKNOWN'));
        }

        if (KornSW_ATH_OAuth_Flow::is_interactive_request()) {
            $return = KornSW_ATH_OAuth_Flow::current_url();
            if (count($profiles) > 1 || in_array('administrator', (array) $user->roles, true)) {
                wp_safe_redirect(self::choice_url($return));
                exit;
            }
            KornSW_ATH_OAuth_Flow::start((string) $profiles[0]['TokenSourceUid'], $return, 'login');
        }
        self::terminate_current_session('Login token binding missing.');
    }

    private static function terminate_current_session($reason) {
        $user_id = get_current_user_id();
        $token = wp_get_session_token();
        if ($user_id && $token !== '') { WP_Session_Tokens::get_instance($user_id)->destroy($token); }
        wp_clear_auth_cookie();
        do_action('kornsw_authtokenhandling_primary_session_terminated', $user_id, $reason);
        if (KornSW_ATH_OAuth_Flow::is_interactive_request()) {
            wp_safe_redirect(wp_login_url(KornSW_ATH_OAuth_Flow::current_url()));
            exit;
        }
        wp_die('Authentication required.', 401);
    }

    private static function is_own_flow() {
        $action = (string) ($_REQUEST['action'] ?? '');
        return str_starts_with($action, 'kornsw_ath_');
    }

    public static function render_oauth_login() {
        $action = (string) ($_REQUEST['action'] ?? 'login');
        if ($action !== '' && $action !== 'login') { return; }
        $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
        if (!$profiles) { return; }
        $return = esc_url_raw(wp_unslash($_REQUEST['redirect_to'] ?? admin_url()));
        $is_native_login = isset($GLOBALS['pagenow']) && $GLOBALS['pagenow'] === 'wp-login.php';
        echo '<aside id="kornsw-ath-login-methods" class="kornsw-ath-login-methods" aria-label="OAuth-Anmeldung" data-native-login="' . ($is_native_login ? '1' : '0') . '">';
        if ($is_native_login) {
            echo '<div class="kornsw-ath-login-methods__title">Oder anmelden mit</div>';
        }
        echo '<div class="kornsw-ath-login-grid">';
        foreach ($profiles as $profile) {
            echo self::login_tile_html($profile, $return);
        }
        echo '</div></aside>';
        if ($is_native_login) {
            echo '<script>(function(){var panel=document.getElementById("kornsw-ath-login-methods");var form=document.getElementById("loginform");if(!panel||!form){return;}form.appendChild(panel);})()</script>';
        }
    }

    private static function login_tile_html($profile, $return) {
        $uid = (string) ($profile['TokenSourceUid'] ?? '');
        $label = trim((string) ($profile['DisplayName'] ?? ''));
        if ($label === '') { $label = 'OAuth'; }
        $target = self::profile_authentication_url($profile);
        $host = self::display_host($target);
        $favicon = self::favicon_url($target);
        $url = self::source_start_url($uid, $return);
        $fallback = self::fallback_icon_html('kornsw-ath-login-tile__fallback');
        $icon = $favicon !== ''
            ? '<img class="kornsw-ath-login-tile__icon" src="' . esc_url($favicon) . '" alt="" loading="lazy" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\';">' . str_replace('class="kornsw-ath-login-tile__fallback"', 'class="kornsw-ath-login-tile__fallback" style="display:none"', $fallback)
            : $fallback;
        return '<a class="kornsw-ath-login-tile" href="' . esc_url($url) . '">' . $icon . '<span class="kornsw-ath-login-tile__body"><span class="kornsw-ath-login-tile__label">Mit ' . esc_html($label) . ' anmelden</span>' . ($host !== '' ? '<span class="kornsw-ath-login-tile__host">' . esc_html($host) . '</span>' : '') . '</span><span class="kornsw-ath-login-tile__arrow" aria-hidden="true">›</span></a>';
    }


    private static function fallback_icon_html($class_name) {
        return '<span class="' . esc_attr($class_name) . '" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><path d="M3 10.7 12 3l9 7.7v9.1c0 .7-.5 1.2-1.2 1.2h-5.3v-6.1h-5V21H4.2C3.5 21 3 20.5 3 19.8v-9.1Zm2 1v7.3h2.5v-6.1h9V19H19v-7.3l-7-6-7 6Z"/></svg></span>';
    }

    private static function profile_authentication_url($profile) {
        $provider = strtolower((string) ($profile['OAuthOperationsProvider'] ?? 'generic'));
        $config = is_array($profile['ProviderConfiguration'] ?? null) ? $profile['ProviderConfiguration'] : array();
        if ($provider === 'google') { return 'https://accounts.google.com/'; }
        if ($provider === 'github') { return 'https://github.com/'; }
        if ($provider === 'microsoft') { return 'https://login.microsoftonline.com/'; }
        if ($provider === 'apple') { return 'https://appleid.apple.com/'; }
        if ($provider === 'facebook') { return 'https://www.facebook.com/'; }
        if ($provider === 'remote_wordpress') { return esc_url_raw((string) ($config['remote_base_url'] ?? '')); }
        return esc_url_raw((string) ($config['authorization_endpoint'] ?? ''));
    }

    private static function favicon_url($url) {
        $parts = wp_parse_url((string) $url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host'])) { return ''; }
        $scheme = strtolower((string) $parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') { return ''; }
        $port = isset($parts['port']) ? ':' . (int) $parts['port'] : '';
        return $scheme . '://' . $parts['host'] . $port . '/favicon.ico';
    }

    private static function display_host($url) {
        $host = wp_parse_url((string) $url, PHP_URL_HOST);
        return is_string($host) ? $host : '';
    }
}
