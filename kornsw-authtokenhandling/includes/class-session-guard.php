<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Session_Guard {
    public static function register_hooks() {
        add_filter('login_redirect', array(__CLASS__, 'login_redirect'), 20, 3);
        add_action('init', array(__CLASS__, 'enforce_login_source'), 1);
        add_action('login_form', array(__CLASS__, 'render_oauth_login'));
        add_action('login_init', array(__CLASS__, 'handle_login_actions'));
        add_action('admin_post_kornsw_ath_admin_bypass', array(__CLASS__, 'admin_bypass'));
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
        ?><!doctype html><html><head><meta charset="utf-8"><title>Authentifizierung wählen</title><?php wp_admin_css('login', true); ?></head><body class="login"><div id="login"><h1><a href="<?php echo esc_url(home_url('/')); ?>">WordPress</a></h1><div class="message"><p><?php echo esc_html(count($profiles) > 1 ? 'Wähle die Token Source, mit der diese WordPress-Sitzung authentifiziert werden soll.' : 'Für diese WordPress-Sitzung ist eine zusätzliche Token-Authentifizierung vorgesehen.'); ?></p></div><?php
        if (!$profiles) {
            echo '<div class="notice notice-error"><p>Es ist keine aktive WordPress-Login-Token-Source verfügbar.</p></div>';
        }
        foreach ($profiles as $profile) {
            $uid = (string) $profile['TokenSourceUid'];
            $label = (string) ($profile['DisplayName'] ?? $uid);
            echo '<p><a class="button button-primary button-large" style="width:100%;text-align:center" href="' . esc_url(self::source_start_url($uid, $return)) . '">Mit ' . esc_html($label) . ' anmelden</a></p>';
        }
        if ($is_admin) {
            ?><div class="message"><p>Als Administrator kannst du die Token-Pflicht nur für diese Sitzung deaktivieren. Dadurch bleibt ein lokaler Notfallzugang erhalten.</p></div><form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"><input type="hidden" name="action" value="kornsw_ath_admin_bypass"><input type="hidden" name="return" value="<?php echo esc_attr($return); ?>"><?php wp_nonce_field('kornsw_ath_admin_bypass'); ?><p><button class="button button-secondary button-large" style="width:100%">Nur WordPress-Passwort für diese Sitzung</button></p></form><?php
        }
        ?></div></body></html><?php
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
        $profiles = KornSW_ATH_Config_Repository::get_login_profiles();
        if (!$profiles) { return; }
        $return = esc_url_raw(wp_unslash($_REQUEST['redirect_to'] ?? admin_url()));
        if (count($profiles) === 1) {
            $profile = $profiles[0];
            $label = esc_html($profile['DisplayName'] ?? 'OAuth');
            $url = self::source_start_url((string) $profile['TokenSourceUid'], $return);
            echo '<p style="margin-top:16px"><a class="button button-secondary button-large" style="width:100%;text-align:center" href="' . esc_url($url) . '">Mit ' . $label . ' anmelden</a></p>';
            return;
        }
        echo '<p style="margin-top:16px"><a class="button button-secondary button-large" style="width:100%;text-align:center" href="' . esc_url(self::choice_url($return)) . '">Mit OAuth / Token Source anmelden</a></p>';
    }
}
