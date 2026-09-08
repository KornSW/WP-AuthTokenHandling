<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Shortcodes {
    public static function register_hooks() {
        add_shortcode('oauth_integrations', array(__CLASS__, 'integrations'));
        add_shortcode('oauth_connect', array(__CLASS__, 'connect'));
    }

    public static function integrations() {
        if (!is_user_logged_in()) {
            return '<p>Bitte zuerst bei WordPress anmelden.</p>';
        }

        $html = '<div class="kornsw-ath-integrations">';
        foreach (KornSW_ATH_Config_Repository::get_enabled_profiles() as $profile) {
            if (!empty($profile['LoginEnabled'])) {
                continue;
            }

            $uid = (string) ($profile['TokenSourceUid'] ?? '');
            if ($uid === '') {
                continue;
            }

            $connected = (bool) KornSW_ATH_Storage::get_connection(get_current_user_id(), $uid);
            $html .= '<p><strong>' . esc_html($profile['DisplayName'] ?? $uid) . '</strong> – ' . ($connected ? 'verbunden' : 'nicht verbunden');
            if (!$connected) {
                $url = admin_url(
                    'admin-post.php?action=kornsw_ath_oauth_start&source=' . rawurlencode($uid) .
                    '&return=' . rawurlencode(KornSW_ATH_OAuth_Flow::current_url())
                );
                $html .= ' <a href="' . esc_url($url) . '">Authentifizieren</a>';
            }
            $html .= '</p>';
        }
        $html .= '</div>';
        return $html;
    }

    public static function connect($atts) {
        $a = shortcode_atts(array('source' => ''), $atts);
        if ($a['source'] === '') {
            return '';
        }

        $url = admin_url(
            'admin-post.php?action=kornsw_ath_oauth_start&source=' . rawurlencode($a['source']) .
            '&return=' . rawurlencode(KornSW_ATH_OAuth_Flow::current_url())
        );
        return '<a href="' . esc_url($url) . '">Authentifizieren</a>';
    }
}
