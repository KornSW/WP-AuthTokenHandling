<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Config_Repository {
    const OPTION_PROFILES_JSON = 'kornsw_ath_profiles_json';
    const OPTION_PRIMARY_SOURCE = 'kornsw_ath_primary_source_uid'; // Legacy migration only.
    const OPTION_AUTO_ROLE = 'kornsw_ath_auto_provision_role';
    const OPTION_LOGIN_SOURCE_MIGRATED = 'kornsw_ath_login_source_migrated';

    public static function get_profiles_json() {
        $json = get_option(self::OPTION_PROFILES_JSON, '[]');
        return is_string($json) ? $json : '[]';
    }

    public static function get_profiles() {
        $decoded = json_decode(self::get_profiles_json(), true);
        if (!is_array($decoded)) { return array(); }
        $result = array();
        foreach ($decoded as $profile) {
            if (is_array($profile) && !empty($profile['TokenSourceUid'])) { $result[] = $profile; }
        }
        return $result;
    }

    public static function save_profiles_json($json) {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) { return new WP_Error('invalid_json', 'Die Profilkonfiguration ist kein gültiges JSON-Array.'); }
        $uids = array();
        foreach ($decoded as $index => $profile) {
            if (!is_array($profile)) { return new WP_Error('invalid_profile', 'Profil #' . ($index + 1) . ' ist kein JSON-Objekt.'); }
            $uid = isset($profile['TokenSourceUid']) ? trim((string) $profile['TokenSourceUid']) : '';
            if ($uid === '') { return new WP_Error('missing_uid', 'Profil #' . ($index + 1) . ' hat keine TokenSourceUid.'); }
            if (isset($uids[$uid])) { return new WP_Error('duplicate_uid', 'TokenSourceUid ist doppelt vorhanden: ' . $uid); }
            $uids[$uid] = true;
            if (!isset($profile['AuthTokenConfig']) || !is_array($profile['AuthTokenConfig'])) { return new WP_Error('missing_config', 'Profil ' . $uid . ' hat keine AuthTokenConfig.'); }
        }
        $normalized = wp_json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        update_option(self::OPTION_PROFILES_JSON, $normalized, false);
        return true;
    }

    public static function get_profile($uid) {
        foreach (self::get_profiles() as $profile) {
            if (hash_equals((string) $profile['TokenSourceUid'], (string) $uid)) { return $profile; }
        }
        return null;
    }

    public static function get_enabled_profiles() {
        return array_values(array_filter(self::get_profiles(), function ($profile) {
            return !isset($profile['Enabled']) || (bool) $profile['Enabled'];
        }));
    }

    public static function get_login_profiles() {
        return array_values(array_filter(self::get_enabled_profiles(), function ($profile) {
            if (empty($profile['LoginEnabled'])) { return false; }
            $mode = (string) (($profile['AuthTokenConfig'] ?? array())['IssueMode'] ?? '');
            return str_starts_with($mode, 'OAUTH_');
        }));
    }

    public static function is_login_source($uid) {
        foreach (self::get_login_profiles() as $profile) {
            if (hash_equals((string) $profile['TokenSourceUid'], (string) $uid)) { return true; }
        }
        return false;
    }

    public static function migrate_legacy_primary_source() {
        if (get_option(self::OPTION_LOGIN_SOURCE_MIGRATED, '') === '1') { return; }
        $legacy = (string) get_option(self::OPTION_PRIMARY_SOURCE, '');
        if ($legacy !== '') {
            $profiles = self::get_profiles();
            $changed = false;
            foreach ($profiles as &$profile) {
                if ((string) ($profile['TokenSourceUid'] ?? '') === $legacy && empty($profile['LoginEnabled'])) {
                    $profile['LoginEnabled'] = true;
                    $changed = true;
                }
            }
            unset($profile);
            if ($changed) { self::save_profiles_json(wp_json_encode($profiles)); }
        }
        delete_option(self::OPTION_PRIMARY_SOURCE);
        update_option(self::OPTION_LOGIN_SOURCE_MIGRATED, '1', false);
    }

    public static function get_auto_provision_role() {
        $role = (string) get_option(self::OPTION_AUTO_ROLE, 'subscriber');
        return $role !== '' ? $role : 'subscriber';
    }

    public static function create_default_profile() {
        return array(
            'TokenSourceUid' => wp_generate_uuid4(),
            'DisplayName' => 'Neue Token Source',
            'Enabled' => true,
            'LoginEnabled' => false,
            'OAuthOperationsProvider' => 'generic',
            'IntrospectionProvider' => 'generic',
            'ProviderConfiguration' => array(
                'authorization_endpoint' => '', 'token_endpoint' => '', 'userinfo_endpoint' => '', 'introspection_endpoint' => '',
                'introspection_auth' => 'none', 'supports_refresh_token' => true, 'supports_id_token' => false,
                'scopes' => 'openid email profile'
            ),
            'IntrospectionProviderConfiguration' => array(
                'introspection_endpoint' => ''
            ),
            'AuthTokenConfig' => array(
                'DisplayLabel' => 'Authentification', 'DisplayIconUrl' => '', 'IssueMode' => 'OAUTH_CIBA_CODEGRAND',
                'RetrieveEndpointUrl' => '', 'RetrieveEndpointAuthorization' => '', 'LocalLogonNameToLower' => false,
                'LocalLogonNamePersistation' => 'OPT-IN', 'LocalLogonNameSyntax' => '', 'LocalLogonNameInputLabel' => '',
                'LocalLogonPassInputLabel' => '', 'LocalLogonSaltDisplayLabel' => '', 'JwtExpMinutes' => 1440,
                'JwtSelfSignKey' => '', 'JwtSelfSignAlg' => 'HS256', 'ClientId' => '', 'ClientSecret' => '',
                'AuthEndpointUrl' => '', 'AdditionalAuthArgs' => '', 'AdditionalRetrieveArgs' => '',
                'AuthEndpointRejectsIframe' => true, 'ValidationMode' => 'OAUTH_INTROSPECTION_ENDPOINT',
                'ValidationOutcomeCacheMins' => 2, 'JwtValidationKey' => '', 'ClaimValidationIgnoresCasing' => true,
                'ValidationEndpointUrl' => '', 'validationEndpointAuthorization' => '', 'Claims' => array()
            )
        );
    }
}
