<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Provider_Registry {
    public static function all() {
        $providers = array(
            'generic' => new KornSW_ATH_Generic_Provider(),
            'google' => new KornSW_ATH_Google_Provider(),
            'github' => new KornSW_ATH_GitHub_Provider()
        );
        return apply_filters('kornsw_authtokenhandling_oauth_providers', $providers);
    }

    public static function get_for_profile($profile) {
        $name = (string) ($profile['OAuthOperationsProvider'] ?? 'generic');
        return self::get_by_name($name, 'OAuthOperationsProvider');
    }

    public static function get_for_introspection_profile($profile, &$runtime_profile = null) {
        $mode = (string) (($profile['AuthTokenConfig'] ?? array())['ValidationMode'] ?? 'IMPLICIT_WHEN_USED');
        $name = (string) ($profile['IntrospectionProvider'] ?? '');

        if ($mode === 'GITHUB_VALIDATION_ENDPOINT') {
            $name = 'github';
        } elseif ($name === '') {
            $name = (string) ($profile['OAuthOperationsProvider'] ?? 'generic');
        }

        $runtime_profile = $profile;
        $runtime_profile['OAuthOperationsProvider'] = $name;

        $base_configuration = is_array($profile['ProviderConfiguration'] ?? null) ? $profile['ProviderConfiguration'] : array();
        $introspection_configuration = is_array($profile['IntrospectionProviderConfiguration'] ?? null) ? $profile['IntrospectionProviderConfiguration'] : array();
        $runtime_profile['ProviderConfiguration'] = array_replace($base_configuration, $introspection_configuration);

        return self::get_by_name($name, 'IntrospectionProvider');
    }

    private static function get_by_name($name, $field_name) {
        $all = self::all();
        if (isset($all[$name])) {
            return $all[$name];
        }
        return new WP_Error('unknown_provider', 'Unbekannter ' . $field_name . ': ' . $name);
    }
}
