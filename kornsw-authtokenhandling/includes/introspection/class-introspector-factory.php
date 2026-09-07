<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Introspector_Factory {
    public static function validate($profile, $access_token) {
        $mode = (string) (($profile['AuthTokenConfig'] ?? array())['ValidationMode'] ?? 'IMPLICIT_WHEN_USED');
        if ($mode === 'LOCAL_JWT_VALIDATION') {
            return self::local_jwt_validate($profile, $access_token);
        }
        if ($mode === 'IMPLICIT_WHEN_USED') {
            return array('technical_success' => true, 'active' => true, 'valid_until' => null, 'reason' => null, 'claims' => array());
        }

        $runtime_profile = null;
        $provider = KornSW_ATH_Provider_Registry::get_for_introspection_profile($profile, $runtime_profile);
        if (is_wp_error($provider)) {
            return array('technical_success' => false, 'active' => false, 'reason' => $provider->get_error_message(), 'claims' => array());
        }
        return $provider->validate_token($runtime_profile, $access_token);
    }

    public static function local_jwt_validate($profile, $token) {
        $config = $profile['AuthTokenConfig'] ?? array();
        $key = (string) ($config['JwtValidationKey'] ?? '');
        if ($key === '') return array('technical_success' => false, 'active' => false, 'reason' => 'JwtValidationKey fehlt', 'claims' => array());
        $parts = explode('.', $token);
        if (count($parts) !== 3) return array('technical_success' => true, 'active' => false, 'reason' => 'Malformed JWT', 'claims' => array());
        $header = json_decode(self::b64d($parts[0]), true);
        $claims = json_decode(self::b64d($parts[1]), true);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'HS256') return array('technical_success' => true, 'active' => false, 'reason' => 'Unsupported JWT', 'claims' => array());
        $expected = self::b64(hash_hmac('sha256', $parts[0] . '.' . $parts[1], $key, true));
        if (!hash_equals($expected, $parts[2])) return array('technical_success' => true, 'active' => false, 'reason' => 'Invalid JWT signature', 'claims' => array());
        $now = time();
        if (isset($claims['exp']) && (int) $claims['exp'] < $now) return array('technical_success' => true, 'active' => false, 'reason' => 'expired', 'claims' => $claims);
        if (isset($claims['nbf']) && (int) $claims['nbf'] > $now) return array('technical_success' => true, 'active' => false, 'reason' => 'not yet valid', 'claims' => $claims);
        return array('technical_success' => true, 'active' => true, 'valid_until' => isset($claims['exp']) ? (int) $claims['exp'] : null, 'reason' => null, 'claims' => $claims);
    }

    private static function b64d($value) {
        $value = strtr($value, '-_', '+/');
        $padding = strlen($value) % 4;
        if ($padding) $value .= str_repeat('=', 4 - $padding);
        return base64_decode($value);
    }

    private static function b64($value) {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
