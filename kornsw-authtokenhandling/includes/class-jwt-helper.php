<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_JWT_Helper {
    public static function encode_hs256($claims, $key, $header = array()) {
        $header = array_merge(array('typ' => 'JWT', 'alg' => 'HS256'), $header);
        $head = self::b64url(wp_json_encode($header));
        $body = self::b64url(wp_json_encode($claims));
        $sig = hash_hmac('sha256', $head . '.' . $body, $key, true);
        return $head . '.' . $body . '.' . self::b64url($sig);
    }

    public static function decode_hs256($token, $key) {
        $parts = explode('.', (string) $token);
        if (count($parts) !== 3) return new WP_Error('jwt_malformed', 'Malformed JWT.');
        $header = json_decode(self::b64url_decode($parts[0]), true);
        $claims = json_decode(self::b64url_decode($parts[1]), true);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'HS256') return new WP_Error('jwt_unsupported', 'Unsupported JWT.');
        $expected = self::b64url(hash_hmac('sha256', $parts[0] . '.' . $parts[1], $key, true));
        if (!hash_equals($expected, $parts[2])) return new WP_Error('jwt_signature', 'Invalid JWT signature.');
        return $claims;
    }

    public static function encode_es256($claims, $private_key_pem, $kid) {
        if (!function_exists('openssl_sign')) return new WP_Error('openssl_missing', 'OpenSSL wird für Sign in with Apple benötigt.');
        $header = array('typ' => 'JWT', 'alg' => 'ES256', 'kid' => $kid);
        $head = self::b64url(wp_json_encode($header));
        $body = self::b64url(wp_json_encode($claims));
        $der = '';
        $ok = openssl_sign($head . '.' . $body, $der, $private_key_pem, OPENSSL_ALGO_SHA256);
        if (!$ok) return new WP_Error('apple_sign_failed', 'Apple Client Secret konnte nicht signiert werden.');
        $raw = self::ecdsa_der_to_raw($der, 32);
        if (is_wp_error($raw)) return $raw;
        return $head . '.' . $body . '.' . self::b64url($raw);
    }

    public static function verify_rs256_jwks($token, $jwks_url, $issuer = '', $audience = '') {
        $parts = explode('.', (string) $token);
        if (count($parts) !== 3) return new WP_Error('jwt_malformed', 'Malformed JWT.');
        $header = json_decode(self::b64url_decode($parts[0]), true);
        $claims = json_decode(self::b64url_decode($parts[1]), true);
        if (!is_array($header) || !is_array($claims) || ($header['alg'] ?? '') !== 'RS256' || empty($header['kid'])) return new WP_Error('jwt_unsupported', 'Unsupported JWT.');
        $cache_key = 'kornsw_ath_jwks_' . md5($jwks_url);
        $jwks = get_transient($cache_key);
        if (!is_array($jwks)) {
            $response = wp_remote_get($jwks_url, array('timeout' => 15));
            if (is_wp_error($response)) return $response;
            $jwks = json_decode((string) wp_remote_retrieve_body($response), true);
            if (!is_array($jwks)) return new WP_Error('jwks_invalid', 'JWKS konnte nicht gelesen werden.');
            set_transient($cache_key, $jwks, HOUR_IN_SECONDS);
        }
        $jwk = null;
        foreach (($jwks['keys'] ?? array()) as $candidate) {
            if (($candidate['kid'] ?? '') === $header['kid']) { $jwk = $candidate; break; }
        }
        if (!$jwk) { delete_transient($cache_key); return new WP_Error('jwks_key_missing', 'Passender JWT-Schlüssel wurde nicht gefunden.'); }
        $pem = self::rsa_jwk_to_pem($jwk);
        if (is_wp_error($pem)) return $pem;
        $verified = openssl_verify($parts[0] . '.' . $parts[1], self::b64url_decode($parts[2]), $pem, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) return new WP_Error('jwt_signature', 'Invalid JWT signature.');
        $now = time();
        if (isset($claims['exp']) && (int) $claims['exp'] < $now) return new WP_Error('jwt_expired', 'JWT ist abgelaufen.');
        if (isset($claims['nbf']) && (int) $claims['nbf'] > $now) return new WP_Error('jwt_not_yet_valid', 'JWT ist noch nicht gültig.');
        if ($issuer !== '' && ($claims['iss'] ?? '') !== $issuer) return new WP_Error('jwt_issuer', 'JWT issuer stimmt nicht.');
        if ($audience !== '') {
            $aud = $claims['aud'] ?? '';
            $valid_aud = is_array($aud) ? in_array($audience, $aud, true) : hash_equals((string) $aud, $audience);
            if (!$valid_aud) return new WP_Error('jwt_audience', 'JWT audience stimmt nicht.');
        }
        return $claims;
    }

    public static function b64url($value) { return rtrim(strtr(base64_encode((string) $value), '+/', '-_'), '='); }
    public static function b64url_decode($value) {
        $value = strtr((string) $value, '-_', '+/');
        $pad = strlen($value) % 4;
        if ($pad) $value .= str_repeat('=', 4 - $pad);
        return (string) base64_decode($value);
    }

    private static function rsa_jwk_to_pem($jwk) {
        if (empty($jwk['n']) || empty($jwk['e'])) return new WP_Error('jwk_invalid', 'RSA JWK unvollständig.');
        $modulus = self::b64url_decode($jwk['n']);
        $exponent = self::b64url_decode($jwk['e']);
        $rsa = self::asn1_sequence(self::asn1_integer($modulus) . self::asn1_integer($exponent));
        $alg = hex2bin('300d06092a864886f70d0101010500');
        $bitstring = "\x03" . self::asn1_length(strlen($rsa) + 1) . "\x00" . $rsa;
        $spki = self::asn1_sequence($alg . $bitstring);
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
    private static function asn1_integer($bytes) { if ((ord($bytes[0]) & 0x80) !== 0) $bytes = "\x00" . $bytes; return "\x02" . self::asn1_length(strlen($bytes)) . $bytes; }
    private static function asn1_sequence($bytes) { return "\x30" . self::asn1_length(strlen($bytes)) . $bytes; }
    private static function asn1_length($length) { if ($length < 128) return chr($length); $temp = ''; while ($length > 0) { $temp = chr($length & 0xff) . $temp; $length >>= 8; } return chr(0x80 | strlen($temp)) . $temp; }
    private static function ecdsa_der_to_raw($der, $part_length) {
        $offset = 0;
        if (ord($der[$offset++]) !== 0x30) return new WP_Error('ecdsa_der', 'Ungültige ECDSA-Signatur.');
        self::read_der_length($der, $offset);
        if (ord($der[$offset++]) !== 0x02) return new WP_Error('ecdsa_der', 'Ungültige ECDSA-Signatur.');
        $rlen = self::read_der_length($der, $offset); $r = substr($der, $offset, $rlen); $offset += $rlen;
        if (ord($der[$offset++]) !== 0x02) return new WP_Error('ecdsa_der', 'Ungültige ECDSA-Signatur.');
        $slen = self::read_der_length($der, $offset); $s = substr($der, $offset, $slen);
        $r = str_pad(ltrim($r, "\x00"), $part_length, "\x00", STR_PAD_LEFT);
        $s = str_pad(ltrim($s, "\x00"), $part_length, "\x00", STR_PAD_LEFT);
        return substr($r, -$part_length) . substr($s, -$part_length);
    }
    private static function read_der_length($der, &$offset) { $length = ord($der[$offset++]); if (($length & 0x80) === 0) return $length; $count = $length & 0x7f; $length = 0; for ($i = 0; $i < $count; $i++) $length = ($length << 8) | ord($der[$offset++]); return $length; }
}
