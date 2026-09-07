<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Crypto {
    private static function key() {
        $material = (defined('AUTH_KEY') ? AUTH_KEY : '') . '|' . (defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : '') . '|kornsw-ath-v1';
        return hash('sha256', $material, true);
    }

    public static function encrypt($plain) {
        if ($plain === null || $plain === '') { return ''; }
        if (!function_exists('openssl_encrypt')) { return new WP_Error('openssl_missing', 'OpenSSL wird für die Tokenverschlüsselung benötigt.'); }
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt((string) $plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($cipher === false) { return new WP_Error('encrypt_failed', 'Token konnte nicht verschlüsselt werden.'); }
        return base64_encode($iv . $tag . $cipher);
    }

    public static function decrypt($encoded) {
        if ($encoded === null || $encoded === '') { return ''; }
        $raw = base64_decode((string) $encoded, true);
        if ($raw === false || strlen($raw) < 29) { return new WP_Error('decrypt_invalid', 'Ungültiges verschlüsseltes Tokenformat.'); }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($plain === false) { return new WP_Error('decrypt_failed', 'Token konnte nicht entschlüsselt werden.'); }
        return $plain;
    }
}
