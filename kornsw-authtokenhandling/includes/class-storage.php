<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Storage {
    public static function tables() {
        global $wpdb;
        return array(
            'connections' => $wpdb->prefix . 'kornsw_ath_connections',
            'token_sets' => $wpdb->prefix . 'kornsw_ath_token_sets',
            'bindings' => $wpdb->prefix . 'kornsw_ath_session_bindings',
            'continuations' => $wpdb->prefix . 'kornsw_ath_continuations'
        );
    }

    public static function install() {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $t = self::tables();
        $charset = $wpdb->get_charset_collate();
        dbDelta("CREATE TABLE {$t['connections']} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            source_uid VARCHAR(64) NOT NULL,
            subject VARCHAR(255) NOT NULL,
            email VARCHAR(320) NULL,
            display_name VARCHAR(255) NULL,
            claims_json LONGTEXT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY source_subject (source_uid, subject),
            UNIQUE KEY user_source (user_id, source_uid),
            KEY user_id (user_id)
        ) $charset;");
        dbDelta("CREATE TABLE {$t['token_sets']} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            source_uid VARCHAR(64) NOT NULL,
            storage_scope VARCHAR(20) NOT NULL,
            session_hash VARCHAR(64) NOT NULL DEFAULT '',
            access_token LONGTEXT NOT NULL,
            refresh_token LONGTEXT NULL,
            id_token LONGTEXT NULL,
            token_type VARCHAR(40) NULL,
            scopes_json LONGTEXT NULL,
            claims_json LONGTEXT NULL,
            expires_at DATETIME NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY scoped_token (user_id, source_uid, storage_scope, session_hash),
            KEY source_user (source_uid, user_id)
        ) $charset;");
        dbDelta("CREATE TABLE {$t['bindings']} (
            user_id BIGINT UNSIGNED NOT NULL,
            session_hash VARCHAR(64) NOT NULL,
            source_uid VARCHAR(64) NOT NULL DEFAULT '',
            bypass_primary TINYINT(1) NOT NULL DEFAULT 0,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (user_id, session_hash)
        ) $charset;");
        dbDelta("CREATE TABLE {$t['continuations']} (
            continuation_id VARCHAR(64) NOT NULL,
            state_hash VARCHAR(64) NOT NULL,
            source_uid VARCHAR(64) NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            session_hash VARCHAR(64) NOT NULL DEFAULT '',
            purpose VARCHAR(40) NOT NULL,
            return_url TEXT NOT NULL,
            payload_json LONGTEXT NULL,
            verifier_enc LONGTEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (continuation_id),
            UNIQUE KEY state_hash (state_hash),
            KEY expires_at (expires_at)
        ) $charset;");
    }

    public static function session_hash() {
        if (!is_user_logged_in()) { return ''; }
        $token = wp_get_session_token();
        if ($token === '') { return ''; }
        return hash_hmac('sha256', $token, wp_salt('auth'));
    }

    public static function get_connection($user_id, $source_uid) {
        global $wpdb; $t = self::tables();
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['connections']} WHERE user_id=%d AND source_uid=%s", $user_id, $source_uid), ARRAY_A);
    }

    public static function get_connection_by_subject($source_uid, $subject) {
        global $wpdb; $t = self::tables();
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['connections']} WHERE source_uid=%s AND subject=%s", $source_uid, $subject), ARRAY_A);
    }

    public static function upsert_connection($user_id, $source_uid, $identity) {
        global $wpdb; $t = self::tables(); $now = current_time('mysql', true);
        $existing = self::get_connection($user_id, $source_uid);
        $data = array(
            'user_id'=>$user_id, 'source_uid'=>$source_uid,
            'subject'=>(string) ($identity['subject'] ?? ''),
            'email'=>(string) ($identity['email'] ?? ''),
            'display_name'=>(string) ($identity['display_name'] ?? ''),
            'claims_json'=>wp_json_encode($identity['claims'] ?? array()),
            'updated_at'=>$now
        );
        if ($existing) {
            $wpdb->update($t['connections'], $data, array('id'=>$existing['id']));
            return (int) $existing['id'];
        }
        $data['created_at']=$now;
        $ok=$wpdb->insert($t['connections'],$data);
        return $ok ? (int)$wpdb->insert_id : new WP_Error('connection_store_failed', $wpdb->last_error ?: 'Connection konnte nicht gespeichert werden.');
    }

    public static function save_token_set($user_id, $source_uid, $scope, $session_hash, $token_result, $claims=array()) {
        global $wpdb; $t=self::tables();
        $access=KornSW_ATH_Crypto::encrypt((string)($token_result['access_token'] ?? ''));
        $refresh=KornSW_ATH_Crypto::encrypt((string)($token_result['refresh_token'] ?? ''));
        $id=KornSW_ATH_Crypto::encrypt((string)($token_result['id_token'] ?? ''));
        if (is_wp_error($access) || is_wp_error($refresh) || is_wp_error($id)) { return new WP_Error('token_encrypt_failed','Tokenverschlüsselung fehlgeschlagen.'); }
        $expires_at=null;
        if (!empty($token_result['expires_in']) && is_numeric($token_result['expires_in'])) {
            $expires_at=gmdate('Y-m-d H:i:s', time() + max(0,(int)$token_result['expires_in']));
        } elseif (!empty($token_result['expires_at'])) {
            $expires_at=gmdate('Y-m-d H:i:s',(int)$token_result['expires_at']);
        }
        $data=array(
            'user_id'=>$user_id,'source_uid'=>$source_uid,'storage_scope'=>$scope,'session_hash'=>$session_hash,
            'access_token'=>$access,'refresh_token'=>$refresh,'id_token'=>$id,
            'token_type'=>(string)($token_result['token_type'] ?? 'Bearer'),
            'scopes_json'=>wp_json_encode(self::normalize_scopes($token_result['scope'] ?? array())),
            'claims_json'=>wp_json_encode($claims),'expires_at'=>$expires_at,'updated_at'=>current_time('mysql',true)
        );
        $existing=$wpdb->get_var($wpdb->prepare("SELECT id FROM {$t['token_sets']} WHERE user_id=%d AND source_uid=%s AND storage_scope=%s AND session_hash=%s",$user_id,$source_uid,$scope,$session_hash));
        if ($existing) { $wpdb->update($t['token_sets'],$data,array('id'=>$existing)); return (int)$existing; }
        $ok=$wpdb->insert($t['token_sets'],$data); return $ok ? (int)$wpdb->insert_id : new WP_Error('token_store_failed',$wpdb->last_error ?: 'Token konnte nicht gespeichert werden.');
    }

    private static function normalize_scopes($scope) {
        if (is_array($scope)) { return array_values(array_filter(array_map('strval',$scope))); }
        if (!is_string($scope) || trim($scope)==='') { return array(); }
        return preg_split('/[\s,]+/', trim($scope), -1, PREG_SPLIT_NO_EMPTY);
    }

    public static function get_token_set($user_id,$source_uid,$prefer_session=true) {
        global $wpdb; $t=self::tables(); $row=null;
        if ($prefer_session) {
            $sh=self::session_hash();
            if ($sh!=='') $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['token_sets']} WHERE user_id=%d AND source_uid=%s AND storage_scope='session' AND session_hash=%s",$user_id,$source_uid,$sh),ARRAY_A);
        }
        if (!$row) $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['token_sets']} WHERE user_id=%d AND source_uid=%s AND storage_scope='persistent' AND session_hash=''",$user_id,$source_uid),ARRAY_A);
        if (!$row) return null;
        foreach (array('access_token','refresh_token','id_token') as $field) {
            $plain=KornSW_ATH_Crypto::decrypt($row[$field]); if (is_wp_error($plain)) return $plain; $row[$field]=$plain;
        }
        $row['scopes']=json_decode((string)$row['scopes_json'],true) ?: array();
        $row['claims']=json_decode((string)$row['claims_json'],true) ?: array();
        return $row;
    }

    public static function delete_token_set($user_id,$source_uid) {
        global $wpdb; $t=self::tables();
        return $wpdb->delete($t['token_sets'],array('user_id'=>$user_id,'source_uid'=>$source_uid));
    }

    public static function set_binding($user_id,$source_uid,$bypass=false) {
        global $wpdb; $t=self::tables(); $sh=self::session_hash(); if ($sh==='') return false;
        return false !== $wpdb->replace($t['bindings'],array('user_id'=>$user_id,'session_hash'=>$sh,'source_uid'=>$source_uid,'bypass_primary'=>$bypass?1:0,'updated_at'=>current_time('mysql',true)));
    }

    public static function get_binding($user_id) {
        global $wpdb; $t=self::tables(); $sh=self::session_hash(); if ($sh==='') return null;
        return $wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['bindings']} WHERE user_id=%d AND session_hash=%s",$user_id,$sh),ARRAY_A);
    }

    public static function create_continuation($source_uid,$user_id,$purpose,$return_url,$payload=array()) {
        global $wpdb; $t=self::tables();
        $id=bin2hex(random_bytes(24)); $state=bin2hex(random_bytes(32)); $verifier=rtrim(strtr(base64_encode(random_bytes(48)),'+/','-_'),'=');
        $enc=KornSW_ATH_Crypto::encrypt($verifier); if (is_wp_error($enc)) return $enc;
        $expires=gmdate('Y-m-d H:i:s',time()+10*MINUTE_IN_SECONDS);
        $ok=$wpdb->insert($t['continuations'],array(
            'continuation_id'=>$id,'state_hash'=>hash('sha256',$state),'source_uid'=>$source_uid,'user_id'=>$user_id,
            'session_hash'=>$user_id?self::session_hash():'','purpose'=>$purpose,'return_url'=>$return_url,
            'payload_json'=>wp_json_encode($payload),'verifier_enc'=>$enc,'expires_at'=>$expires,'created_at'=>current_time('mysql',true)
        ));
        if (!$ok) return new WP_Error('continuation_store_failed',$wpdb->last_error ?: 'Continuation konnte nicht gespeichert werden.');
        return array('id'=>$id,'state'=>$state,'verifier'=>$verifier);
    }

    public static function consume_continuation_by_state($state) {
        global $wpdb; $t=self::tables();
        $row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$t['continuations']} WHERE state_hash=%s",hash('sha256',(string)$state)),ARRAY_A);
        if (!$row) return new WP_Error('invalid_state','OAuth-State ist unbekannt oder wurde bereits verbraucht.');
        $wpdb->delete($t['continuations'],array('continuation_id'=>$row['continuation_id']));
        if (strtotime($row['expires_at'].' UTC') < time()) return new WP_Error('expired_state','OAuth-State ist abgelaufen.');
        $verifier=KornSW_ATH_Crypto::decrypt($row['verifier_enc']); if (is_wp_error($verifier)) return $verifier;
        $row['verifier']=$verifier; $row['payload']=json_decode((string)$row['payload_json'],true) ?: array();
        return $row;
    }
}
