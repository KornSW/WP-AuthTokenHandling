<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_OAuth_Server_Config {
    const OPTION_ENABLED = 'kornsw_ath_oauth_server_enabled';
    const OPTION_CLIENTS = 'kornsw_ath_oauth_server_clients';
    const OPTION_ROLE_SCOPES = 'kornsw_ath_oauth_server_role_scopes';
    const OPTION_USER_SCOPES = 'kornsw_ath_oauth_server_user_scopes';

    public static function enabled(){ return get_option(self::OPTION_ENABLED, '0') === '1'; }
    public static function clients(){ $v=get_option(self::OPTION_CLIENTS,array()); return is_array($v)?$v:array(); }
    public static function get_client($client_id){ foreach(self::clients() as $client){ if(isset($client['client_id']) && hash_equals((string)$client['client_id'],(string)$client_id)) return $client; } return null; }
    public static function role_scopes(){ $v=get_option(self::OPTION_ROLE_SCOPES,array()); return is_array($v)?$v:array(); }
    public static function user_scopes(){ $v=get_option(self::OPTION_USER_SCOPES,array()); return is_array($v)?$v:array(); }
    public static function issuer(){ return untrailingslashit(home_url('/')); }
    public static function endpoint($action){ return admin_url('admin-post.php?action='.$action); }
    public static function authorize_endpoint(){ return self::endpoint('kornsw_ath_server_authorize'); }
    public static function token_endpoint(){ return self::endpoint('kornsw_ath_server_token'); }
    public static function introspection_endpoint(){ return self::endpoint('kornsw_ath_server_introspect'); }

    public static function save($post){
        update_option(self::OPTION_ENABLED, !empty($post['server_enabled'])?'1':'0', false);
        $clients=array();
        $titles=(array)($post['client_title']??array());
        $ids=(array)($post['client_id']??array());
        $secrets=(array)($post['client_secret']??array());
        $redirects=(array)($post['client_redirect']??array());
        $count=max(count($titles),count($ids),count($secrets),count($redirects));
        for($i=0;$i<$count;$i++){
            $id=sanitize_text_field(wp_unslash($ids[$i]??''));
            if($id==='') continue;
            $clients[]=array(
                'title'=>sanitize_text_field(wp_unslash($titles[$i]??$id)),
                'client_id'=>$id,
                'client_secret'=>((string)wp_unslash($secrets[$i]??''))!==''?(string)wp_unslash($secrets[$i]):rtrim(strtr(base64_encode(random_bytes(36)),'+/','-_'),'='),
                'redirect_uri'=>esc_url_raw(wp_unslash($redirects[$i]??''))
            );
        }
        update_option(self::OPTION_CLIENTS,$clients,false);

        $role_scopes=array();
        foreach((array)($post['role_scopes']??array()) as $role=>$scopes){
            $role=sanitize_key($role); if($role!=='') $role_scopes[$role]=self::normalize_scope_string(wp_unslash($scopes));
        }
        update_option(self::OPTION_ROLE_SCOPES,$role_scopes,false);

        $user_scopes=array();
        $users=(array)($post['scope_user']??array());
        $scopes=(array)($post['scope_user_scopes']??array());
        $count=max(count($users),count($scopes));
        for($i=0;$i<$count;$i++){
            $key=trim((string)wp_unslash($users[$i]??''));
            if($key==='') continue;
            $user=is_numeric($key)?get_user_by('id',(int)$key):get_user_by('email',sanitize_email($key));
            if(!$user) continue;
            $user_scopes[(string)$user->ID]=self::normalize_scope_string(wp_unslash($scopes[$i]??''));
        }
        update_option(self::OPTION_USER_SCOPES,$user_scopes,false);
    }

    public static function normalize_scope_string($value){ return implode(' ', KornSW_ATH_OAuth_Server_Scopes::normalize($value)); }
}
