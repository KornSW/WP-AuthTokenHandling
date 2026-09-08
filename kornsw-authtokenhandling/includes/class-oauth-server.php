<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_OAuth_Server {
    public static function register_hooks(){
        foreach(array('kornsw_ath_server_authorize'=>'authorize','kornsw_ath_server_token'=>'token','kornsw_ath_server_introspect'=>'introspect') as $action=>$method){
            add_action('admin_post_'.$action,array(__CLASS__,$method));
            add_action('admin_post_nopriv_'.$action,array(__CLASS__,$method));
        }
    }

    public static function authorize(){
        if(!KornSW_ATH_OAuth_Server_Config::enabled()) self::oauth_error('server_disabled','OAuth-Server ist deaktiviert.',503);
        if(!empty($_GET['txn'])){
            $txn=sanitize_text_field(wp_unslash($_GET['txn']));
            $request=get_transient('kornsw_ath_srvtxn_'.$txn);
            if(!is_array($request)) self::oauth_error('transaction_expired','Authorization-Transaktion ist abgelaufen.',400);
        } else {
            $request=array(
                'response_type'=>sanitize_text_field(wp_unslash($_GET['response_type']??'')),
                'client_id'=>sanitize_text_field(wp_unslash($_GET['client_id']??'')),
                'redirect_uri'=>esc_url_raw(wp_unslash($_GET['redirect_uri']??'')),
                'state'=>sanitize_text_field(wp_unslash($_GET['state']??'')),
                'scope'=>(string)wp_unslash($_GET['scope']??''),
                'code_challenge'=>sanitize_text_field(wp_unslash($_GET['code_challenge']??'')),
                'code_challenge_method'=>sanitize_text_field(wp_unslash($_GET['code_challenge_method']??'')),
                'nonce'=>sanitize_text_field(wp_unslash($_GET['nonce']??''))
            );
            $txn=bin2hex(random_bytes(20));
            set_transient('kornsw_ath_srvtxn_'.$txn,$request,10*MINUTE_IN_SECONDS);
        }
        $client=KornSW_ATH_OAuth_Server_Config::get_client($request['client_id']);
        if(!$client) self::oauth_error('invalid_client','Unbekannte ClientId.',401);
        if(!self::redirect_matches((string)$client['redirect_uri'],$request['redirect_uri'])) self::oauth_error('invalid_redirect_uri','Redirect URI ist für diesen Client nicht freigegeben.',400);
        if($request['response_type']!=='code') self::redirect_error($request,'unsupported_response_type','Nur response_type=code wird unterstützt.');
        if($request['code_challenge']!=='' && $request['code_challenge_method']!=='S256') self::redirect_error($request,'invalid_request','Nur PKCE S256 wird unterstützt.');

        if(!is_user_logged_in()){
            $resume=add_query_arg(array('action'=>'kornsw_ath_server_authorize','txn'=>$txn),admin_url('admin-post.php'));
            wp_safe_redirect(wp_login_url($resume)); exit;
        }

        $user=wp_get_current_user();
        if(!$user->ID || sanitize_email($user->user_email)==='') self::redirect_error($request,'access_denied','Der WordPress-Benutzer besitzt keine nutzbare E-Mail-Adresse.');
        $code=KornSW_ATH_Storage::create_server_code($request['client_id'],$user->ID,$request['redirect_uri'],$request['scope'],$request['code_challenge'],$request['nonce']);
        if(is_wp_error($code)) self::redirect_error($request,'server_error',$code->get_error_message());
        delete_transient('kornsw_ath_srvtxn_'.$txn);
        $target=add_query_arg(array('code'=>$code,'state'=>$request['state']),$request['redirect_uri']);
        wp_redirect($target,302); exit;
    }

    public static function token(){
        if(!KornSW_ATH_OAuth_Server_Config::enabled()) self::json(array('error'=>'server_disabled'),503);
        $client=self::authenticate_client(); if(is_wp_error($client)) self::json(array('error'=>'invalid_client','error_description'=>$client->get_error_message()),401);
        $grant=sanitize_text_field(wp_unslash($_POST['grant_type']??''));
        if($grant==='authorization_code'){
            $code=sanitize_text_field(wp_unslash($_POST['code']??''));
            $row=KornSW_ATH_Storage::consume_server_code($code);
            if(is_wp_error($row)) self::json(array('error'=>'invalid_grant','error_description'=>$row->get_error_message()),400);
            if(!hash_equals((string)$row['client_id'],(string)$client['client_id'])) self::json(array('error'=>'invalid_grant'),400);
            $redirect=esc_url_raw(wp_unslash($_POST['redirect_uri']??''));
            if(!hash_equals((string)$row['redirect_uri'],$redirect)) self::json(array('error'=>'invalid_grant','error_description'=>'redirect_uri stimmt nicht.'),400);
            if((string)$row['code_challenge']!==''){
                $verifier=(string)wp_unslash($_POST['code_verifier']??'');
                $challenge=rtrim(strtr(base64_encode(hash('sha256',$verifier,true)),'+/','-_'),'=');
                if(!hash_equals((string)$row['code_challenge'],$challenge)) self::json(array('error'=>'invalid_grant','error_description'=>'PKCE verification failed.'),400);
            }
            $issued=self::issue_tokens($client,(int)$row['user_id'],(string)$row['requested_scope'],(string)$row['nonce']);self::json($issued,isset($issued['error'])?500:200);
        }
        if($grant==='refresh_token'){
            $refresh=(string)wp_unslash($_POST['refresh_token']??'');
            $row=KornSW_ATH_Storage::consume_server_refresh_token($refresh,(string)$client['client_id']);
            if(is_wp_error($row)) self::json(array('error'=>'invalid_grant','error_description'=>$row->get_error_message()),400);
            $issued=self::issue_tokens($client,(int)$row['user_id'],(string)$row['requested_scope'],'',true);self::json($issued,isset($issued['error'])?500:200);
        }
        self::json(array('error'=>'unsupported_grant_type'),400);
    }

    public static function introspect(){
        if(!KornSW_ATH_OAuth_Server_Config::enabled()) self::json(array('active'=>false),200);
        $client=self::authenticate_client(); if(is_wp_error($client)) self::json(array('error'=>'invalid_client'),401);
        $token=(string)wp_unslash($_POST['token']??'');
        $claims=KornSW_ATH_JWT_Helper::decode_hs256($token,self::client_signing_key($client));
        if(is_wp_error($claims)) self::json(array('active'=>false),200);
        $now=time();
        if(($claims['aud']??'')!==(string)$client['client_id'] || (int)($claims['exp']??0)<=$now || ($claims['iss']??'')!==KornSW_ATH_OAuth_Server_Config::issuer()) self::json(array('active'=>false),200);
        $email=sanitize_email((string)($claims['sub']??''));
        $user=$email!==''?get_user_by('email',$email):false;
        if(!$user) self::json(array('active'=>false),200);
        $current_scopes=KornSW_ATH_OAuth_Server_Scopes::resolve($user->ID,(string)$client['client_id'],array(),array('phase'=>'introspection','token_claims'=>$claims));
        $result=$claims;
        $result['active']=true;
        $result['scope']=implode(' ',$current_scopes);
        $result['email']=$user->user_email;
        $result['given_name']=get_user_meta($user->ID,'first_name',true);
        $result['family_name']=get_user_meta($user->ID,'last_name',true);
        $result['name']=$user->display_name;
        self::json($result,200);
    }

    private static function issue_tokens($client,$user_id,$requested_scope,$nonce='',$is_refresh=false){
        $user=get_user_by('id',$user_id);
        if(!$user || sanitize_email($user->user_email)==='') return array('error'=>'invalid_grant','error_description'=>'Benutzer ist nicht verfügbar.');
        $requested=KornSW_ATH_OAuth_Server_Scopes::normalize($requested_scope);
        $context=array('phase'=>$is_refresh?'refresh':'issue','requested_scopes'=>$requested);
        $scopes=KornSW_ATH_OAuth_Server_Scopes::resolve($user_id,(string)$client['client_id'],$requested,$context);
        $now=time(); $exp=$now+HOUR_IN_SECONDS;
        $base=array('iss'=>KornSW_ATH_OAuth_Server_Config::issuer(),'sub'=>$user->user_email,'aud'=>(string)$client['client_id'],'iat'=>$now,'nbf'=>$now,'exp'=>$exp,'jti'=>wp_generate_uuid4(),'scope'=>implode(' ',$scopes));
        $extra=apply_filters('kornsw_authtokenhandling_token_claims',array(),$user_id,(string)$client['client_id'],'access_token',$context);
        if(!is_array($extra)) $extra=array();
        $claims=array_merge($extra,$base);
        foreach(array('iss','sub','aud','iat','nbf','exp','jti','scope') as $protected) $claims[$protected]=$base[$protected];
        $key=self::client_signing_key($client);
        $access=KornSW_ATH_JWT_Helper::encode_hs256($claims,$key);

        $id_base=array('iss'=>$base['iss'],'sub'=>$base['sub'],'aud'=>$base['aud'],'iat'=>$now,'exp'=>$exp,'email'=>$user->user_email,'name'=>$user->display_name,'given_name'=>get_user_meta($user_id,'first_name',true),'family_name'=>get_user_meta($user_id,'last_name',true));
        if($nonce!=='') $id_base['nonce']=$nonce;
        $id_extra=apply_filters('kornsw_authtokenhandling_token_claims',array(),$user_id,(string)$client['client_id'],'id_token',$context);
        if(!is_array($id_extra)) $id_extra=array();
        $id_claims=array_merge($id_extra,$id_base);
        foreach(array_keys($id_base) as $protected) $id_claims[$protected]=$id_base[$protected];
        $id_token=KornSW_ATH_JWT_Helper::encode_hs256($id_claims,$key);
        $refresh=KornSW_ATH_Storage::create_server_refresh_token((string)$client['client_id'],$user_id,implode(' ',$requested));
        if(is_wp_error($refresh)) return array('error'=>'server_error','error_description'=>$refresh->get_error_message());
        return array('access_token'=>$access,'token_type'=>'Bearer','expires_in'=>HOUR_IN_SECONDS,'refresh_token'=>$refresh,'id_token'=>$id_token,'scope'=>implode(' ',$scopes));
    }

    private static function authenticate_client(){
        $client_id=sanitize_text_field(wp_unslash($_POST['client_id']??''));
        $client_secret=(string)wp_unslash($_POST['client_secret']??'');
        $auth=(string)($_SERVER['HTTP_AUTHORIZATION']??'');
        if(str_starts_with($auth,'Basic ')){
            $decoded=base64_decode(substr($auth,6),true);
            if(is_string($decoded) && str_contains($decoded,':')) list($client_id,$client_secret)=explode(':',$decoded,2);
        }
        $client=KornSW_ATH_OAuth_Server_Config::get_client($client_id);
        if(!$client || !hash_equals((string)$client['client_secret'],$client_secret)) return new WP_Error('invalid_client','Client credentials stimmen nicht.');
        return $client;
    }

    private static function client_signing_key($client){ return hash_hmac('sha256',(string)$client['client_secret'],wp_salt('auth')); }

    private static function redirect_matches($mask,$actual){
        $mask=trim((string)$mask); $actual=trim((string)$actual);
        if($mask===''||$actual==='') return false;
        if(!str_contains($mask,'*')) return hash_equals($mask,$actual);
        $mp=wp_parse_url($mask); $ap=wp_parse_url($actual);
        if(!$mp||!$ap||str_contains((string)($mp['scheme']??''),'*')||str_contains((string)($mp['host']??''),'*')) return false;
        if(strtolower((string)($mp['scheme']??''))!==strtolower((string)($ap['scheme']??'')) || strtolower((string)($mp['host']??''))!==strtolower((string)($ap['host']??''))) return false;
        $quoted=preg_quote($mask,'~'); $regex='~^'.str_replace('\\*','.*',$quoted).'$~';
        return (bool)preg_match($regex,$actual);
    }

    private static function redirect_error($request,$error,$description){ if(!empty($request['redirect_uri'])){ $url=add_query_arg(array('error'=>$error,'error_description'=>$description,'state'=>$request['state']??''),$request['redirect_uri']); wp_redirect($url,302); exit; } self::oauth_error($error,$description,400); }
    private static function oauth_error($error,$description,$status){ status_header($status); wp_die(esc_html($description),esc_html($error),array('response'=>$status)); }
    private static function json($data,$status){ status_header($status); nocache_headers(); header('Content-Type: application/json; charset=utf-8'); echo wp_json_encode($data); exit; }
}
