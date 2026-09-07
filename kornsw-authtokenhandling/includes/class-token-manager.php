<?php
if (!defined('ABSPATH')) { exit; }
final class KornSW_ATH_Token_Manager {
    public static function try_get_access_token($source_uid,$user_id=0,$options=array()){
        $profile=KornSW_ATH_Config_Repository::get_profile($source_uid);if(!$profile)return self::result('SOURCE_NOT_FOUND');if(isset($profile['Enabled'])&&!$profile['Enabled'])return self::result('SOURCE_DISABLED');
        if(!$user_id)$user_id=get_current_user_id();if(!$user_id)return self::result('USER_NOT_LOGGED_IN');
        $prefer_session=($source_uid===KornSW_ATH_Config_Repository::get_primary_source_uid());$token=KornSW_ATH_Storage::get_token_set($user_id,$source_uid,$prefer_session);if(is_wp_error($token))return self::result('ERROR',array('error'=>$token));
        if(!$token){
            $mode=(string)(($profile['AuthTokenConfig']??array())['IssueMode']??'RAW_INPUT');
            if($mode==='LOCAL_JWT_GENERATION'){$user=get_user_by('id',$user_id);$issuer=new KornSW_ATH_Local_JWT_Issuer($profile,$user);$issued=$issuer->try_request_access_token();if(is_wp_error($issued))return self::result('ERROR',array('error'=>$issued));$scope=$prefer_session?'session':'persistent';$sh=$scope==='session'?KornSW_ATH_Storage::session_hash():'';KornSW_ATH_Storage::save_token_set($user_id,$source_uid,$scope,$sh,$issued);$token=KornSW_ATH_Storage::get_token_set($user_id,$source_uid,$prefer_session);} else return self::result('AUTHENTICATION_REQUIRED');
        }
        $validated=self::validate_token_set($profile,$token,$user_id,$source_uid);
        if($validated['status']==='SUCCESS')return $validated;
        if($validated['status']==='AUTHENTICATION_REQUIRED')return $validated;
        return $validated;
    }

    private static function validate_token_set($profile,$token,$user_id,$source_uid){
        if(!empty($token['expires_at'])&&strtotime($token['expires_at'].' UTC')<=time()+30){$ref=self::try_refresh($profile,$token,$user_id,$source_uid);if($ref['status']!=='SUCCESS')return self::result('AUTHENTICATION_REQUIRED');$token=$ref['token_set'];}
        $v=KornSW_ATH_Introspector_Factory::validate($profile,$token['access_token']);
        if(empty($v['technical_success']))return self::result('VALIDATION_UNAVAILABLE',array('validation'=>$v));
        if(empty($v['active'])){$ref=self::try_refresh($profile,$token,$user_id,$source_uid);if($ref['status']==='SUCCESS'){$token=$ref['token_set'];$v=KornSW_ATH_Introspector_Factory::validate($profile,$token['access_token']);if(!empty($v['technical_success'])&&!empty($v['active']))return self::success($token,$v);}return self::result('AUTHENTICATION_REQUIRED',array('validation'=>$v));}
        return self::success($token,$v);
    }

    private static function try_refresh($profile,$token,$user_id,$source_uid){if(empty($token['refresh_token']))return self::result('AUTHENTICATION_REQUIRED');$lock='kornsw_ath_refresh_'.md5($user_id.'|'.$source_uid.'|'.($token['session_hash']??''));if(!self::acquire_lock($lock)){usleep(200000);$fresh=KornSW_ATH_Storage::get_token_set($user_id,$source_uid,true);return $fresh?array('status'=>'SUCCESS','token_set'=>$fresh):self::result('AUTHENTICATION_REQUIRED');}try{$provider=KornSW_ATH_Provider_Registry::get_for_profile($profile);if(is_wp_error($provider))return self::result('ERROR',array('error'=>$provider));$r=$provider->refresh_access_token($profile,$token['refresh_token']);if(is_wp_error($r))return self::result('AUTHENTICATION_REQUIRED',array('error'=>$r));if(empty($r['refresh_token']))$r['refresh_token']=$token['refresh_token'];$scope=$token['storage_scope'];$sh=$token['session_hash'];KornSW_ATH_Storage::save_token_set($user_id,$source_uid,$scope,$sh,$r,$token['claims']);$fresh=KornSW_ATH_Storage::get_token_set($user_id,$source_uid,$scope==='session');do_action('kornsw_authtokenhandling_token_refreshed',$source_uid,$user_id);return array('status'=>'SUCCESS','token_set'=>$fresh);}finally{delete_option($lock);}}
    private static function acquire_lock($name){$created=add_option($name,time(),'','no');if($created)return true;$old=(int)get_option($name,0);if($old<time()-30){delete_option($name);return add_option($name,time(),'','no');}return false;}
    private static function success($token,$validation){return self::result('SUCCESS',array('access_token'=>$token['access_token'],'token_type'=>$token['token_type']?:'Bearer','expires_at'=>$token['expires_at'],'scopes'=>$token['scopes'],'claims'=>array_merge($token['claims'],$validation['claims']??array()),'token_set'=>$token));}
    private static function result($status,$extra=array()){return array_merge(array('status'=>$status,'access_token'=>null),$extra);}
    public static function require_access_token($source_uid,$options=array()){$r=self::try_get_access_token($source_uid,0,$options);if($r['status']==='SUCCESS')return $r['access_token'];if($r['status']==='AUTHENTICATION_REQUIRED' && KornSW_ATH_OAuth_Flow::is_interactive_request()){$return=$options['return_url']??KornSW_ATH_OAuth_Flow::current_url();KornSW_ATH_OAuth_Flow::start($source_uid,$return,'api',$options);}return new WP_Error(strtolower($r['status']),$r['status'],$r);}
    public static function authorized_request($source_uid,$url,$options=array()){$profile=KornSW_ATH_Config_Repository::get_profile($source_uid);if(!$profile)return new WP_Error('source_not_found','Token Source nicht gefunden.');if(!self::is_target_allowed($profile,$url))return new WP_Error('target_not_allowed','Zielhost ist für diese Token Source nicht freigegeben.');$token=self::require_access_token($source_uid,array('return_url'=>$options['return_url']??null));if(is_wp_error($token))return $token;$headers=is_array($options['headers']??null)?$options['headers']:array();$headers['Authorization']='Bearer '.$token;$options['headers']=$headers;$response=wp_remote_request($url,$options);if(!is_wp_error($response)&&(int)wp_remote_retrieve_response_code($response)===401){delete_transient('kornsw_ath_val_'.md5($source_uid.'|'.$token));$retry=self::try_get_access_token($source_uid);if($retry['status']==='SUCCESS' && $retry['access_token']!==$token){$options['headers']['Authorization']='Bearer '.$retry['access_token'];$response=wp_remote_request($url,$options);}}return $response;}
    private static function is_target_allowed($profile,$url){$allowed=$profile['AllowedResourceHosts']??array();if(!$allowed)return true;$host=wp_parse_url($url,PHP_URL_HOST);return $host && in_array(strtolower($host),array_map('strtolower',$allowed),true);}
}
