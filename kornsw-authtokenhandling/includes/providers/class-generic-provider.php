<?php
if (!defined('ABSPATH')) { exit; }
final class KornSW_ATH_Generic_Provider extends KornSW_ATH_Provider_Base {
    public function invariant_name(){return 'generic';}
    public function display_title(){return 'Generic OAuth 2.0 / OIDC';}
    public function get_authorization_url($profile,$redirect_uri,$state,$verifier){
        $url=$this->config($profile,'authorization_endpoint',''); if ($url==='') return new WP_Error('missing_authorization_endpoint','authorization_endpoint fehlt.');
        $args=array('response_type'=>'code','client_id'=>$this->auth_config($profile,'ClientId',''),'redirect_uri'=>$redirect_uri,'state'=>$state,'code_challenge'=>$this->pkce_challenge($verifier),'code_challenge_method'=>'S256');
        $scopes=trim((string)$this->config($profile,'scopes','')); if ($scopes!=='') $args['scope']=$scopes;
        foreach($this->parse_args($this->auth_config($profile,'AdditionalAuthArgs','')) as $k=>$v){ if(!in_array($k,array('response_type','client_id','redirect_uri','state','code_challenge','code_challenge_method'),true))$args[$k]=$v; }
        return add_query_arg($args,$url);
    }
    public function exchange_authorization_code($profile,$code,$redirect_uri,$verifier){
        $url=$this->config($profile,'token_endpoint',''); if($url==='')return new WP_Error('missing_token_endpoint','token_endpoint fehlt.');
        $body=array('grant_type'=>'authorization_code','code'=>$code,'redirect_uri'=>$redirect_uri,'client_id'=>$this->auth_config($profile,'ClientId',''),'code_verifier'=>$verifier);
        $secret=(string)$this->auth_config($profile,'ClientSecret',''); if($secret!=='')$body['client_secret']=$secret;
        foreach($this->parse_args($this->auth_config($profile,'AdditionalRetrieveArgs','')) as $k=>$v){if(!array_key_exists($k,$body))$body[$k]=$v;}
        return $this->normalize_token_result($this->post_form($url,$body,array('Accept'=>'application/json')));
    }
    public function refresh_access_token($profile,$refresh_token){
        if(!$this->has_capability($profile,'refresh_token'))return new WP_Error('refresh_unsupported','Provider unterstützt laut Profil kein Refresh Token.');
        $url=$this->config($profile,'token_endpoint',''); $body=array('grant_type'=>'refresh_token','refresh_token'=>$refresh_token,'client_id'=>$this->auth_config($profile,'ClientId',''));
        $secret=(string)$this->auth_config($profile,'ClientSecret',''); if($secret!=='')$body['client_secret']=$secret;
        return $this->normalize_token_result($this->post_form($url,$body,array('Accept'=>'application/json')));
    }
    public function validate_token($profile,$access_token){
        $cached=$this->validation_cache_get($profile,$access_token); if($cached!==false)return $cached;
        $mode=(string)$this->auth_config($profile,'ValidationMode','IMPLICIT_WHEN_USED');
        if($mode==='IMPLICIT_WHEN_USED')return array('technical_success'=>true,'active'=>true,'valid_until'=>null,'reason'=>null,'claims'=>array());
        if($mode==='LOCAL_JWT_VALIDATION')return KornSW_ATH_Introspector_Factory::local_jwt_validate($profile,$access_token);
        $url=$this->config($profile,'introspection_endpoint',$this->auth_config($profile,'ValidationEndpointUrl','')); if($url==='')return array('technical_success'=>false,'active'=>false,'reason'=>'introspection_endpoint fehlt','claims'=>array());
        $headers=array('Accept'=>'application/json'); $auth=(string)$this->auth_config($profile,'validationEndpointAuthorization',''); if($auth==='')$auth=(string)$this->config($profile,'introspection_authorization',''); if($auth!=='')$headers['Authorization']=$auth;
        if($mode==='OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY')$data=$this->get_json(add_query_arg('token',rawurlencode($access_token),$url),$headers); else $data=$this->post_form($url,array('token'=>$access_token),$headers);
        if(is_wp_error($data))return array('technical_success'=>false,'active'=>false,'reason'=>$data->get_error_message(),'claims'=>array());
        $active=isset($data['active'])?filter_var($data['active'],FILTER_VALIDATE_BOOLEAN):false;
        $result=array('technical_success'=>true,'active'=>$active,'valid_until'=>isset($data['exp'])?(int)$data['exp']:null,'reason'=>$active?null:(string)($data['error_description'] ?? 'inactive'),'claims'=>$data);
        $this->validation_cache_set($profile,$access_token,$result); return $result;
    }
    public function resolve_identity($profile,$access_token,$id_token=''){
        $url=$this->config($profile,'userinfo_endpoint','');
        if($url!==''){$data=$this->get_json($url,array('Authorization'=>'Bearer '.$access_token,'Accept'=>'application/json'));if(!is_wp_error($data)){return $this->identity_from_claims($data);}}
        $validation=$this->validate_token($profile,$access_token); if(!empty($validation['technical_success'])&&!empty($validation['active']))return $this->identity_from_claims($validation['claims']);
        return new WP_Error('identity_unresolved','Subject konnte weder über UserInfo noch Introspection aufgelöst werden.');
    }
    private function identity_from_claims($c){$sub=(string)($c['sub']??$c['id']??'');if($sub==='')return new WP_Error('missing_subject','Provider liefert keinen stabilen Subject-Identifier.');return array('subject'=>$sub,'email'=>(string)($c['email']??''),'given_name'=>(string)($c['given_name']??''),'family_name'=>(string)($c['family_name']??''),'display_name'=>(string)($c['name']??$c['preferred_username']??$c['login']??''),'claims'=>$c);}
    public function has_capability($profile,$name){$pc=$profile['ProviderConfiguration']??array(); if($name==='introspection')return $this->config($profile,'introspection_endpoint','')!==''; return !empty($pc['supports_'.$name]);}
}
