<?php
if (!defined('ABSPATH')) { exit; }
abstract class KornSW_ATH_Provider_Base implements KornSW_ATH_IOAuth_Operations_Provider {
    protected function config($profile,$name,$default='') {
        $pc=is_array($profile['ProviderConfiguration'] ?? null)?$profile['ProviderConfiguration']:array();
        if (array_key_exists($name,$pc)) return $pc[$name];
        $ac=is_array($profile['AuthTokenConfig'] ?? null)?$profile['AuthTokenConfig']:array();
        $legacy=array('authorization_endpoint'=>'AuthEndpointUrl','token_endpoint'=>'RetrieveEndpointUrl','introspection_endpoint'=>'ValidationEndpointUrl');
        if (isset($legacy[$name]) && !empty($ac[$legacy[$name]])) return $ac[$legacy[$name]];
        return $default;
    }
    protected function auth_config($profile,$name,$default='') {
        $ac=is_array($profile['AuthTokenConfig'] ?? null)?$profile['AuthTokenConfig']:array();
        return array_key_exists($name,$ac)?$ac[$name]:$default;
    }
    protected function pkce_challenge($verifier) { return rtrim(strtr(base64_encode(hash('sha256',$verifier,true)),'+/','-_'),'='); }
    protected function parse_args($value) {
        if (is_array($value)) return $value;
        if (!is_string($value) || trim($value)==='') return array();
        $decoded=json_decode($value,true); if (is_array($decoded)) return $decoded;
        parse_str($value,$result); return is_array($result)?$result:array();
    }
    protected function post_form($url,$body,$headers=array()) {
        $response=wp_remote_post($url,array('timeout'=>20,'redirection'=>3,'headers'=>$headers,'body'=>$body));
        return $this->parse_http_response($response);
    }
    protected function get_json($url,$headers=array()) {
        $response=wp_remote_get($url,array('timeout'=>20,'redirection'=>3,'headers'=>$headers));
        return $this->parse_http_response($response);
    }
    protected function parse_http_response($response) {
        if (is_wp_error($response)) return $response;
        $code=(int)wp_remote_retrieve_response_code($response); $body=(string)wp_remote_retrieve_body($response);
        $json=json_decode($body,true);
        if ($code<200 || $code>=300) return new WP_Error('oauth_http_'.$code,'OAuth-Endpunkt antwortete mit HTTP '.$code,array('body'=>is_array($json)?$json:null));
        if (is_array($json)) return $json;
        parse_str($body,$form); if (is_array($form) && $form) return $form;
        return new WP_Error('oauth_invalid_response','OAuth-Endpunkt lieferte keine unterstützte Antwort.');
    }
    protected function normalize_token_result($data) {
        if (is_wp_error($data)) return $data;
        if (!empty($data['error'])) return new WP_Error('oauth_'.$data['error'],(string)($data['error_description'] ?? $data['error']));
        if (empty($data['access_token'])) return new WP_Error('oauth_missing_access_token','Token-Antwort enthält kein access_token.');
        return $data;
    }
    protected function validation_cache_get($profile,$token) {
        $mins=(int)$this->auth_config($profile,'ValidationOutcomeCacheMins',0); if ($mins<=0) return false;
        return get_transient('kornsw_ath_val_'.md5(($profile['TokenSourceUid'] ?? '').'|'.$token));
    }
    protected function validation_cache_set($profile,$token,$result) {
        $mins=(int)$this->auth_config($profile,'ValidationOutcomeCacheMins',0); if ($mins<=0) return;
        if (is_array($result) && !empty($result['technical_success'])) set_transient('kornsw_ath_val_'.md5(($profile['TokenSourceUid'] ?? '').'|'.$token),$result,$mins*MINUTE_IN_SECONDS);
    }
}
