<?php
if (!defined('ABSPATH')) { exit; }
final class KornSW_ATH_Local_JWT_Issuer implements KornSW_ATH_IAccess_Token_Issuer {
    private $profile; private $user;
    public function __construct($profile,$user){$this->profile=$profile;$this->user=$user;}
    public function try_request_access_token($claims_to_request=array()){
        $c=$this->profile['AuthTokenConfig']??array();$key=(string)($c['JwtSelfSignKey']??'');if($key==='')return new WP_Error('missing_signing_key','JwtSelfSignKey fehlt.');
        $alg=strtoupper((string)($c['JwtSelfSignAlg']??'HS256'));if(!in_array($alg,array('HS256','SHA256','SHA265'),true))return new WP_Error('unsupported_jwt_alg','V1 unterstützt lokale JWT-Erzeugung nur mit HS256.');
        $now=time();$claims=is_array($c['Claims']??null)?$c['Claims']:array();$claims=array_merge($claims,$claims_to_request);$claims['iat']=$now;$claims['exp']=$now+max(1,(int)($c['JwtExpMinutes']??1440))*60;if(empty($claims['sub']))$claims['sub']='wp-user-'.$this->user->ID;
        $header=array('typ'=>'JWT','alg'=>'HS256');$segments=array(self::b64(wp_json_encode($header)),self::b64(wp_json_encode($claims)));$sig=hash_hmac('sha256',implode('.',$segments),$key,true);$segments[]=self::b64($sig);
        return array('access_token'=>implode('.',$segments),'token_type'=>'Bearer','expires_in'=>max(1,(int)($c['JwtExpMinutes']??1440))*60,'scope'=>(string)($claims['scope']??''));
    }
    private static function b64($v){return rtrim(strtr(base64_encode($v),'+/','-_'),'=');}
}
