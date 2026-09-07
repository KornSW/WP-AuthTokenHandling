<?php
if (!defined('ABSPATH')) { exit; }
final class KornSW_ATH_Provider_Registry {
    public static function all(){ $providers=array('generic'=>new KornSW_ATH_Generic_Provider(),'google'=>new KornSW_ATH_Google_Provider(),'github'=>new KornSW_ATH_GitHub_Provider()); return apply_filters('kornsw_authtokenhandling_oauth_providers',$providers); }
    public static function get_for_profile($profile){$name=(string)($profile['OAuthOperationsProvider']??'generic');$all=self::all();return isset($all[$name])?$all[$name]:new WP_Error('unknown_provider','Unbekannter OAuthOperationsProvider: '.$name);}
}
