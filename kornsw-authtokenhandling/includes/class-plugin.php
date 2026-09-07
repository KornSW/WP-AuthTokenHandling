<?php
if (!defined('ABSPATH')) { exit; }
final class KornSW_ATH_Plugin {
    private static $instance;
    public static function instance(){if(!self::$instance)self::$instance=new self();return self::$instance;}
    public static function activate(){KornSW_ATH_Storage::install();if(get_option(KornSW_ATH_Config_Repository::OPTION_PROFILES_JSON,null)===null)add_option(KornSW_ATH_Config_Repository::OPTION_PROFILES_JSON,'[]','',false);if(get_option(KornSW_ATH_Config_Repository::OPTION_AUTO_ROLE,null)===null)add_option(KornSW_ATH_Config_Repository::OPTION_AUTO_ROLE,'subscriber','',false);}
    public function boot(){KornSW_ATH_Admin::register_hooks();KornSW_ATH_OAuth_Flow::register_hooks();KornSW_ATH_Session_Guard::register_hooks();KornSW_ATH_Shortcodes::register_hooks();}
}
