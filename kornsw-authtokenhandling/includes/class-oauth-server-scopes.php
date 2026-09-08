<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_OAuth_Server_Scopes {
    public static function register_hooks(){
        add_filter('kornsw_authtokenhandling_user_scopes',array(__CLASS__,'add_role_scopes'),10,5);
        add_filter('kornsw_authtokenhandling_user_scopes',array(__CLASS__,'add_user_scopes'),20,5);
    }

    public static function resolve($user_id,$client_id,$requested_scopes=array(),$context=array()){
        $requested=self::normalize($requested_scopes);
        $scopes=apply_filters('kornsw_authtokenhandling_user_scopes',array(),(int)$user_id,(string)$client_id,$requested,$context);
        return self::normalize($scopes);
    }

    public static function add_role_scopes($scopes,$user_id,$client_id,$requested_scopes,$context){
        $user=get_user_by('id',(int)$user_id); if(!$user) return $scopes;
        $configured=KornSW_ATH_OAuth_Server_Config::role_scopes();
        foreach((array)$user->roles as $role){
            $scopes[]='Role:'.ucfirst((string)$role);
            foreach(self::normalize($configured[$role]??'') as $scope) $scopes[]=$scope;
        }
        return $scopes;
    }

    public static function add_user_scopes($scopes,$user_id,$client_id,$requested_scopes,$context){
        $configured=KornSW_ATH_OAuth_Server_Config::user_scopes();
        foreach(self::normalize($configured[(string)(int)$user_id]??'') as $scope) $scopes[]=$scope;
        return $scopes;
    }

    public static function normalize($value){
        $items=array();
        if(is_array($value)){
            foreach($value as $entry){ foreach(self::normalize($entry) as $scope) $items[]=$scope; }
        } else {
            $text=trim((string)$value);
            if($text!=='') $items=preg_split('/\s+/', $text,-1,PREG_SPLIT_NO_EMPTY);
        }
        $result=array();
        foreach($items as $scope){ $scope=trim((string)$scope); if($scope!=='' && !in_array($scope,$result,true)) $result[]=$scope; }
        return $result;
    }
}
