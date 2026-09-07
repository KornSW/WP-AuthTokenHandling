<?php
if (!defined('ABSPATH')) { exit; }
interface KornSW_ATH_IOAuth_Operations_Provider {
    public function invariant_name();
    public function display_title();
    public function get_authorization_url($profile,$redirect_uri,$state,$code_verifier);
    public function exchange_authorization_code($profile,$code,$redirect_uri,$code_verifier);
    public function refresh_access_token($profile,$refresh_token);
    public function validate_token($profile,$access_token);
    public function resolve_identity($profile,$access_token,$id_token='');
    public function has_capability($profile,$capability_name);
}
