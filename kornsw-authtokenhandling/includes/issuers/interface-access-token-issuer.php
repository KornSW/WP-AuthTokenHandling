<?php
if (!defined('ABSPATH')) { exit; }
interface KornSW_ATH_IAccess_Token_Issuer { public function try_request_access_token($claims_to_request=array()); }
