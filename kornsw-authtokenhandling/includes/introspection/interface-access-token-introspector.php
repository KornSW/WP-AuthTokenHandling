<?php
if (!defined('ABSPATH')) { exit; }
interface KornSW_ATH_IAccess_Token_Introspector { public function introspect($profile,$access_token); }
