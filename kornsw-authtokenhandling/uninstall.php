<?php
if (!defined('WP_UNINSTALL_PLUGIN')) { exit; }
global $wpdb;
foreach(array('kornsw_ath_connections','kornsw_ath_token_sets','kornsw_ath_session_bindings','kornsw_ath_continuations','kornsw_ath_server_codes','kornsw_ath_server_refresh') as $suffix){$table=$wpdb->prefix.$suffix;$wpdb->query("DROP TABLE IF EXISTS `$table`");}
foreach(array('kornsw_ath_profiles_json','kornsw_ath_primary_source_uid','kornsw_ath_auto_provision_role','kornsw_ath_login_source_migrated','kornsw_ath_db_version','kornsw_ath_oauth_server_enabled','kornsw_ath_oauth_server_clients','kornsw_ath_oauth_server_role_scopes','kornsw_ath_oauth_server_user_scopes') as $option) delete_option($option);
