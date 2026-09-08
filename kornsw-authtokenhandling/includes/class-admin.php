<?php
if (!defined('ABSPATH')) { exit; }

final class KornSW_ATH_Admin {
    public static function register_hooks() {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'assets'));
        add_action('admin_post_kornsw_ath_save_settings', array(__CLASS__, 'save'));
        add_filter('plugin_action_links_' . plugin_basename(KORNSW_ATH_FILE), array(__CLASS__, 'plugin_links'));
    }

    public static function menu() {
        add_users_page('AuthTokenHandling (KornSW)', 'AuthTokenHandling (KornSW)', 'manage_options', 'kornsw-authtokenhandling', array(__CLASS__, 'page'));
    }

    public static function plugin_links($links) {
        array_unshift($links, '<a href="' . esc_url(admin_url('users.php?page=kornsw-authtokenhandling')) . '">Einstellungen</a>');
        return $links;
    }

    public static function assets($hook) {
        if ($hook !== 'users_page_kornsw-authtokenhandling') return;
        wp_enqueue_style('kornsw-ath-admin', KORNSW_ATH_URL . 'assets/admin.css', array(), KORNSW_ATH_VERSION);
        wp_enqueue_script('kornsw-ath-admin', KORNSW_ATH_URL . 'assets/admin.js', array(), KORNSW_ATH_VERSION, true);
        wp_localize_script('kornsw-ath-admin', 'KornSWATH', array('defaultProfile' => KornSW_ATH_Config_Repository::create_default_profile()));
    }

    public static function save() {
        if (!current_user_can('manage_options')) wp_die('Nicht erlaubt.', 403);
        check_admin_referer('kornsw_ath_save_settings');
        $json = (string) wp_unslash($_POST['profiles_json'] ?? '[]');
        $result = KornSW_ATH_Config_Repository::save_profiles_json($json);
        if (is_wp_error($result)) {
            wp_safe_redirect(add_query_arg(array('page' => 'kornsw-authtokenhandling', 'ath_error' => rawurlencode($result->get_error_message())), admin_url('users.php')));
            exit;
        }
        update_option(KornSW_ATH_Config_Repository::OPTION_AUTO_ROLE, sanitize_key(wp_unslash($_POST['auto_role'] ?? 'subscriber')), false);
        wp_safe_redirect(add_query_arg(array('page' => 'kornsw-authtokenhandling', 'updated' => 'true'), admin_url('users.php')));
        exit;
    }

    public static function page() {
        if (!current_user_can('manage_options')) return;
        $json = KornSW_ATH_Config_Repository::get_profiles_json();
        ?>
        <div class="wrap kornsw-ath">
            <h1>KornSW AuthTokenHandling</h1>
            <?php if (isset($_GET['ath_error'])) echo '<div class="notice notice-error"><p>' . esc_html(wp_unslash($_GET['ath_error'])) . '</p></div>'; ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" id="kornsw-ath-form">
                <input type="hidden" name="action" value="kornsw_ath_save_settings">
                <?php wp_nonce_field('kornsw_ath_save_settings'); ?>

                <div class="ath-global">
                    <label>
                        <strong>Standardrolle für Auto-Provisioning</strong>
                        <select name="auto_role"><?php wp_dropdown_roles(KornSW_ATH_Config_Repository::get_auto_provision_role()); ?></select>
                    </label>
                    <p class="description">Jede Token Source kann als WordPress-Login-Quelle qualifiziert werden. Die Feldmaske wird zweistufig aus Strategie und konkreter OAuth-/Introspection-Implementierung abgeleitet.</p>
                </div>

                <div class="ath-layout">
                    <aside class="ath-profiles">
                        <div class="ath-sidebar-head"><strong>Token Sources</strong><button type="button" class="button" id="ath-add-profile">+</button></div>
                        <div id="ath-profile-list"></div>
                    </aside>
                    <main class="ath-editor">
                        <div id="ath-no-profile">Profil auswählen oder neu anlegen.</div>
                        <div id="ath-profile-editor" hidden><?php self::editor_controls(); ?></div>
                    </main>
                </div>

                <h2>Authentifizierungs-JSON-Array</h2>
                <p class="description">Dies ist die führende Konfiguration. Versteckte und unbekannte Felder bleiben beim visuellen Bearbeiten unverändert erhalten.</p>
                <textarea name="profiles_json" id="ath-json" rows="24" spellcheck="false"><?php echo esc_textarea($json); ?></textarea>
                <p><button type="button" class="button" id="ath-apply-json">JSON in Editor übernehmen</button> <button type="submit" class="button button-primary">Konfiguration speichern</button></p>
            </form>
        </div>
        <?php
    }

    private static function editor_controls() {
        ?>
        <div class="ath-profile-header">
            <label>Name<input type="text" data-outer="DisplayName"></label>
            <label>Token Source UID<input type="text" data-outer="TokenSourceUid" readonly></label>
            <label class="ath-inline"><input type="checkbox" data-outer="Enabled"> Aktiv</label>
            <label class="ath-inline"><input type="checkbox" data-outer="LoginEnabled"> Als WordPress-Login anbieten</label>
            <button type="button" class="button-link-delete" id="ath-delete-profile">Profil entfernen</button>
        </div>

        <nav class="ath-tabs">
            <button type="button" class="button button-primary" data-tab="issuing">Issuing</button>
            <button type="button" class="button" data-tab="introspection">Introspection</button>
        </nav>

        <section data-panel="issuing">
            <h2>Issuing-Strategie</h2>
            <p class="description">Ebene 1 bestimmt den Token-Erzeugungs-/Beschaffungsweg. Bei OAuth bestimmt Ebene 2 den konkreten Operations Provider und damit dessen wirklich benötigte Eingaben.</p>
            <div class="ath-grid">
                <label>
                    Strategie / IssueMode
                    <select data-config="IssueMode">
                        <option value="RAW_INPUT">Raw Input</option>
                        <option value="HTTP_GET">HTTP GET</option>
                        <option value="LOCAL_JWT_GENERATION">Local JWT Generation</option>
                        <option value="OAUTH_CIBA_CODEGRAND">OAuth Authorization Code + PKCE</option>
                        <option value="LOCAL_BASICAUTH_GENERATION">LOCAL_BASICAUTH_GENERATION (Kompatibilität)</option>
                        <option value="OAUTH_IMPLICIT_FLOW">OAUTH_IMPLICIT_FLOW (Legacy)</option>
                        <option value="OAUTH_CIBA_CODEGRAND_HTTPGETONLY">OAUTH_CIBA_CODEGRAND_HTTPGETONLY (Legacy)</option>
                    </select>
                </label>

                <label hidden data-ath-field="issuing.provider">
                    OAuth Operations Provider
                    <select data-outer="OAuthOperationsProvider">
                        <option value="generic">Generic OAuth 2.0 / OIDC</option>
                        <option value="google">Google</option>
                        <option value="github">GitHub</option>
                        <option value="microsoft">Microsoft</option>
                        <option value="apple">Apple</option>
                        <option value="facebook">Facebook</option>
                        <option value="remote_wordpress">Remote-WordPress (AuthTokenHandling)</option>
                    </select>
                    <span class="description" id="ath-issuing-provider-help"></span>
                </label>

                <label hidden data-ath-field="issuing.client_id">Client ID<input type="text" data-config="ClientId"></label>
                <label hidden data-ath-field="issuing.client_secret">Client Secret<input type="password" data-config="ClientSecret" autocomplete="new-password"></label>
                <label hidden data-ath-field="issuing.scopes">Scopes<input type="text" data-provider="scopes"></label>

                <label hidden data-ath-field="issuing.microsoft_tenant">Microsoft Tenant<input type="text" data-provider="tenant" placeholder="common"></label>
                <label hidden data-ath-field="issuing.apple_team_id">Apple Team ID<input type="text" data-provider="apple_team_id"></label>
                <label hidden data-ath-field="issuing.apple_key_id">Apple Key ID<input type="text" data-provider="apple_key_id"></label>
                <label hidden data-ath-field="issuing.apple_private_key">Apple Private Key (PEM)<textarea rows="6" data-provider="apple_private_key"></textarea></label>
                <label hidden data-ath-field="issuing.remote_base_url">Remote WordPress Base URL<input type="url" data-provider="remote_base_url" placeholder="https://portal.example.com"></label>

                <label hidden data-ath-field="issuing.authorization_endpoint">Authorization Endpoint<input type="url" data-provider="authorization_endpoint"></label>
                <label hidden data-ath-field="issuing.token_endpoint">Token Endpoint<input type="url" data-provider="token_endpoint"></label>
                <label hidden data-ath-field="issuing.userinfo_endpoint">UserInfo Endpoint<input type="url" data-provider="userinfo_endpoint"></label>
                <label hidden data-ath-field="issuing.additional_auth_args">Additional Auth Args<input type="text" data-config="AdditionalAuthArgs" placeholder='{"prompt":"login"}'></label>
                <label hidden data-ath-field="issuing.additional_retrieve_args">Additional Retrieve Args<input type="text" data-config="AdditionalRetrieveArgs"></label>
                <label class="ath-inline" hidden data-ath-field="issuing.supports_refresh_token"><input type="checkbox" data-provider="supports_refresh_token"> Generic Provider unterstützt Refresh Token</label>
                <label class="ath-inline" hidden data-ath-field="issuing.supports_id_token"><input type="checkbox" data-provider="supports_id_token"> Generic Provider unterstützt ID Token</label>
                <label class="ath-inline" hidden data-ath-field="issuing.github_refresh_token"><input type="checkbox" data-provider="supports_refresh_token"> GitHub Refresh Token verwenden, falls vom GitHub-App-Modell unterstützt</label>

                <label hidden data-ath-field="issuing.jwt_exp">JWT Expiration (Minuten)<input type="number" data-config="JwtExpMinutes"></label>
                <label hidden data-ath-field="issuing.jwt_signing_key">JWT Signing Key<input type="password" data-config="JwtSelfSignKey"></label>
                <label hidden data-ath-field="issuing.jwt_algorithm">JWT Algorithm<input type="text" data-config="JwtSelfSignAlg" readonly></label>

                <label hidden data-ath-field="issuing.retrieve_url">RetrieveEndpointUrl<input type="url" data-config="RetrieveEndpointUrl"></label>
                <label hidden data-ath-field="issuing.retrieve_authorization">RetrieveEndpointAuthorization<input type="text" data-config="RetrieveEndpointAuthorization"></label>
            </div>
            <div class="notice notice-warning inline ath-compatibility" id="ath-issuing-compatibility" hidden></div>
        </section>

        <section data-panel="introspection" hidden>
            <h2>Introspection-/Validierungsstrategie</h2>
            <p class="description">Ebene 1 legt die Validierungsstrategie fest. Nur bei einer externen Providerprüfung erscheint Ebene 2. OOB-Provider verwenden feste Implementierungsendpunkte; nur Generic benötigt frei konfigurierbare Endpoint-URLs.</p>
            <div class="ath-grid">
                <label>
                    Strategie / ValidationMode
                    <select data-config="ValidationMode">
                        <option value="IMPLICIT_WHEN_USED">Implicit when used</option>
                        <option value="LOCAL_JWT_VALIDATION">Local JWT Validation</option>
                        <option value="OAUTH_INTROSPECTION_ENDPOINT">OAuth / Provider Validation</option>
                        <option value="OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY">OAuth Introspection via GET (Legacy)</option>
                        <option value="GITHUB_VALIDATION_ENDPOINT">GitHub Validation</option>
                    </select>
                </label>

                <label hidden data-ath-field="introspection.provider">
                    Introspection-Implementierung
                    <select id="ath-introspection-provider">
                        <option value="generic">Generic OAuth Introspection</option>
                        <option value="google">Google</option>
                        <option value="github">GitHub</option>
                        <option value="microsoft">Microsoft</option>
                        <option value="facebook">Facebook</option>
                        <option value="remote_wordpress">Remote-WordPress (AuthTokenHandling)</option>
                    </select>
                    <span class="description" id="ath-introspection-provider-help"></span>
                </label>

                <label hidden data-ath-field="introspection.cache">Provider-interner Validation Cache (Min.)<input type="number" min="0" data-config="ValidationOutcomeCacheMins"></label>
                <label hidden data-ath-field="introspection.jwt_validation_key">JWT Validation Key<input type="password" data-config="JwtValidationKey"></label>
                <label class="ath-inline" hidden data-ath-field="introspection.claim_casing"><input type="checkbox" data-config="ClaimValidationIgnoresCasing"> Claim-Namen casing-unabhängig</label>

                <label hidden data-ath-field="introspection.endpoint">Introspection Endpoint<input type="url" data-introspection-provider="introspection_endpoint"></label>
                <label hidden data-ath-field="introspection.authorization">Introspection Authorization<input type="text" data-config="validationEndpointAuthorization"></label>
            </div>
            <div class="notice notice-warning inline ath-compatibility" id="ath-introspection-compatibility" hidden></div>
        </section>

        <details class="ath-advanced">
            <summary>Weitere kompatible AuthTokenConfig-Felder</summary>
            <div class="ath-grid">
                <label>DisplayLabel<input type="text" data-config="DisplayLabel"></label>
                <label>DisplayIconUrl<input type="url" data-config="DisplayIconUrl"></label>
                <label>LocalLogonNameSyntax<input type="text" data-config="LocalLogonNameSyntax"></label>
                <label>LocalLogonNamePersistation<select data-config="LocalLogonNamePersistation"><option>NEVER</option><option>OPT-IN</option><option>OPT-OUT</option><option>ALWAYS</option></select></label>
                <label>LocalLogonNameInputLabel<input type="text" data-config="LocalLogonNameInputLabel"></label>
                <label>LocalLogonPassInputLabel<input type="text" data-config="LocalLogonPassInputLabel"></label>
                <label>LocalLogonSaltDisplayLabel<input type="text" data-config="LocalLogonSaltDisplayLabel"></label>
                <label class="ath-inline"><input type="checkbox" data-config="LocalLogonNameToLower"> LocalLogonNameToLower</label>
                <label class="ath-inline"><input type="checkbox" data-config="AuthEndpointRejectsIframe"> AuthEndpointRejectsIframe</label>
            </div>
        </details>

        <details class="ath-advanced">
            <summary>Claims (JSON)</summary>
            <textarea rows="8" id="ath-claims"></textarea>
        </details>

        <details class="ath-advanced">
            <summary>Raw AuthTokenConfig</summary>
            <p class="description">Escape Hatch für vollständige Cross-Stack-Kompatibilität. Unbekannte oder derzeit nicht visuell unterstützte Felder können hier direkt bearbeitet werden.</p>
            <textarea rows="16" id="ath-raw-auth-config"></textarea>
            <p><button type="button" class="button" id="ath-apply-raw-config">Raw AuthTokenConfig übernehmen</button></p>
        </details>
        <?php
    }
}
