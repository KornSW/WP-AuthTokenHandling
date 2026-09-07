(() => {
  const json = document.querySelector('#ath-json');
  if (!json) return;

  let profiles = [];
  let current = -1;
  const list = document.querySelector('#ath-profile-list');
  const editor = document.querySelector('#ath-profile-editor');
  const empty = document.querySelector('#ath-no-profile');
  const clone = value => JSON.parse(JSON.stringify(value));

  /*
   * Two-level UI mapping:
   *   Level 1: strategy decides which strategy fields exist.
   *   Level 2: provider/implementation decides which provider-specific fields exist.
   * Hidden fields remain in JSON and are never deleted automatically.
   */
  const ISSUING_STRATEGY_RULES = {
    RAW_INPUT: [],
    HTTP_GET: ['issuing.retrieve_url', 'issuing.retrieve_authorization'],
    LOCAL_JWT_GENERATION: ['issuing.jwt_exp', 'issuing.jwt_signing_key', 'issuing.jwt_algorithm'],
    OAUTH_CIBA_CODEGRAND: ['issuing.provider']
  };

  const ISSUING_PROVIDER_RULES = {
    generic: [
      'issuing.client_id', 'issuing.client_secret', 'issuing.scopes',
      'issuing.authorization_endpoint', 'issuing.token_endpoint', 'issuing.userinfo_endpoint',
      'issuing.additional_auth_args', 'issuing.additional_retrieve_args',
      'issuing.supports_refresh_token', 'issuing.supports_id_token'
    ],
    google: ['issuing.client_id', 'issuing.client_secret', 'issuing.scopes'],
    github: ['issuing.client_id', 'issuing.client_secret', 'issuing.scopes', 'issuing.github_refresh_token']
  };

  const INTROSPECTION_STRATEGY_RULES = {
    IMPLICIT_WHEN_USED: [],
    LOCAL_JWT_VALIDATION: ['introspection.jwt_validation_key', 'introspection.claim_casing'],
    OAUTH_INTROSPECTION_ENDPOINT: ['introspection.provider', 'introspection.cache'],
    OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY: ['introspection.provider', 'introspection.cache'],
    GITHUB_VALIDATION_ENDPOINT: ['introspection.provider', 'introspection.cache']
  };

  const INTROSPECTION_PROVIDER_RULES = {
    generic: ['introspection.endpoint', 'introspection.authorization'],
    google: [],
    github: []
  };

  const SUPPORTED_ISSUE_MODES = Object.keys(ISSUING_STRATEGY_RULES);
  const SUPPORTED_VALIDATION_MODES = Object.keys(INTROSPECTION_STRATEGY_RULES);

  function parse() {
    try {
      const parsed = JSON.parse(json.value || '[]');
      if (!Array.isArray(parsed)) throw new Error('JSON muss ein Array sein.');
      profiles = parsed;
      renderList();
      select(Math.min(current, profiles.length - 1));
    } catch (error) {
      alert(error.message);
    }
  }

  function sync() {
    json.value = JSON.stringify(profiles, null, 2);
    renderList();
  }

  function ensure(profile) {
    profile.AuthTokenConfig = profile.AuthTokenConfig || {};
    profile.ProviderConfiguration = profile.ProviderConfiguration || {};
    profile.IntrospectionProviderConfiguration = profile.IntrospectionProviderConfiguration || {};
    return profile;
  }

  function renderList() {
    list.innerHTML = '';
    profiles.forEach((profile, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'ath-profile-item' + (index === current ? ' active' : '');
      button.textContent = profile.DisplayName || profile.TokenSourceUid || ('Profil ' + (index + 1));
      button.onclick = () => select(index);
      list.appendChild(button);
    });
  }

  function select(index) {
    current = index >= 0 && index < profiles.length ? index : -1;
    editor.hidden = current < 0;
    empty.hidden = current >= 0;
    renderList();
    if (current < 0) return;

    const profile = ensure(profiles[current]);
    document.querySelectorAll('[data-outer]').forEach(element => setControl(element, profile[element.dataset.outer]));
    document.querySelectorAll('[data-config]').forEach(element => setControl(element, profile.AuthTokenConfig[element.dataset.config]));
    document.querySelectorAll('[data-provider]').forEach(element => setControl(element, profile.ProviderConfiguration[element.dataset.provider]));
    document.querySelectorAll('[data-introspection-provider]').forEach(element => setControl(element, profile.IntrospectionProviderConfiguration[element.dataset.introspectionProvider]));

    const introspectionProvider = profile.IntrospectionProvider || inferIntrospectionProvider(profile);
    setControl(document.querySelector('#ath-introspection-provider'), introspectionProvider);

    document.querySelector('#ath-claims').value = JSON.stringify(profile.AuthTokenConfig.Claims || {}, null, 2);
    const raw = document.querySelector('#ath-raw-auth-config');
    if (raw) raw.value = JSON.stringify(profile.AuthTokenConfig || {}, null, 2);
    updateVisibility();
  }

  function setControl(element, value) {
    if (!element) return;
    if (element.type === 'checkbox') element.checked = !!value;
    else element.value = value === undefined || value === null ? '' : value;
  }

  function controlValue(element) {
    if (element.type === 'checkbox') return element.checked;
    if (element.type === 'number') return element.value === '' ? '' : Number(element.value);
    return element.value;
  }

  document.querySelectorAll('[data-outer],[data-config],[data-provider],[data-introspection-provider]').forEach(element => {
    element.addEventListener('input', () => {
      if (current < 0) return;
      const profile = ensure(profiles[current]);
      if (element.dataset.outer) profile[element.dataset.outer] = controlValue(element);
      if (element.dataset.config) profile.AuthTokenConfig[element.dataset.config] = controlValue(element);
      if (element.dataset.provider) profile.ProviderConfiguration[element.dataset.provider] = controlValue(element);
      if (element.dataset.introspectionProvider) profile.IntrospectionProviderConfiguration[element.dataset.introspectionProvider] = controlValue(element);
      sync();
      updateVisibility();
    });
  });

  const introspectionProviderSelect = document.querySelector('#ath-introspection-provider');
  introspectionProviderSelect.addEventListener('input', () => {
    if (current < 0) return;
    const profile = ensure(profiles[current]);
    profile.IntrospectionProvider = introspectionProviderSelect.value;
    if (profile.AuthTokenConfig.ValidationMode === 'GITHUB_VALIDATION_ENDPOINT' && introspectionProviderSelect.value !== 'github') {
      profile.AuthTokenConfig.ValidationMode = 'OAUTH_INTROSPECTION_ENDPOINT';
      setControl(document.querySelector('[data-config="ValidationMode"]'), profile.AuthTokenConfig.ValidationMode);
    }
    if (introspectionProviderSelect.value === 'github' && profile.AuthTokenConfig.ValidationMode === 'OAUTH_INTROSPECTION_ENDPOINT') {
      profile.AuthTokenConfig.ValidationMode = 'GITHUB_VALIDATION_ENDPOINT';
      setControl(document.querySelector('[data-config="ValidationMode"]'), profile.AuthTokenConfig.ValidationMode);
    }
    sync();
    updateVisibility();
  });

  const rawApply = document.querySelector('#ath-apply-raw-config');
  if (rawApply) {
    rawApply.addEventListener('click', () => {
      if (current < 0) return;
      try {
        const parsed = JSON.parse(document.querySelector('#ath-raw-auth-config').value || '{}');
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('AuthTokenConfig muss ein JSON-Objekt sein.');
        profiles[current].AuthTokenConfig = parsed;
        sync();
        select(current);
      } catch (error) {
        alert(error.message);
      }
    });
  }

  document.querySelector('#ath-claims').addEventListener('change', event => {
    if (current < 0) return;
    try {
      profiles[current].AuthTokenConfig.Claims = JSON.parse(event.target.value || '{}');
      sync();
    } catch (error) {
      alert('Claims: ' + error.message);
    }
  });

  function inferIntrospectionProvider(profile) {
    const mode = String(profile.AuthTokenConfig.ValidationMode || 'IMPLICIT_WHEN_USED');
    if (mode === 'GITHUB_VALIDATION_ENDPOINT') return 'github';
    return profile.OAuthOperationsProvider || 'generic';
  }

  function setFieldVisibility(visibleFields) {
    document.querySelectorAll('[data-ath-field]').forEach(element => {
      element.hidden = !visibleFields.has(element.dataset.athField);
    });
  }

  function showCompatibilityNotice(kind, mode) {
    const notice = document.querySelector('#ath-' + kind + '-compatibility');
    if (!notice) return;
    const supported = kind === 'issuing' ? SUPPORTED_ISSUE_MODES : SUPPORTED_VALIDATION_MODES;
    notice.hidden = supported.includes(mode);
    if (!notice.hidden) {
      notice.textContent = 'Der gespeicherte Modus "' + mode + '" wird verlustfrei erhalten, besitzt in dieser WordPress-V1 aber keinen eigenen visuellen Editor. Änderungen daran bitte über Raw AuthTokenConfig vornehmen.';
    }
  }

  function updateVisibility() {
    if (current < 0) return;
    const profile = ensure(profiles[current]);
    const issueMode = String(profile.AuthTokenConfig.IssueMode || 'RAW_INPUT');
    const issuingProvider = String(profile.OAuthOperationsProvider || 'generic');
    const validationMode = String(profile.AuthTokenConfig.ValidationMode || 'IMPLICIT_WHEN_USED');
    let introspectionProvider = String(profile.IntrospectionProvider || inferIntrospectionProvider(profile));
    if (validationMode === 'GITHUB_VALIDATION_ENDPOINT') {
      introspectionProvider = 'github';
      setControl(document.querySelector('#ath-introspection-provider'), 'github');
    }

    const visible = new Set();
    (ISSUING_STRATEGY_RULES[issueMode] || []).forEach(field => visible.add(field));
    if (issueMode === 'OAUTH_CIBA_CODEGRAND') {
      (ISSUING_PROVIDER_RULES[issuingProvider] || []).forEach(field => visible.add(field));
    }

    (INTROSPECTION_STRATEGY_RULES[validationMode] || []).forEach(field => visible.add(field));
    if (['OAUTH_INTROSPECTION_ENDPOINT', 'OAUTH_INTROSPECTION_ENDPOINT_HTTPGETONLY', 'GITHUB_VALIDATION_ENDPOINT'].includes(validationMode)) {
      (INTROSPECTION_PROVIDER_RULES[introspectionProvider] || []).forEach(field => visible.add(field));
    }

    setFieldVisibility(visible);
    showCompatibilityNotice('issuing', issueMode);
    showCompatibilityNotice('introspection', validationMode);

    const providerHelp = document.querySelector('#ath-issuing-provider-help');
    if (providerHelp) {
      if (issuingProvider === 'generic') providerHelp.textContent = 'Generic: Authorization-, Token- und UserInfo-Endpunkte werden in diesem Profil konfiguriert.';
      if (issuingProvider === 'google') providerHelp.textContent = 'Google: Authorization-, Token- und UserInfo-Endpunkte sind fest im Provider implementiert.';
      if (issuingProvider === 'github') providerHelp.textContent = 'GitHub: Authorization-, Token- und User-Endpunkte sind fest im Provider implementiert.';
    }

    const introspectionHelp = document.querySelector('#ath-introspection-provider-help');
    if (introspectionHelp) {
      if (introspectionProvider === 'generic') introspectionHelp.textContent = 'Generic: der Introspection-Endpunkt und seine Authorization werden hier konfiguriert.';
      if (introspectionProvider === 'google') introspectionHelp.textContent = 'Google: die Tokenprüfung verwendet den fest implementierten Google-tokeninfo-Endpunkt.';
      if (introspectionProvider === 'github') introspectionHelp.textContent = 'GitHub: die Tokenprüfung verwendet die fest implementierte GitHub User API.';
    }
  }

  document.querySelector('#ath-add-profile').onclick = () => {
    const profile = clone(KornSWATH.defaultProfile);
    profile.TokenSourceUid = crypto.randomUUID ? crypto.randomUUID() : ('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx').replace(/[xy]/g, character => {
      const random = Math.random() * 16 | 0;
      const value = character === 'x' ? random : (random & 3 | 8);
      return value.toString(16);
    });
    profiles.push(profile);
    current = profiles.length - 1;
    sync();
    select(current);
  };

  document.querySelector('#ath-delete-profile').onclick = () => {
    if (current < 0 || !confirm('Token Source wirklich aus der Konfiguration entfernen? Bestehende Token-Verbindungen werden dadurch nicht automatisch gelöscht.')) return;
    profiles.splice(current, 1);
    current = Math.min(current, profiles.length - 1);
    sync();
    select(current);
  };

  document.querySelector('#ath-apply-json').onclick = parse;
  document.querySelectorAll('[data-tab]').forEach(button => {
    button.onclick = () => {
      document.querySelectorAll('[data-tab]').forEach(item => item.classList.toggle('button-primary', item === button));
      document.querySelectorAll('[data-panel]').forEach(panel => panel.hidden = panel.dataset.panel !== button.dataset.tab);
    };
  });

  parse();
})();
