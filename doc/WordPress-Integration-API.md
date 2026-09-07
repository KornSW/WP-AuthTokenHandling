# KornSW AuthTokenHandling – WordPress Integration API

## Zweck

Andere WordPress-Plugins sollen OAuth weder implementieren noch Token speichern. Sie speichern ausschließlich die stabile Token-Source-UID und benutzen diese API.

## Token Sources für Admin-Oberflächen

```php
$options = kornsw_authtokenhandling_get_token_source_options(true);
```

Liefert `TokenSourceUid => DisplayName`. Vollständige nicht-geheime Metadaten:

```php
$sources = kornsw_authtokenhandling_get_token_sources();
```

Convenience-Renderer:

```php
echo kornsw_authtokenhandling_render_token_source_select(
    'my_plugin_token_source',
    get_option('my_plugin_token_source'),
    array('include_none' => true)
);
```

Ein Consumer speichert **nur die UID**, niemals Client Secret oder Access/Refresh Token.

## Nichtinteraktiver Tokenzugriff

```php
$result = kornsw_authtokenhandling_try_get_access_token($sourceUid);
```

Wichtige Statuswerte: `SUCCESS`, `AUTHENTICATION_REQUIRED`, `SOURCE_NOT_FOUND`, `SOURCE_DISABLED`, `USER_NOT_LOGGED_IN`, `VALIDATION_UNAVAILABLE`, `ERROR`.

Diese API löst keinen Browser-Redirect aus und ist für Cron/REST/AJAX/Backendlogik geeignet.

## Interaktiver On-Demand-Zugriff

```php
$token = kornsw_authtokenhandling_require_access_token($sourceUid);
```

Ist ein nutzbares Token vorhanden, wird es direkt zurückgegeben. Ist Refresh möglich, wird zuerst refreshed. Ist Benutzerinteraktion erforderlich und der Request browser-interaktiv, startet AuthTokenHandling einen OAuth-Flow und speichert eine kurzlebige Continuation. Nach dem Provider-Callback landet der Browser an der ursprünglichen URL; der normale Plugin-Code läuft erneut und erhält nun das Token.

**Wichtig:** Das ist semantisch synchron, technisch aber ein Redirect-/Callback-Flow über mehrere HTTP-Requests. POST-Dateien oder beliebige PHP-Callbacks werden nicht serialisiert.

Eigene Return-URL:

```php
$token = kornsw_authtokenhandling_require_access_token(
    $sourceUid,
    array('return_url' => admin_url('admin.php?page=my-plugin&resume=1'))
);
```

## Bevorzugte High-Level-API

```php
$response = kornsw_authtokenhandling_authorized_request(
    $sourceUid,
    'https://api.example.org/customers',
    array('method' => 'GET')
);
```

AuthTokenHandling setzt `Authorization: Bearer`, kümmert sich um Validierung/Refresh und respektiert `AllowedResourceHosts`, falls im Profil gesetzt. Diese API ist gegenüber direktem Raw-Token-Zugriff zu bevorzugen.

## Context / Abilities

```php
$context = kornsw_authtokenhandling_get_token_context($sourceUid);
$allowed = kornsw_authtokenhandling_has_ability($sourceUid, 'studies.read');
$connected = kornsw_authtokenhandling_is_connected($sourceUid);
```

`has_ability()` betrachtet in V1 Scopes sowie einen optionalen Claim `abilities` als positive Berechtigungen. Ein aktives Token impliziert nicht automatisch fachliche Autorisierung.

## Hooks

- `kornsw_authtokenhandling_token_sources` – Filter über die öffentlichen Pool-Metadaten.
- `kornsw_authtokenhandling_oauth_providers` – Filter zum Registrieren weiterer Operations Provider.
- `kornsw_authtokenhandling_connection_changed` – Action nach erfolgreicher Verbindung.
- `kornsw_authtokenhandling_token_refreshed` – Action nach Refresh.
- `kornsw_authtokenhandling_user_auto_provisioned` – Action nach automatischer Benutzeranlage.
- `kornsw_authtokenhandling_primary_session_terminated` – Action beim Ende einer nicht mehr legitimierten Primary-Session.

## Sicherheitsvertrag

Refresh Tokens werden nie über diese API ausgegeben. Tokens liegen verschlüsselt serverseitig. Ein Consumer darf keine internen Tabellen lesen oder Token selbst refreshen. `try_*` erzeugt niemals Browsernavigation; `require_*` darf einen interaktiven OAuth-Flow einschieben. Fremde Zielhosts sollten über `AllowedResourceHosts` eingeschränkt werden.
