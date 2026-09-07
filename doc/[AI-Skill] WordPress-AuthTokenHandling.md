# AI Skill – WordPress AuthTokenHandling Integration

## Ziel

Wenn eine andere Coding-Session ein WordPress-Plugin baut, das ein externes Access Token benötigt, soll sie **KornSW AuthTokenHandling konsumieren statt OAuth selbst zu implementieren**.

## Mentales Modell

```text
Global Token Source Pool
      │
      ├─ stabile TokenSourceUid A
      ├─ stabile TokenSourceUid B
      └─ stabile TokenSourceUid C
               │
               ▼
       UserTokenConnection
               │
       ┌───────┴────────┐
       ▼                ▼
persistent optional   konkrete WP Session
Token Set             Primary Token Set
```

Eine `TokenSourceUid` identifiziert ausschließlich ein konkretes Konfigurationsprofil. Sie ist weder Providername noch Issuing-Strategie.

`AuthTokenConfig` bleibt der portable Konfigurationsvertrag. Issuer beantwortet **welcher Token-Acquisition-Use-Case**, `IOAuthOperationsProvider` beantwortet **wie der konkrete Provider OAuth ausführt**.

## Pflichtregeln für Consumer-Plugins

1. In der Admin-Konfiguration den Token-Source-Pool über `kornsw_authtokenhandling_get_token_source_options()` lesen.
2. Im eigenen Plugin ausschließlich die gewählte `TokenSourceUid` speichern.
3. Keine Client Secrets, Access Tokens oder Refresh Tokens duplizieren.
4. Für normale API-Aufrufe bevorzugt `kornsw_authtokenhandling_authorized_request()` verwenden.
5. Nur wenn das rohe Token technisch nötig ist `kornsw_authtokenhandling_try_get_access_token()` oder `...require_access_token()` verwenden.
6. Für Cron/REST/AJAX immer `try_*`; dort darf kein interaktiver Redirect vorausgesetzt werden.
7. Für Browser-UI darf `require_*` benutzt werden. Bei fehlender/abgelaufener Authentifizierung schiebt AuthTokenHandling den OAuth-Flow mit Continuation ein und kehrt danach zur ursprünglichen URL zurück.
8. Nach der Rückkehr wird der ursprüngliche WordPress-Request neu ausgeführt. Consumer-Code muss daher normal wiederholbar sein; er bekommt keinen serialisierten PHP-Callback.
9. Ein gültiges Token ist nicht automatisch fachliche Berechtigung. Benötigte Scopes/Abilities separat prüfen.
10. Niemals interne AuthTokenHandling-Tabellen direkt lesen oder schreiben.

## Canonical Consumer Example

```php
$sourceUid = get_option('my_plugin_token_source_uid', '');

if ($sourceUid === '') {
    return new WP_Error('token_source_missing', 'Keine Token Source konfiguriert.');
}

$response = kornsw_authtokenhandling_authorized_request(
    $sourceUid,
    'https://api.example.org/data',
    array('method' => 'GET')
);
```

## Canonical Admin Select

```php
echo kornsw_authtokenhandling_render_token_source_select(
    'my_plugin_token_source_uid',
    get_option('my_plugin_token_source_uid', ''),
    array('include_none' => true)
);
```

## On-Demand Interactive Token Acquisition

```php
$token = kornsw_authtokenhandling_require_access_token(
    $sourceUid,
    array('return_url' => admin_url('admin.php?page=my-plugin'))
);
```

Semantik: gültig → sofort liefern; abgelaufen + Refresh → refreshen und liefern; Authentifizierung erforderlich → OAuth starten, Continuation speichern, Callback verarbeiten, zur Return-URL zurückkehren, Consumer läuft erneut und erhält Token.

## Primary WordPress Session Source

Global kann eine Source als Primary bestimmt werden. Deren Token legitimiert zusätzlich zur normalen WordPress-Cookie-Session genau diese Sitzung. Bei jedem relevanten Request fragt die Session Guard die Token-Runtime nach Gültigkeit. Provider/Introspector besitzen etwaige Validation-Caches; es gibt keinen separaten WordPress-Gültigkeitscache davor.

Administratoren können vor dem Primary-OAuth-Redirect bewusst einen lokalen Passwort-Bypass **nur für die konkrete Sitzung** wählen. Das dient als Lockout-Schutz und macht die Sitzung semantisch zu einer normalen WP-Sitzung ohne Primary Token.

## Auto-Provisioning

Direkter Primary-OAuth-Login kann einen neuen WordPress-Benutzer mit der global konfigurierten Standardrolle anlegen. Ein vorhandenes WP-Konto mit gleicher E-Mail wird niemals allein aufgrund der E-Mail übernommen; einmalig ist das bestehende WordPress-Passwort zur Verknüpfung erforderlich.

## Extension Point für neue Provider

Neue Provider werden über `kornsw_authtokenhandling_oauth_providers` registriert und implementieren `KornSW_ATH_IOAuth_Operations_Provider`. Provider-spezifische OAuth-Details einschließlich PKCE-Verwendung gehören hinter diese Grenze und nicht in Consumer-Plugins.
