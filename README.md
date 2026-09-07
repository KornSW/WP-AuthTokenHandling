# KornSW AuthTokenHandling

WordPress-Port der AccessTokenHandling-Semantik mit globalem Token-Source-Pool, mehreren Token-Verbindungen pro Benutzer, optionaler Primary-Session-Autorität und einer öffentlichen API für andere Plugins.

## V1

- Ein vollständiges JSON-Array ist die führende Profilkonfiguration.
- `AuthTokenConfig` bleibt als portabler innerer Vertrag erhalten.
- OAuthOperationsProvider: Generic, Google, GitHub.
- Authorization Code + PKCE S256 für interaktive OAuth-Flows.
- Lokale HS256-JWT-Erzeugung/-Validierung.
- serverseitig AES-256-GCM verschlüsselte Access-/Refresh-/ID-Tokens.
- persistente optionale Token-Verbindungen und sessiongebundene Primary-Token-Sets.
- Administrator-Bypass pro konkreter WordPress-Session.
- Auto-Provisioning mit konfigurierbarer Standardrolle.
- E-Mail-Kollisionen mit bestehenden Konten verlangen einmalig das WordPress-Passwort.
- öffentliche Discovery-, Low-Level-Token- und `authorized_request()`-API.
- On-Demand OAuth mit Continuation/Return-URL.

Siehe `doc/WordPress-Integration-API.md` und `doc/AI-Skill-WordPress-AuthTokenHandling.md`.
