# Keycloak 24 — login events (jboss-logging event listener)

Source: Keycloak Server Administration Guide, "Auditing and events",
https://www.keycloak.org/docs/24.0.5/server_admin/#auditing-and-events and the
event type reference https://www.keycloak.org/docs-api/24.0.5/javadocs/org/keycloak/events/EventType.html

The listener writes one line per event through the server's Java logging:

    <timestamp> <level> [<logger>] (<thread>) type="<type>", realmId="...", clientId="...", ...

- `timestamp` — `yyyy-MM-dd HH:mm:ss,SSS`
- `level` — `INFO` for successful events, `WARN` for errors (as configured here)
- `logger` — the Java logger, `org.keycloak.events`
- `thread` — the server thread that handled the request

## The event attributes, as key="value" pairs

- `type` — the event type: `LOGIN`, `LOGIN_ERROR`, ...
- `realmId` — the realm (tenant) the event happened in, as a UUID
- `clientId` — the OAuth client - the APPLICATION - the login was for
- `userId` — Keycloak's id of the user, a UUID; `null` if the user does not exist
- `username` — the login name that was submitted
- `ipAddress` — the address the request came from
- `error` — on an error event, its code: `invalid_user_credentials`, `user_not_found`, `client_not_found`
- `sessionId`, `authSessionParentId`, `authSessionTabId` — session identifiers
- `auth_method` — the protocol, `openid-connect`
- `grant_type` — the OAuth grant, `password` here
- `client_auth_method` — how the client authenticated
- `token_id`, `refresh_token_id`, `refresh_token_type`, `scope` — the tokens issued on success
