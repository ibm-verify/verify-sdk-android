# Auth Code Flow Demo

This demo application demonstrates OAuth 2.0 Authorization Code Flow with optional PKCE support.

## Setup

### Configuration

Before running the app, you need to create a configuration file:

1. Navigate to `src/main/assets/`
2. Copy `config.properties.sample` to `config.properties`
3. Update the values in `config.properties` with your OAuth server details:

```properties
host=your-oauth-server.com
clientId=your-client-id
redirect=https://your-oauth-server.com/callback
```

**Note:** The `config.properties` file is excluded from Git to prevent accidentally committing sensitive credentials.

### Build-Time Configuration

The `redirect` URL from `config.properties` is parsed at build time and injected into the Android manifest as:
- `auth_redirect_scheme` - The URL scheme (e.g., "https")
- `auth_redirect_host` - The host/domain (e.g., "your-oauth-server.com")
- `auth_redirect_path` - The path component (e.g., "/callback")

These values override the default settings in the Authentication SDK, allowing you to configure the OAuth redirect handling per environment.

## Features

- OAuth 2.0 Authorization Code Flow
- Optional PKCE (Proof Key for Code Exchange) support
- Browser-based authentication
- Token exchange

## Usage

1. Launch the app
2. Review the configuration (host, client ID, redirect URL)
3. Toggle PKCE on/off as needed
4. Tap "Authenticate with browser" to start the flow
5. Complete authentication in the browser
6. View the authorization code in the app