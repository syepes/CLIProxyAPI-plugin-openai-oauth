# CLIProxyAPI OpenAI OAuth plugin

## Description

A native Go plugin that connects CLIProxyAPI to an OAuth protected, OpenAI compatible API.
It manages access tokens automatically and runs inside the host, not as a separate HTTP proxy.
Supported platforms are Linux and macOS on AMD64/ARM64, and FreeBSD on AMD64.

The plugin uses OAuth application credentials, not browser login.
Each plugin instance configures one OAuth application and does not create an account in the host's OAuth Auth Files list.

## Features

- OAuth 2.0 `client_credentials` with `client_secret_post` or `client_secret_basic` authentication.
- In-memory access tokens with automatic renewal before expiry.
- Shared token exchanges for concurrent requests and backoff during OAuth server outages.
- Continued use of valid cached tokens during temporary renewal failures, never expired tokens.
- One authentication retry after an upstream `401`, before output starts.
- Native Chat Completions and Responses forwarding, including streaming, tools, and continuation IDs.
- Model discovery or an explicit allowlist, with configurable prefixes, aliases, and exclusions.
- An embedded dashboard, protected token-health API, isolated host integration tests, and plugin-store ZIP packaging.

## Build

Use Go 1.27.1 or newer, a working C compiler, and GNU Make (`gmake` on FreeBSD).
The plugin requires a plugin-enabled CLIProxyAPI host supporting C ABI v1 and JSON schema v6; v8.0.12 is the integration-test baseline.

```sh
make check
make build
```

A local build produces `dist/<goos>/<goarch>/openai-oauth.so`, or `openai-oauth.dylib` on macOS.
The adjacent generated `.h` file is not needed for installation.
The host and library must match in OS, architecture, and C runtime.
Build on your deployment distribution if you need a different libc baseline, including Alpine/musl.
`CGO_ENABLED=0` and ordinary Go cross-compilation cannot produce these native libraries.

Local builds use a placeholder repository URL.
Supply your real repository URL for a distributable build:

```sh
make build VERSION=0.1.0 REPOSITORY=https://github.com/YOUR_ACCOUNT/YOUR_REPOSITORY
```

### FreeBSD cross-build

On Linux with Clang, LLD, binutils, curl, and xz installed:

```sh
make freebsd
```

This uses a checksum-pinned FreeBSD 14.4 sysroot and produces `dist/freebsd/amd64/openai-oauth.so`.
It cross-compiles libraries and tests without running a FreeBSD VM or executing the FreeBSD tests.

### Integration tests

Supply an existing plugin-enabled CLIProxyAPI binary matching your platform:

```sh
make integration CPA_BINARY=/absolute/path/to/cli-proxy-api
```

CI runs build and unit checks; real-host integration tests must be run separately with `CPA_BINARY`.
Tests use an isolated host and mock OAuth/API endpoints, not your existing deployment or real credentials.
See [docs/VALIDATION.md](docs/VALIDATION.md) for validation coverage and [docs/PLUGIN_STORE.md](docs/PLUGIN_STORE.md) for packaging.

## Install

1. Stop CLIProxyAPI and back up its configuration.
2. Copy the built library into `<plugins-dir>/<goos>/<goarch>/`, keeping its original filename.
3. Make the OAuth inputs below available to the host process.
4. Merge the configuration below into the existing host configuration.
5. Restart CLIProxyAPI and open **OpenAI OAuth** from its plugin resources menu in CPAMC.

Keep existing API keys, management authentication, providers, and credentials.
The library filename and configuration ID must both remain `openai-oauth`.
Only install the library for the host's platform, such as `darwin/arm64` or `linux/amd64`.

## Configure settings

### Basic configuration

```yaml
plugins:
  enabled: true
  dir: ./plugins
  configs:
    openai-oauth:
      enabled: true
      CLIENT_ID: "env:CLIENT_ID"
      CLIENT_SECRET: "env:CLIENT_SECRET"
      CLIENT_SCOPE: "env:CLIENT_SCOPE"
      TOKEN_URL: "env:TOKEN_URL"
      API_URL: "env:API_URL"
      model_prefix: "oauth"
      models: []
      models_excluded: []
```

See [examples/config.yaml](examples/config.yaml) for environment references or [examples/config.files.yaml](examples/config.files.yaml) for protected-file references.

### OAuth inputs

| Input | Purpose |
| --- | --- |
| `CLIENT_ID` | OAuth application client ID |
| `CLIENT_SECRET` | OAuth application client secret |
| `CLIENT_SCOPE` | OAuth scope string, including space-separated scopes if required |
| `TOKEN_URL` | Full OAuth token endpoint URL |
| `API_URL` | OpenAI-compatible API base URL, including its version prefix, such as `https://api.example.com/v1` |

Each input accepts a literal value, `env:VARIABLE_NAME`, or `file:/absolute/path`.
Omitted inputs use the environment variable with the same name.
Prefer environment or protected-file references for secrets: literal values appear in host configuration and management exports.
Credential files must be regular, non-symlink files with no group or other permissions, normally `0600` or `0400`.
Trailing CR/LF characters are removed; other secret whitespace is preserved.

If your environment uses `SCOPE`, set `CLIENT_SCOPE: "env:SCOPE"`.
Desktop apps may not inherit terminal exports, so use file references or configure the launching service's environment.
The plugin does not source shell scripts or run credential commands.
Reload the plugin after changing environment variables or credential files.
The OAuth server must return `access_token`, a positive `expires_in`, and optionally `token_type: Bearer`.

### Model settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `model_prefix` | `oauth` | Namespace for discovered IDs and configured models without aliases; trailing `/` is optional |
| `models` | `[]` | Optional `{name, alias}` allowlist instead of discovery |
| `models_excluded` | `[]` | Case-insensitive upstream model ID prefixes to exclude |

```yaml
model_prefix: "oauth"
models:
  - name: upstream-model-id
  - name: upstream-model-id
    alias: coding
models_excluded:
  - "text-embedding-"
  - "whisper-"
```

Without an alias, a nonempty `model_prefix` is separated from the upstream name by `/`, so `model_prefix: "oauth"` produces `oauth/upstream-model-id`.
An existing trailing slash is preserved, so `model_prefix: "oauth/"` produces the same ID.
Set `model_prefix: ""` to expose upstream names without a prefix.
An explicit alias replaces the entire public ID and must be unique.
Use the exact IDs returned by the host's `/v1/models` and avoid collisions with other providers.

With no allowlist, discovery requests `API_URL/models` when the provider is registered.
If discovery fails, the plugin remains available for diagnosis but advertises no discovered models.
Use an explicit allowlist when the gateway does not expose `/models`.
Exclusions are literal prefixes, not globs or regular expressions, and apply before aliases to both discovered and configured models.
An allowlist cannot override an exclusion; if all explicit models are excluded, discovery is not used as a fallback.
Discovery does not verify protocol support, so exclude models that do not serve the supported APIs.
Save through **Edit config** or reload the plugin to rebuild model registrations.

### Authentication settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `token_auth_method` | `client_secret_post` | Client authentication method; also supports `client_secret_basic` |
| `token_timeout_seconds` | `10` | Token request timeout, from 1 to 60 seconds |

Renewal starts within a safety window of 20% of token lifetime, capped at 60 seconds.
Failed exchanges back off from 1 to 32 seconds.
Tokens are not persisted across restarts.

### Security and API limits

Open `/v0/resource/plugins/openai-oauth/dashboard` and enter the host management key to inspect token health or request a manual refresh.
The protected API provides `GET /v0/management/plugins/openai-oauth/status` and `POST /v0/management/plugins/openai-oauth/refresh`.
Neither returns secrets, and the dashboard does not persist the management key in browser storage.
Regular token renewal is automatic; manual refresh is only for diagnostics.

Supported client routes are `POST /v1/chat/completions`, `POST /v1/responses`, and non-streaming `POST /v1/responses/compact` when the gateway supports it.
The plugin forwards the matching protocol without translating Responses into Chat Completions.
WebSockets, embeddings, image/audio/video APIs, arbitrary HTTP forwarding, and token counting are not supported.
Ambiguous network failures, gateway `5xx` responses, and partially delivered streams are not retried by the plugin.
Incomplete streams fail rather than reporting success.

Inference uses the host's HTTP transport policy.
OAuth and discovery use a separate client with system certificate validation, redirects disabled, and standard process proxy variables, not provider-specific host proxy settings.
Protect configuration and management access, and treat host request logs as sensitive.
Native plugins run with the host's privileges.
