/**
   * Maximum time allowed for a complete connection and request.


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
export type IDuration = number | string;

/**
 * undefined
 */
export interface ITls {
  /**
   * undefined
   */
  use_server_identity: boolean;
  /**
   * undefined
   */
  client_certificate_file: string;
  /**
   * undefined
   */
  client_certificate_key_file: string;
  root_ca_pem_files: Array<string>;
}

/**
   * HTTPLoader can load Caddy configs over HTTP(S).

If the response is not a JSON config, a config adapter must be specified
either in the loader config (`adapter`), or in the Content-Type HTTP header
returned in the HTTP response from the server. The Content-Type header is
read just like the admin API's `/load` endpoint. Uf you don't have control
over the HTTP server (but can still trust its response), you can override
the Content-Type header by setting the `adapter` property in this config.

   */
export interface IHttpLoader {
  /**
   * The method for the request. Default: GET
   */
  method: string;
  /**
   * The URL of the request.
   */
  url: string;
  /**
   * A Header represents the key-value pairs in an HTTP header.

The keys should be in canonical form, as returned by
CanonicalHeaderKey.

   */
  header: Record<string, Array<string>>;
  /**
   * Maximum time allowed for a complete connection and request.


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  timeout: IDuration;
  /**
   * The name of the config adapter to use, if any. Only needed
if the HTTP response is not a JSON config and if the server's
Content-Type header is missing or incorrect.
   */
  adapter: string;
  tls: ITls;
}

/**
 * undefined
 */
export interface INats {
  /**
   * undefined
   */
  hosts: string;
  /**
   * undefined
   */
  bucket: string;
  /**
   * undefined
   */
  creds: string;
  /**
   * undefined
   */
  inbox_prefix: string;
  /**
   * undefined
   */
  connection_name: string;
}

/**
   * FileStorage is a certmagic.Storage wrapper for certmagic.FileStorage.

   */
export interface IFileStorage {
  /**
   * The base path to the folder used for storage.
   */
  root: string;
}

/**
   * RedisStorage contain Redis client, and plugin option

   */
export interface IRedisStorage {
  /**
   * undefined
   */
  address: string;
  /**
   * undefined
   */
  host: string;
  /**
   * undefined
   */
  port: string;
  /**
   * undefined
   */
  db: number;
  /**
   * undefined
   */
  password: string;
  /**
   * undefined
   */
  timeout: number;
  /**
   * undefined
   */
  key_prefix: string;
  /**
   * undefined
   */
  value_prefix: string;
  /**
   * undefined
   */
  aes_key: string;
  /**
   * undefined
   */
  tls_enabled: boolean;
  /**
   * undefined
   */
  tls_insecure: boolean;
}

/**
   * A highly available storage module that integrates with HashiCorp Vault.

   */
export interface IVaultStorage {
  addresses: Array<string>;
  /**
   * Local path to read the access token from. Updates on that file will be
detected and automatically read. (As fallback the the environment
variable "VAULT_TOKEN" will be used, but it will only be read once on
startup.)
   */
  token_path: string;
  /**
   * Path of the KVv2 mount to use. (Default is "kv".)
   */
  secrets_mount_path: string;
  /**
   * Path in the KVv2 mount to use. (Default is "caddy".)
   */
  secrets_path_prefix: string;
  /**
   * Limit of connection retries after which to fail a request. (Default is 3.)
   */
  max_retries: number;
  /**
   * Timeout for locks (in seconds). (Default is 60.)
   */
  lock_timeout: number;
  /**
   * Interval for checking lock status (in seconds). (Default is 5.)
   */
  lock_check_interval: number;
}

/**
   * CaddyStorageGCS implements a caddy storage backend for Google Cloud Storage.

   */
export interface ICaddyStorageGcs {
  /**
   * BucketName is the name of the storage bucket.
   */
  "bucket-name": string;
  /**
   * EncryptionKeySet is the path of a json tink encryption keyset
   */
  "encryption-key-set": string;
}

/**
   * ConsulStorage allows to store certificates and other TLS resources
in a shared cluster environment using Consul's key/value-store.
It uses distributed locks to ensure consistency.

   */
export interface IConsulStorage {
  /**
   * undefined
   */
  address: string;
  /**
   * undefined
   */
  token: string;
  /**
   * undefined
   */
  timeout: number;
  /**
   * undefined
   */
  prefix: string;
  /**
   * undefined
   */
  value_prefix: string;
  aes_key: Array<any>;
  /**
   * undefined
   */
  tls_enabled: boolean;
  /**
   * undefined
   */
  tls_insecure: boolean;
}

/**
 * undefined
 */
export interface IS3 {
  /**
   * undefined
   */
  host: string;
  /**
   * undefined
   */
  bucket: string;
  /**
   * undefined
   */
  access_id: string;
  /**
   * undefined
   */
  secret_key: string;
  /**
   * undefined
   */
  prefix: string;
}

export type IEnvRedis = any;

/**
 * undefined
 */
export interface IPostgresStorage {
  /**
   * A Duration represents the elapsed time between two instants
as an int64 nanosecond count. The representation limits the
largest representable duration to approximately 290 years.

   */
  query_timeout: IDuration;
  /**
   * A Duration represents the elapsed time between two instants
as an int64 nanosecond count. The representation limits the
largest representable duration to approximately 290 years.

   */
  lock_timeout: IDuration;
  /**
   * undefined
   */
  host: string;
  /**
   * undefined
   */
  port: string;
  /**
   * undefined
   */
  user: string;
  /**
   * undefined
   */
  password: string;
  /**
   * undefined
   */
  dbname: string;
  /**
   * undefined
   */
  sslmode: string;
  /**
   * undefined
   */
  connection_string: string;
}

/**
 * undefined
 */
export interface IMysqlStorage {
  /**
   * A Duration represents the elapsed time between two instants
as an int64 nanosecond count. The representation limits the
largest representable duration to approximately 290 years.

   */
  query_timeout: IDuration;
  /**
   * A Duration represents the elapsed time between two instants
as an int64 nanosecond count. The representation limits the
largest representable duration to approximately 290 years.

   */
  lock_timeout: IDuration;
  /**
   * undefined
   */
  dsn: string;
}

export type IStorage =
  | INats
  | IFileStorage
  | IRedisStorage
  | IVaultStorage
  | ICaddyStorageGcs
  | IConsulStorage
  | IS3
  | IEnvRedis
  | IPostgresStorage
  | IMysqlStorage;

/**
   * StorageLoader is a dynamic configuration loader that reads the configuration from a Caddy storage. If
the storage is not configured, the default storage is used, which may be the file-system if none is configured
If the `key` is not configured, the default key is `config/caddy.json`.

   */
export interface IStorageLoader {
  /**
   * StorageRaw is a storage module that defines how/where Caddy
stores assets (such as TLS certificates). The default storage
module is `caddy.storage.file_system` (the local file system),
and the default path
[depends on the OS and environment](/docs/conventions#data-directory).
   */
  storage: IStorage;
  /**
   * The storage key at which the configuration is to be found
   */
  key: string;
  /**
   * The adapter to use to convert the storage's contents to Caddy JSON.
   */
  adapter: string;
}

export type IConfigLoaders = IHttpLoader | IStorageLoader;

/**
   * Options pertaining to configuration management.


ConfigSettings configures the management of configuration.
   */
export interface IConfigSettings {
  /**
   * Whether to keep a copy of the active config on disk. Default is true.
Note that "pulled" dynamic configs (using the neighboring "load" module)
are not persisted; only configs that are pushed to Caddy get persisted.
   */
  persist: boolean;
  /**
   * Loads a configuration to use. This is helpful if your configs are
managed elsewhere, and you want Caddy to pull its config dynamically
when it starts. The pulled config completely replaces the current
one, just like any other config load. It is an error if a pulled
config is configured to pull another config.

EXPERIMENTAL: Subject to change.
   */
  load: IConfigLoaders;
}

/**
   * Options that establish this server's identity. Identity refers to
credentials which can be used to uniquely identify and authenticate
this server instance. This is required if remote administration is
enabled (but does not require remote administration to be enabled).
Default: no identity management.


IdentityConfig configures management of this server's identity. An identity
consists of credentials that uniquely verify this instance; for example,
TLS certificates (public + private key pairs).
   */
export interface IIdentityConfig {
  identifiers: Array<string>;
  issuers: Array<any>;
}

/**
   * Limits what the associated identities are allowed to do.
If unspecified, all permissions are granted.


AdminPermissions specifies what kinds of requests are allowed
to be made to the admin endpoint.
   */
export interface IAdminPermissions {
  paths: Array<string>;
  methods: Array<string>;
}

/**
   * List of access controls for this secure admin endpoint.
This configures TLS mutual authentication (i.e. authorized
client certificates), but also application-layer permissions
like which paths and methods each identity is authorized for.


AdminAccess specifies what permissions an identity or group
of identities are granted.
   */
export interface IAdminAccess {
  public_keys: Array<string>;
  permissions: Array<IAdminPermissions>;
}

/**
   * Options pertaining to remote administration. By default, remote
administration is disabled. If enabled, identity management must
also be configured, as that is how the endpoint is secured.
See the neighboring "identity" object.

EXPERIMENTAL: This feature is subject to change.


RemoteAdmin enables and configures remote administration. If enabled,
a secure listener enforcing mutual TLS authentication will be started
on a different port from the standard plaintext admin server.

This endpoint is secured using identity management, which must be
configured separately (because identity management does not depend
on remote administration). See the admin/identity config struct.

EXPERIMENTAL: Subject to change.
   */
export interface IRemoteAdmin {
  /**
   * The address on which to start the secure listener.
Default: :2021
   */
  listen: string;
  access_control: Array<IAdminAccess>;
}

/**
   * AdminConfig configures Caddy's API endpoint, which is used
to manage Caddy while it is running.

   */
export interface IAdminConfig {
  /**
   * If true, the admin endpoint will be completely disabled.
Note that this makes any runtime changes to the config
impossible, since the interface to do so is through the
admin endpoint.
   */
  disabled: boolean;
  /**
   * The address to which the admin endpoint's listener should
bind itself. Can be any single network address that can be
parsed by Caddy. Default: localhost:2019
   */
  listen: string;
  /**
   * If true, CORS headers will be emitted, and requests to the
API will be rejected if their `Host` and `Origin` headers
do not match the expected value(s). Use `origins` to
customize which origins/hosts are allowed. If `origins` is
not set, the listen address is the only value allowed by
default. Enforced only on local (plaintext) endpoint.
   */
  enforce_origin: boolean;
  origins: Array<string>;
  config: IConfigSettings;
  identity: IIdentityConfig;
  remote: IRemoteAdmin;
}

/**
   * DiscardWriter discards all writes.

   */
export type IDiscardWriter = any;

/**
   * StderrWriter writes logs to standard error.

   */
export type IStderrWriter = any;

/**
   * StdoutWriter writes logs to standard out.

   */
export type IStdoutWriter = any;

/**
   * FileWriter can write logs to files. By default, log files
are rotated ("rolled") when they get large, and old log
files get deleted, to ensure that the process does not
exhaust disk space.

   */
export interface IFileWriter {
  /**
   * Filename is the name of the file to write.
   */
  filename: string;
  /**
   * Roll toggles log rolling or rotation, which is
enabled by default.
   */
  roll: boolean;
  /**
   * When a log file reaches approximately this size,
it will be rotated.
   */
  roll_size_mb: number;
  /**
   * Whether to compress rolled files. Default: true
   */
  roll_gzip: boolean;
  /**
   * Whether to use local timestamps in rolled filenames.
Default: false
   */
  roll_local_time: boolean;
  /**
   * The maximum number of rolled log files to keep.
Default: 10
   */
  roll_keep: number;
  /**
   * How many days to keep rolled log files. Default: 90
   */
  roll_keep_days: number;
}

/**
   * NetWriter implements a log writer that outputs to a network socket. If
the socket goes down, it will dump logs to stderr while it attempts to
reconnect.

   */
export interface INetWriter {
  /**
   * The address of the network socket to which to connect.
   */
  address: string;
  /**
   * The timeout to wait while connecting to the socket.


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  dial_timeout: IDuration;
  /**
   * If enabled, allow connections errors when first opening the
writer. The error and subsequent log entries will be reported
to stderr instead until a connection can be re-established.
   */
  soft_start: boolean;
}

/**
 * undefined
 */
export interface IInfluxLog {
  /**
   * undefined
   */
  host: string;
  /**
   * undefined
   */
  token: string;
  /**
   * undefined
   */
  org: string;
  /**
   * undefined
   */
  bucket: string;
  /**
   * undefined
   */
  measurement: string;
  /**
   * undefined
   */
  tags: Record<string, string>;
}

/**
   * Writer is a influxdb client to write time series data

   */
export type IWriter = any;

/**
   * GraphiteLog is a Caddy logger used to send server activity to a Graphite
database.

Templating is available as follow :

	.Level
	.Date
	.Logger
	.Msg
	.Request
		.RemoteIP
		.RemotePort
		.ClientIP
		.Proto
		.Method
		.Host
		.URI
		.Headers
	.BytesRead
	.UserID
	.Duration
	.Size
	.Status
	.RespHeaders map[string][]string

	.DirName
	.FileName

   */
export interface IGraphiteLog {
  /**
   * IP address or host name of the graphite server
   */
  server: string;
  /**
   * Port number to be used (usually 2003)
   */
  port: number;
  /**
   * Metrics Path, can be templated
   */
  path: string;
  /**
   * Value to be sent, can be templated
   */
  value: string;
  methods: Array<string>;
}

export type IWriters =
  | IDiscardWriter
  | IStderrWriter
  | IStdoutWriter
  | IFileWriter
  | INetWriter
  | IInfluxLog
  | IWriter
  | IGraphiteLog;

/**
   * Sink is the destination for all unstructured logs emitted
from Go's standard library logger. These logs are common
in dependencies that are not designed specifically for use
in Caddy. Because it is global and unstructured, the sink
lacks most advanced features and customizations.


StandardLibLog configures the default Go standard library
global logger in the log package. This is necessary because
module dependencies which are not built specifically for
Caddy will use the standard logger. This is also known as
the "sink" logger.
   */
export interface IStandardLibLog {
  /**
   * The module that writes out log entries for the sink.
   */
  writer: IWriters;
}

/**
   * AppendEncoder can be used to add fields to all log entries
that pass through it. It is a wrapper around another
encoder, which it uses to actually encode the log entries.
It is most useful for adding information about the Caddy
instance that is producing the log entries, possibly via
an environment variable.

   */
export interface IAppendEncoder {
  wrap: IEncoders;
  /**
   * undefined
   */
  fields: Record<string, any>;
}

/**
   * ConsoleEncoder encodes log entries that are mostly human-readable.

   */
export interface IConsoleEncoder {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * Recognized values are: unix_seconds_float, unix_milli_float, unix_nano, iso8601, rfc3339, rfc3339_nano, wall, wall_milli, wall_nano, common_log.
The value may also be custom format per the Go `time` package layout specification, as described [here](https://pkg.go.dev/time#pkg-constants).
   */
  time_format: string;
  /**
   * undefined
   */
  time_local: boolean;
  /**
   * Recognized values are: s/second/seconds, ns/nano/nanos, ms/milli/millis, string.
Empty and unrecognized value default to seconds.
   */
  duration_format: string;
  /**
   * Recognized values are: lower, upper, color.
Empty and unrecognized value default to lower.
   */
  level_format: string;
}

/**
 * A list of actions to apply to the cookies.
 */
export interface ICookieFilterAction {
  /**
   * `replace` to replace the value of the cookie, `hash` to replace it with the 4 initial bytes of the SHA-256 of its content or `delete` to remove it entirely.
   */
  type: string;
  /**
   * The name of the cookie.
   */
  name: string;
  /**
   * The value to use as replacement if the action is `replace`.
   */
  value: string;
}

/**
   * CookieFilter is a Caddy log field filter that filters
cookies.

This filter updates the logged HTTP header string
to remove, replace or hash cookies containing sensitive data. For instance,
it can be used to redact any kind of secrets, such as session IDs.

If several actions are configured for the same cookie name, only the first
will be applied.

   */
export interface ICookieFilter {
  actions: Array<ICookieFilterAction>;
}

/**
   * DeleteFilter is a Caddy log field filter that
deletes the field.

   */
export type IDeleteFilter = any;

/**
   * HashFilter is a Caddy log field filter that
replaces the field with the initial 4 bytes
of the SHA-256 hash of the content. Operates
on string fields, or on arrays of strings
where each string is hashed.

   */
export type IHashFilter = any;

/**
   * IPMaskFilter is a Caddy log field filter that
masks IP addresses in a string, or in an array
of strings. The string may be a comma separated
list of IP addresses, where all of the values
will be masked.

   */
export interface IIpMaskFilter {
  /**
   * The IPv4 mask, as an subnet size CIDR.
   */
  ipv4_cidr: number;
  /**
   * The IPv6 mask, as an subnet size CIDR.
   */
  ipv6_cidr: number;
}

/**
 * A list of actions to apply to the query parameters of the URL.
 */
export interface IQueryFilterAction {
  /**
   * `replace` to replace the value(s) associated with the parameter(s), `hash` to replace them with the 4 initial bytes of the SHA-256 of their content or `delete` to remove them entirely.
   */
  type: string;
  /**
   * The name of the query parameter.
   */
  parameter: string;
  /**
   * The value to use as replacement if the action is `replace`.
   */
  value: string;
}

/**
   * QueryFilter is a Caddy log field filter that filters
query parameters from a URL.

This filter updates the logged URL string to remove, replace or hash
query parameters containing sensitive data. For instance, it can be
used to redact any kind of secrets which were passed as query parameters,
such as OAuth access tokens, session IDs, magic link tokens, etc.

   */
export interface IQueryFilter {
  actions: Array<IQueryFilterAction>;
}

/**
   * RegexpFilter is a Caddy log field filter that
replaces the field matching the provided regexp
with the indicated string. If the field is an
array of strings, each of them will have the
regexp replacement applied.

   */
export interface IRegexpFilter {
  /**
   * The regular expression pattern defining what to replace.
   */
  regexp: string;
  /**
   * The value to use as replacement
   */
  value: string;
}

/**
   * RenameFilter is a Caddy log field filter that
renames the field's key with the indicated name.

   */
export interface IRenameFilter {
  /**
   * undefined
   */
  name: string;
}

/**
   * ReplaceFilter is a Caddy log field filter that
replaces the field with the indicated string.

   */
export interface IReplaceFilter {
  /**
   * undefined
   */
  value: string;
}

/**
   * BasicAuthFilter is a Caddy log field filter that replaces the a base64 encoded authorization
header with just the user name.

   */
export type IBasicAuthFilter = any;

/**
   * TLSCipherFilter is Caddy log field filter that replaces the numeric TLS cipher_suite value with
the string representation.

   */
export type ITlsCipherFilter = any;

/**
   * TLSVersionFilter is a Caddy log field filter that replaces the numeric TLS version with the
string version and optionally adds a prefix.

   */
export interface ITlsVersionFilter {
  /**
   * Prefix is a constant string that will be added before the replaced version string.
   */
  prefix: string;
}

export interface IFilter {
  cookie: ICookieFilter;
  delete: IDeleteFilter;
  hash: IHashFilter;
  ip_mask: IIpMaskFilter;
  query: IQueryFilter;
  regexp: IRegexpFilter;
  rename: IRenameFilter;
  replace: IReplaceFilter;
  basic_auth_user: IBasicAuthFilter;
  tls_cipher: ITlsCipherFilter;
  tls_version: ITlsVersionFilter;
}

/**
   * FilterEncoder can filter (manipulate) fields on
log entries before they are actually encoded by
an underlying encoder.

   */
export interface IFilterEncoder {
  wrap: IEncoders;
  /**
   * A map of field names to their filters. Note that this
is not a module map; the keys are field names.

Nested fields can be referenced by representing a
layer of nesting with `>`. In other words, for an
object like `{"a":{"b":0}}`, the inner field can
be referenced as `a>b`.

The following fields are fundamental to the log and
cannot be filtered because they are added by the
underlying logging library as special cases: ts,
level, logger, and msg.
   */
  fields: IFilter;
}

/**
   * JSONEncoder encodes entries as JSON.

   */
export interface IJsonEncoder {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * Recognized values are: unix_seconds_float, unix_milli_float, unix_nano, iso8601, rfc3339, rfc3339_nano, wall, wall_milli, wall_nano, common_log.
The value may also be custom format per the Go `time` package layout specification, as described [here](https://pkg.go.dev/time#pkg-constants).
   */
  time_format: string;
  /**
   * undefined
   */
  time_local: boolean;
  /**
   * Recognized values are: s/second/seconds, ns/nano/nanos, ms/milli/millis, string.
Empty and unrecognized value default to seconds.
   */
  duration_format: string;
  /**
   * Recognized values are: lower, upper, color.
Empty and unrecognized value default to lower.
   */
  level_format: string;
}

/**
   * LogfmtEncoder encodes log entries as logfmt:
https://www.brandur.org/logfmt

Note that logfmt does not encode nested structures
properly, so it is not a good fit for most logs.

⚠️ DEPRECATED. Do not use. It will eventually be removed
from the standard Caddy modules. For more information,
see https://github.com/caddyserver/caddy/issues/3575.

   */
export interface ILogfmtEncoder {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * undefined
   */
  time_format: string;
  /**
   * undefined
   */
  duration_format: string;
  /**
   * undefined
   */
  level_format: string;
}

/**
   * SingleFieldEncoder writes a log entry that consists entirely
of a single string field in the log entry. This is useful
for custom, self-encoded log entries that consist of a
single field in the structured log entry.

   */
export interface ISingleFieldEncoder {
  /**
   * undefined
   */
  field: string;
  fallback: IEncoders;
}

/**
 * undefined
 */
export interface ICompat {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * undefined
   */
  time_format: string;
  /**
   * undefined
   */
  duration_format: string;
  /**
   * undefined
   */
  level_format: string;
  /**
   * undefined
   */
  template: string;
  /**
   * undefined
   */
  placeholder: string;
}

/**
   * TransformEncoder allows the user to provide custom template for log prints. The
encoder builds atop the json encoder, thus it follows its message structure. The placeholders
are namespaced by the name of the app logging the message.

   */
export interface ITransformEncoder {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * undefined
   */
  time_format: string;
  /**
   * undefined
   */
  duration_format: string;
  /**
   * undefined
   */
  level_format: string;
  /**
   * undefined
   */
  template: string;
  /**
   * undefined
   */
  placeholder: string;
}

/**
 * undefined
 */
export interface IElasticEncoder {
  /**
   * undefined
   */
  message_key: string;
  /**
   * undefined
   */
  level_key: string;
  /**
   * undefined
   */
  time_key: string;
  /**
   * undefined
   */
  name_key: string;
  /**
   * undefined
   */
  caller_key: string;
  /**
   * undefined
   */
  stacktrace_key: string;
  /**
   * undefined
   */
  line_ending: string;
  /**
   * undefined
   */
  time_format: string;
  /**
   * undefined
   */
  duration_format: string;
  /**
   * undefined
   */
  level_format: string;
}

export type IEncoders =
  | IAppendEncoder
  | IConsoleEncoder
  | IFilterEncoder
  | IJsonEncoder
  | ILogfmtEncoder
  | ISingleFieldEncoder
  | ICompat
  | ITransformEncoder
  | IElasticEncoder;

/**
   * Sampling configures log entry sampling. If enabled,
only some log entries will be emitted. This is useful
for improving performance on extremely high-pressure
servers.


LogSampling configures log entry sampling.
   */
export interface ILogSampling {
  /**
   * The window over which to conduct sampling.


A Duration represents the elapsed time between two instants
as an int64 nanosecond count. The representation limits the
largest representable duration to approximately 290 years.
   */
  interval: IDuration;
  /**
   * Log this many entries within a given level and
message for each interval.
   */
  first: number;
  /**
   * If more entries with the same level and message
are seen during the same interval, keep one in
this many entries until the end of the interval.
   */
  thereafter: number;
}

/**
   * Logs are your logs, keyed by an arbitrary name of your
choosing. The default log can be customized by defining
a log called "default". You can further define other logs
and filter what kinds of entries they accept.


CustomLog represents a custom logger configuration.

By default, a log will emit all log entries. Some entries
will be skipped if sampling is enabled. Further, the Include
and Exclude parameters define which loggers (by name) are
allowed or rejected from emitting in this log. If both Include
and Exclude are populated, their values must be mutually
exclusive, and longer namespaces have priority. If neither
are populated, all logs are emitted.
   */
export interface ICustomLog {
  writer: IWriters;
  /**
   * The encoder is how the log entries are formatted or encoded.
   */
  encoder: IEncoders;
  /**
   * Level is the minimum level to emit, and is inclusive.
Possible levels: DEBUG, INFO, WARN, ERROR, PANIC, and FATAL
   */
  level: string;
  sampling: ILogSampling;
  include: Array<string>;
  exclude: Array<string>;
}

/**
   * Logging facilitates logging within Caddy. The default log is
called "default" and you can customize it. You can also define
additional logs.

By default, all logs at INFO level and higher are written to
standard error ("stderr" writer) in a human-readable format
("console" encoder if stdout is an interactive terminal, "json"
encoder otherwise).

All defined logs accept all log entries by default, but you
can filter by level and module/logger names. A logger's name
is the same as the module's name, but a module may append to
logger names for more specificity. For example, you can
filter logs emitted only by HTTP handlers using the name
"http.handlers", because all HTTP handler module names have
that prefix.

Caddy logs (except the sink) are zero-allocation, so they are
very high-performing in terms of memory and CPU time. Enabling
sampling can further increase throughput on extremely high-load
servers.

   */
export interface ILogging {
  sink: IStandardLibLog;
  /**
   * undefined
   */
  logs: Record<string, ICustomLog>;
}

/**
   * Cmd is the module configuration

   */
export interface ICmd {
  /**
   * The command to run.
   */
  command: string;
  args: Array<string>;
  /**
   * The directory to run the command from.
Defaults to current directory.
   */
  directory: string;
  /**
   * If the command should run in the foreground.
By default, commands run in the background and doesn't
affect Caddy.
Setting this makes the command run in the foreground.
Note that failure of a startup command running in the
foreground may prevent Caddy from starting.
   */
  foreground: boolean;
  /**
   * Timeout for the command. The command will be killed
after timeout has elapsed if it is still running.
Defaults to 10s.
   */
  timeout: string;
  at: Array<string>;
  log: IWriters;
  err_log: IWriters;
}

/**
   * App is top level module that runs shell commands.

   */
export interface IApp {
  commands: Array<ICmd>;
}

/**
   * reconnect is a module that provides an additional "reconnect" network type
that can be used to reconnect to a [network address] if the initial
connection fails. Caddy will bind to the address as soon as it is available.
Until that point, the listener will block in the Accept() loop. This is
useful if you want to configure Caddy to bind on an address that is
potentially not available at startup time.

You can configure the following networks:
- reconnect+tcp
- reconnect+tcp4
- reconnect+tcp6
- reconnect+udp
- reconnect+udp4
- reconnect+udp6

These are equivalent to the standard networks, except that they will block
until the address is available.

For example, to start Caddy as an http server on 192.168.1.2:443, even if
that address is not available at startup time, you can add the following
listener to the [apps.http.servers.{srv}.listen] list:

	"listen": ["reconnect+tcp/192.168.1.2:443"]

Note: This module has only been tested with Linux. Other operating systems
might not work as intended.

[apps.http.servers.{srv}.listen]: https://caddyserver.com/docs/json/apps/http/servers/listen/
[network address]: https://caddyserver.com/docs/conventions#network-addresses

   */
export type IReconnect = any;

/**
   * The root certificate to use; if null, one will be generated.


KeyPair represents a public-private key pair, where the
public key is also called a certificate.
   */
export interface IKeyPair {
  /**
   * The certificate. By default, this should be the path to
a PEM file unless format is something else.
   */
  certificate: string;
  /**
   * The private key. By default, this should be the path to
a PEM file unless format is something else.
   */
  private_key: string;
  /**
   * The format in which the certificate and private
key are provided. Default: pem_file
   */
  format: string;
}

/**
   * The certificate authorities to manage. Each CA is keyed by an
ID that is used to uniquely identify it from other CAs.
At runtime, the GetCA() method should be used instead to ensure
the default CA is provisioned if it hadn't already been.
The default CA ID is "local".


CA describes a certificate authority, which consists of
root/signing certificates and various settings pertaining
to the issuance of certificates and trusting them.
   */
export interface ICa {
  /**
   * The user-facing name of the certificate authority.
   */
  name: string;
  /**
   * The name to put in the CommonName field of the
root certificate.
   */
  root_common_name: string;
  /**
   * The name to put in the CommonName field of the
intermediate certificates.
   */
  intermediate_common_name: string;
  /**
   * The lifetime for the intermediate certificates


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  intermediate_lifetime: IDuration;
  /**
   * Whether Caddy will attempt to install the CA's root
into the system trust store, as well as into Java
and Mozilla Firefox trust stores. Default: true.
   */
  install_trust: boolean;
  root: IKeyPair;
  intermediate: IKeyPair;
  storage: IStorage;
}

/**
   * PKI provides Public Key Infrastructure facilities for Caddy.

This app can define certificate authorities (CAs) which are capable
of signing certificates. Other modules can be configured to use
the CAs defined by this app for issuing certificates or getting
key information needed for establishing trust.

   */
export interface IPki {
  /**
   * undefined
   */
  certificate_authorities: Record<string, ICa>;
}

/**
 * Workers configures the worker scripts to start.
 */
export interface IWorkerConfig {
  /**
   * FileName sets the path to the worker script.
   */
  file_name: string;
  /**
   * Num sets the number of workers to start.
   */
  num: number;
  /**
   * undefined
   */
  env: Record<string, string>;
}

/**
 * undefined
 */
export interface IFrankenPhpApp {
  /**
   * NumThreads sets the number of PHP threads to start. Default: 2x the number of available CPUs.
   */
  num_threads: number;
  workers: Array<IWorkerConfig>;
}

/**
   * CrowdSec is a Caddy App that functions as a CrowdSec bouncer. It acts
as a CrowdSec API client as well as a local cache for CrowdSec decisions,
which can be used by the HTTP handler and Layer4 matcher to decide if
a request or connection is allowed or not.

   */
export interface ICrowdSec {
  /**
   * APIKey for the CrowdSec Local API
   */
  api_key: string;
  /**
   * APIUrl for the CrowdSec Local API. Defaults to http://127.0.0.1:8080/
   */
  api_url: string;
  /**
   * TickerInterval is the interval the StreamBouncer uses for querying
the CrowdSec Local API. Defaults to "10s".
   */
  ticker_interval: string;
  /**
   * EnableStreaming indicates whether the StreamBouncer should be used.
If it's false, the LiveBouncer is used. The StreamBouncer keeps
CrowdSec decisions in memory, resulting in quicker lookups. The
LiveBouncer will perform an API call to your CrowdSec instance.
Defaults to true.
   */
  enable_streaming: boolean;
  /**
   * EnableHardFails indicates whether calls to the CrowdSec API should
result in hard failures, resulting in Caddy quitting vs.
Caddy continuing operation (with a chance of not performing)
validations. Defaults to false.
   */
  enable_hard_fails: boolean;
}

/**
   * Allow is PortForwardingAsker module which always allows the session

   */
export type IAllow = any;

/**
   * Allow is PortForwardingAsker module which always rejects the session

   */
export type IDeny = any;

export type ILocalforward = IAllow | IDeny;

export type IReverseforward = IAllow | IDeny;

export type IPty = IAllow | IDeny;

/**
   * Chained is a multi-authorizer module that authorizes a session against multiple authorizers

   */
export interface IChained {
  authorize: Array<any>;
}

/**
   * MaxSession is an authorizer that permits sessions so long as the
number of active sessions is below the specified maximum.

   */
export interface IMaxSession {
  /**
   * The maximum number of active sessions
   */
  max_sessions: number;
}

/**
   * Public authorizes all sessions

   */
export type IPublic = any;

/**
   * Reject rejects all sessions

   */
export type IReject = any;

export type IAuthorizers = IChained | IMaxSession | IPublic | IReject;

/**
   * InMemSFTP is an in-memory SFTP server allowing shared space
between all users. It starts with an empty space.
Warning: For illustration purposes only!

   */
export type IInMemSftp = any;

export interface ISubsystem {
  inmem_sftp: IInMemSftp;
}

/**
   * Fallback signer checks if the RSA, Ed25519, and ECDSA private keys exist in the storage to load. If they're absent,
RSA-4096 and Ed25519 keys are generated and stored. The ECDSA key is only loaded, not generated.
It is the default signer.

   */
export interface IFallback {
  storage: IStorage;
}

/**
   * The `git` filesystem module uses a git repository as the
virtual filesystem.

   */
export interface IRepo {
  /**
   * The URL of the git repository
   */
  url: string;
  /**
   * The reference to clone the repository at.
An empty value means HEAD.
   */
  ref: string;
  /**
   * The period between ref refreshes


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  refresh_period: IDuration;
}

export type IFs = IRepo;

/**
   * The collection of `signer.Key` resources.
Relative paths are appended to the path of the current working directory.
The supported PEM types and algorithms are:
- RSA PRIVATE KEY: RSA
- PRIVATE KEY: RSA, ECDSA, ed25519
- EC PRIVATE KEY: ECDSA
- DSA PRIVATE KEY: DSA
- OPENSSH PRIVATE KEY: RSA, ed25519, ECDSA


Key is a generic holder of the location and passphrase of key (abstract) files
   */
export interface IKey {
  /**
   * Source is the identifying path of the key depending on the source. In the case of `file` signer,
`Source` refers to the path to the file on disk in relative or absolute path forms. Other signers
are free to define the semantics of the field.
   */
  source: string;
  /**
   * A non-empty value means the key is protected with a passphrase
   */
  passphrase: string;
}

/**
   * File is a session signer that uses pre-existing keys, which may be backed
as files

   */
export interface IFile {
  /**
   * The file system implementation to use. The default is the local disk file system.
File system modules used here must implement the fs.FS interface
   */
  file_system: IFs;
  keys: Array<IKey>;
}

export type ISigners = IFallback | IFile;

/**
   * Lifted and merged from golang.org/x/crypto/ssh
ProvidedConfig holds server specific configuration data.

   */
export interface IProvidedConfig {
  /**
   * The session signers to be loaded. The field takes the form:
"signer": {
		"module": "<signer module name>"
		... signer module config
}
If empty, the default module is "fallback", which will load existing keys, or generates and stores them if non-existent.
   */
  signer: ISigners;
  key_exchanges: Array<string>;
  ciphers: Array<string>;
  ma_cs: Array<string>;
  /**
   * NoClientAuth is true if clients are allowed to connect without
authenticating.
   */
  no_client_auth: boolean;
  /**
   * MaxAuthTries specifies the maximum number of authentication attempts
permitted per connection. If set to a negative number, the number of
attempts are unlimited. If set to zero, the number of attempts are limited
to 6.
   */
  max_auth_tries: number;
  authentication: IConfig;
  /**
   * ServerVersion is the version identification string to announce in
the public handshake.
If empty, a reasonable default is used.
Note that RFC 4253 section 4.2 requires that this string start with
"SSH-2.0-".
   */
  server_version: string;
}

export type ILoaders = IProvidedConfig;

/**
   * List of configurators that could configure the server per matchers and config providers


Configurator holds the set of matchers and configurators that will apply custom server
configurations if matched
   */
export interface IConfigurator {
  /**
   * RawConfigMatcherSet is a group of matcher sets in their raw, JSON form.

   */
  match: Array<any>;
  /**
   * The config provider that shall configure the server for the matched session.
"config": {
		"loader": "<actor name>"
		... config loader config
}
   */
  config: ILoaders;
}

/**
   * StaticResponse is an actor that writes a static value to the client

   */
export interface IStaticResponse {
  /**
   * undefined
   */
  response: string;
}

/**
   * Shell is an `ssh.actors` module providing "shell" to a session. The module spawns a process
using the user's default shell, as defined in the OS. On *nix, except for macOS, the module parses `/etc/passwd`,
for the details and caches the result for future logins. On macOS, the module calls `dscl . -read` for the necessary
user details and caches them for future logins. On Windows, the module uses the
[`os/user` package](https://pkg.go.dev/os/user?GOOS=windows) from the Go standard library.

   */
export interface IShell {
  /**
   * Executes the designated command using the user's default shell, regardless of
the supplied command. It follows the OpenSSH semantics specified for
the [`ForceCommand`](https://man.openbsd.org/OpenBSD-current/man5/sshd_config.5#ForceCommand) except for
the part about `internal-sftp`.
   */
  force_command: string;
  /**
   * undefined
   */
  env: Record<string, string>;
  /**
   * whether the server should check for explicit pty request
   */
  force_pty: boolean;
}

export type IActors = IStaticResponse | IShell;

/**
   * The actors that can act on a session per the matching criteria


Actor is a collection of actor matchers and actors of an ssh session
   */
export interface IActor {
  /**
   * RawActorMatcherSet is a group of matcher sets in their raw, JSON form.

   */
  match: Array<any>;
  /**
   * The actor that shall act on the matched session.
"act": {
		"action": "<actor name>"
		... actor config
}
   */
  act: IActors;
  /**
   * Whether the session shoul be closed upon execution of the actor
   */
  final: boolean;
}

/**
 * The set of ssh servers keyed by custom names
 */
export interface IServer {
  /**
   * Socket addresses to which to bind listeners. Accepts
[network addresses](/docs/conventions#network-addresses)
that may include port ranges. Listener addresses must
be unique; they cannot be repeated across all defined
servers. TCP is the only acceptable network (for now, perhaps).
   */
  address: string;
  /**
   * The configuration of local-forward permission module. The config structure is:
"localforward": {
		"forward": "<module name>"
		... config
}
defaults to: { "forward": "deny" }
   */
  localforward: ILocalforward;
  /**
   * The configuration of reverse-forward permission module. The config structure is:
"reverseforward": {
		"forward": "<module name>"
		... config
}
defaults to: { "reverseforward": "deny" }
   */
  reverseforward: IReverseforward;
  /**
   * The configuration of PTY permission module. The config structure is:
"pty": {
		"pty": "<module name>"
		... config
}
defaults to: { "forward": "deny" }
   */
  pty: IPty;
  /**
   * connection timeout when no activity, none if empty


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  idle_timeout: IDuration;
  /**
   * absolute connection timeout, none if empty


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  max_timeout: IDuration;
  /**
   * The configuration of the authorizer module. The config structure is:
"authorize": {
		"authorizer": "<module name>"
		... config
}
default to: { "authorizer": "public" }.
   */
  authorize: IAuthorizers;
  /**
   * The list of defined subsystems in a json structure keyed by the arbitrary name of the subsystem.
TODO: The current implementation is naive and can be expanded to follow the Authorzation and Actors model


ModuleMap is a map that can contain multiple modules,
where the map key is the module's name. (The namespace
is usually read from an associated field's struct tag.)
Because the module's name is given as the key in a
module map, the name does not have to be given in the
json.RawMessage.
   */
  subsystems: ISubsystem;
  /**
   * ConfigList is a list of server config providers that can
custom configure the server based on the session

   */
  configs: Array<IConfigurator>;
  /**
   * ActorList is a list of server actors that can
take an action on a session

   */
  actors: Array<IActor>;
}

/**
   * SSH is the app providing ssh services

   */
export interface ISsh {
  /**
   * GracePeriod is the duration a server should wait for open connections to close during shutdown
before closing them forcefully


Duration can be an integer or a string. An integer is
interpreted as nanoseconds. If a string, it is a Go
time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`.
   */
  grace_period: IDuration;
  /**
   * undefined
   */
  servers: Record<string, IServer>;
}

/**
   * SCION implements a caddy module. Currently, it is used to initialize the
logger for the global network. In the future, additional configuration can be
parsed with this component.

   */
export type IScion = any;

/**
   * geoip2 is global caddy app with http.handlers.geoip2
it update geoip2 data automatically by the params

   */
export interface IGeoIp2State {
  /**
   * Your MaxMind account ID. This was formerly known as UserId.
   */
  accountId: number;
  /**
   * The directory to store the database files. Defaults to DATADIR
   */
  databaseDirectory: string;
  /**
   * Your case-sensitive MaxMind license key.
   */
  licenseKey: string;
  /**
   * The lock file to use. This ensures only one geoipupdate process can run at a
time.
Note: Once created, this lockfile is not removed from the filesystem.
   */
  lockFile: string;
  /**
   * Enter the edition IDs of the databases you would like to update.
Should be  GeoLite2-City
   */
  editionID: string;
  /**
   * update url to use. Defaults to https://updates.maxmind.com
   */
  updateUrl: string;
  /**
   * The Frequency in seconds to run update. Default to 0, only update On Start
   */
  updateFrequency: number;
}

export interface IApps {
  exec: IApp;
  reconnect: IReconnect;
  supervisor: IApp;
  events: IApp;
  http: IApp;
  pki: IPki;
  tls: ITls;
  frankenphp: IFrankenPhpApp;
  security: IApp;
  crowdsec: ICrowdSec;
  ssh: ISsh;
  dynamic_dns: IApp;
  layer4: IApp;
  profefe: IApp;
  profiling: IApp;
  pyroscope: IApp;
  scion: IScion;
  geoip2: IGeoIp2State;
}

/**
   * Config is the top (or beginning) of the Caddy configuration structure.
Caddy config is expressed natively as a JSON document. If you prefer
not to work with JSON directly, there are [many config adapters](/docs/config-adapters)
available that can convert various inputs into Caddy JSON.

Many parts of this config are extensible through the use of Caddy modules.
Fields which have a json.RawMessage type and which appear as dots (•••) in
the online docs can be fulfilled by modules in a certain module
namespace. The docs show which modules can be used in a given place.

Whenever a module is used, its name must be given either inline as part of
the module, or as the key to the module's value. The docs will make it clear
which to use.

Generally, all config settings are optional, as it is Caddy convention to
have good, documented default values. If a parameter is required, the docs
should say so.

Go programs which are directly building a Config struct value should take
care to populate the JSON-encodable fields of the struct (i.e. the fields
with `json` struct tags) if employing the module lifecycle (e.g. Provision
method calls).

   */
export interface IConfig {
  admin: IAdminConfig;
  logging: ILogging;
  storage: IStorage;
  /**
   * AppsRaw are the apps that Caddy will load and run. The
app module name is the key, and the app's config is the
associated value.


ModuleMap is a map that can contain multiple modules,
where the map key is the module's name. (The namespace
is usually read from an associated field's struct tag.)
Because the module's name is given as the key in a
module map, the name does not have to be given in the
json.RawMessage.
   */
  apps: IApps;
}
