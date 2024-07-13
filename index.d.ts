/**
 * Maximum time allowed for a complete connection and request.
 * Duration can be an integer or a string. An integer is
 * interpreted as nanoseconds. If a string, it is a Go
 * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
 * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
export type IDuration = number;

export interface ITls {
  use_server_identity?: boolean;
  client_certificate_file?: string;
  client_certificate_key_file?: string;
  root_ca_pem_files?: Array<string>;
  [key: string]: any;
}

/**
 * HTTPLoader can load Caddy configs over HTTP(S).
 * If the response is not a JSON config, a config adapter must be specified
 * either in the loader config (`adapter`), or in the Content-Type HTTP header
 * returned in the HTTP response from the server. The Content-Type header is
 * read just like the admin API's `/load` endpoint. Uf you don't have control
 * over the HTTP server (but can still trust its response), you can override
 * the Content-Type header by setting the `adapter` property in this config. */
export interface ICaddyconfigHttpLoader {
  /**
   * The method for the request. Default: GET */
  method?: string;
  /**
   * The URL of the request. */
  url?: string;
  /**
   * A Header represents the key-value pairs in an HTTP header.
   * The keys should be in canonical form, as returned by
   * CanonicalHeaderKey. */
  header?: Record<string, Array<string>>;
  /**
   * Maximum time allowed for a complete connection and request.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  timeout?: IDuration;
  /**
   * The name of the config adapter to use, if any. Only needed
   * if the HTTP response is not a JSON config and if the server's
   * Content-Type header is missing or incorrect. */
  adapter?: string;
  tls?: ITls;
  [key: string]: any;
}

export interface IGithubComHeavyHorstCertmagicNatsNats {
  hosts?: string;
  bucket?: string;
  creds?: string;
  inbox_prefix?: string;
  connection_name?: string;
  [key: string]: any;
}

/**
 * FileStorage is a certmagic.Storage wrapper for certmagic.FileStorage. */
export interface IModulesFilestorageFileStorage {
  /**
   * The base path to the folder used for storage. */
  root?: string;
  [key: string]: any;
}

/**
 * RedisStorage contain Redis client, and plugin option */
export interface IGithubComGamalanCaddyTlsredisRedisStorage {
  address?: string;
  host?: string;
  port?: string;
  db?: number;
  password?: string;
  timeout?: number;
  key_prefix?: string;
  value_prefix?: string;
  aes_key?: string;
  tls_enabled?: boolean;
  tls_insecure?: boolean;
  [key: string]: any;
}

/**
 * A highly available storage module that integrates with HashiCorp Vault. */
export interface IGithubComGerolfVentCaddyVaultStorageVaultStorage {
  addresses?: Array<string>;
  /**
   * Local path to read the access token from. Updates on that file will be
   * detected and automatically read. (As fallback the the environment
   * variable "VAULT_TOKEN" will be used, but it will only be read once on
   * startup.) */
  token_path?: string;
  /**
   * Path of the KVv2 mount to use. (Default is "kv".) */
  secrets_mount_path?: string;
  /**
   * Path in the KVv2 mount to use. (Default is "caddy".) */
  secrets_path_prefix?: string;
  /**
   * Limit of connection retries after which to fail a request. (Default is 3.) */
  max_retries?: number;
  /**
   * Timeout for locks (in seconds). (Default is 60.) */
  lock_timeout?: number;
  /**
   * Interval for checking lock status (in seconds). (Default is 5.) */
  lock_check_interval?: number;
  [key: string]: any;
}

/**
 * CaddyStorageGCS implements a caddy storage backend for Google Cloud Storage. */
export interface IGithubComGrafanaCertmagicGcsCaddyStorageGcs {
  /**
   * BucketName is the name of the storage bucket. */
  "bucket-name"?: string;
  /**
   * EncryptionKeySet is the path of a json tink encryption keyset */
  "encryption-key-set"?: string;
  [key: string]: any;
}

/**
 * Storage is the impelementation of certmagic.Storage interface for Caddy with encryption/decryption layer
 * using [SOPS](https://github.com/getsops/sops). The module accepts any Caddy storage module as the backend. */
export interface IGithubComMohammed90CaddyEncryptedStorageStorage {
  backend: IStorage;
  encryption?: Array<unknown>;
  [key: string]: any;
}

/**
 * ConsulStorage allows to store certificates and other TLS resources
 * in a shared cluster environment using Consul's key/value-store.
 * It uses distributed locks to ensure consistency. */
export interface IGithubComPteichCaddyTlsconsulConsulStorage {
  address?: string;
  token?: string;
  timeout?: number;
  prefix?: string;
  value_prefix?: string;
  aes_key?: Array<unknown>;
  tls_enabled?: boolean;
  tls_insecure?: boolean;
  [key: string]: any;
}

/**
 * Storage implements certmagic.Storage to facilitate
 * storage of certificates in DynamoDB for a clustered environment.
 * Also implements certmagic.Locker to facilitate locking
 * and unlocking of cert data during storage */
export interface IGithubComSilinternationalCertmagicStorageDynamodbV3Storage {
  /**
   * Table - [required] DynamoDB table name */
  table?: string;
  /**
   * AwsEndpoint - [optional] provide an override for DynamoDB service.
   * By default it'll use the standard production DynamoDB endpoints.
   * Useful for testing with a local DynamoDB instance. */
  aws_endpoint?: string;
  /**
   * AwsRegion - [optional] region using DynamoDB in.
   * Useful for testing with a local DynamoDB instance. */
  aws_region?: string;
  /**
   * AwsDisableSSL - [optional] disable SSL for DynamoDB connections. Default: false
   * Only useful for local testing, do not use outside of local testing. */
  aws_disable_ssl?: boolean;
  /**
   * LockTimeout - [optional] how long to wait for a lock to be created. Default: 5 minutes
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  lock_timeout?: IDuration;
  /**
   * LockPollingInterval - [optional] how often to check for lock released. Default: 5 seconds
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  lock_polling_interval?: IDuration;
  [key: string]: any;
}

export interface IGithubComSs098CertmagicS3S3 {
  host?: string;
  bucket?: string;
  access_id?: string;
  secret_key?: string;
  prefix?: string;
  [key: string]: any;
}

export type IEnvRedis = Record<string, any>;

/**
 * A Duration represents the elapsed time between two instants
 * as an int64 nanosecond count. The representation limits the
 * largest representable duration to approximately 290 years. */
export type ITimeDuration = number;

export interface IGithubComYroc92PostgresStoragePostgresStorage {
  /**
   * A Duration represents the elapsed time between two instants
   * as an int64 nanosecond count. The representation limits the
   * largest representable duration to approximately 290 years. */
  query_timeout?: ITimeDuration;
  /**
   * A Duration represents the elapsed time between two instants
   * as an int64 nanosecond count. The representation limits the
   * largest representable duration to approximately 290 years. */
  lock_timeout?: ITimeDuration;
  host?: string;
  port?: string;
  user?: string;
  password?: string;
  dbname?: string;
  sslmode?: string;
  connection_string?: string;
  [key: string]: any;
}

export interface IGithubComZhangjiayinCaddyMysqlStorageMysqlStorage {
  /**
   * A Duration represents the elapsed time between two instants
   * as an int64 nanosecond count. The representation limits the
   * largest representable duration to approximately 290 years. */
  query_timeout?: ITimeDuration;
  /**
   * A Duration represents the elapsed time between two instants
   * as an int64 nanosecond count. The representation limits the
   * largest representable duration to approximately 290 years. */
  lock_timeout?: ITimeDuration;
  dsn?: string;
  [key: string]: any;
}

export type IStorage =
  | IGithubComHeavyHorstCertmagicNatsNats
  | IModulesFilestorageFileStorage
  | IGithubComGamalanCaddyTlsredisRedisStorage
  | IGithubComGerolfVentCaddyVaultStorageVaultStorage
  | IGithubComGrafanaCertmagicGcsCaddyStorageGcs
  | IGithubComMohammed90CaddyEncryptedStorageStorage
  | IGithubComPteichCaddyTlsconsulConsulStorage
  | IGithubComSilinternationalCertmagicStorageDynamodbV3Storage
  | IGithubComSs098CertmagicS3S3
  | IEnvRedis
  | IGithubComYroc92PostgresStoragePostgresStorage
  | IGithubComZhangjiayinCaddyMysqlStorageMysqlStorage;

/**
 * StorageLoader is a dynamic configuration loader that reads the configuration from a Caddy storage. If
 * the storage is not configured, the default storage is used, which may be the file-system if none is configured
 * If the `key` is not configured, the default key is `config/caddy.json`. */
export interface IGithubComMohammed90CaddyStorageLoaderStorageLoader {
  /**
   * StorageRaw is a storage module that defines how/where Caddy
   * stores assets (such as TLS certificates). The default storage
   * module is `caddy.storage.file_system` (the local file system),
   * and the default path
   * [depends on the OS and environment](/docs/conventions#data-directory). */
  storage?: IStorage;
  /**
   * The storage key at which the configuration is to be found */
  key?: string;
  /**
   * The adapter to use to convert the storage's contents to Caddy JSON. */
  adapter?: string;
  [key: string]: any;
}

export type IConfigLoaders =
  | ICaddyconfigHttpLoader
  | IGithubComMohammed90CaddyStorageLoaderStorageLoader;

/**
 * Options pertaining to configuration management.
 * ConfigSettings configures the management of configuration. */
export interface IConfigSettings {
  /**
   * Whether to keep a copy of the active config on disk. Default is true.
   * Note that "pulled" dynamic configs (using the neighboring "load" module)
   * are not persisted; only configs that are pushed to Caddy get persisted. */
  persist?: boolean;
  /**
   * Loads a configuration to use. This is helpful if your configs are
   * managed elsewhere, and you want Caddy to pull its config dynamically
   * when it starts. The pulled config completely replaces the current
   * one, just like any other config load. It is an error if a pulled
   * config is configured to pull another config.
   * EXPERIMENTAL: Subject to change. */
  load?: IConfigLoaders;
  [key: string]: any;
}

/**
 * Options that establish this server's identity. Identity refers to
 * credentials which can be used to uniquely identify and authenticate
 * this server instance. This is required if remote administration is
 * enabled (but does not require remote administration to be enabled).
 * Default: no identity management.
 * IdentityConfig configures management of this server's identity. An identity
 * consists of credentials that uniquely verify this instance; for example,
 * TLS certificates (public + private key pairs). */
export interface IIdentityConfig {
  identifiers?: Array<string>;
  issuers?: Array<unknown>;
  [key: string]: any;
}

/**
 * Limits what the associated identities are allowed to do.
 * If unspecified, all permissions are granted.
 * AdminPermissions specifies what kinds of requests are allowed
 * to be made to the admin endpoint. */
export interface IAdminPermissions {
  paths?: Array<string>;
  methods?: Array<string>;
  [key: string]: any;
}

/**
 * List of access controls for this secure admin endpoint.
 * This configures TLS mutual authentication (i.e. authorized
 * client certificates), but also application-layer permissions
 * like which paths and methods each identity is authorized for.
 * AdminAccess specifies what permissions an identity or group
 * of identities are granted. */
export interface IAdminAccess {
  public_keys?: Array<string>;
  permissions?: Array<IAdminPermissions>;
  [key: string]: any;
}

/**
 * Options pertaining to remote administration. By default, remote
 * administration is disabled. If enabled, identity management must
 * also be configured, as that is how the endpoint is secured.
 * See the neighboring "identity" object.
 * EXPERIMENTAL: This feature is subject to change.
 * RemoteAdmin enables and configures remote administration. If enabled,
 * a secure listener enforcing mutual TLS authentication will be started
 * on a different port from the standard plaintext admin server.
 * This endpoint is secured using identity management, which must be
 * configured separately (because identity management does not depend
 * on remote administration). See the admin/identity config struct.
 * EXPERIMENTAL: Subject to change. */
export interface IRemoteAdmin {
  /**
   * The address on which to start the secure listener.
   * Default: :2021 */
  listen?: string;
  access_control?: Array<IAdminAccess>;
  [key: string]: any;
}

/**
 * AdminConfig configures Caddy's API endpoint, which is used
 * to manage Caddy while it is running. */
export interface IAdminConfig {
  /**
   * If true, the admin endpoint will be completely disabled.
   * Note that this makes any runtime changes to the config
   * impossible, since the interface to do so is through the
   * admin endpoint. */
  disabled?: boolean;
  /**
   * The address to which the admin endpoint's listener should
   * bind itself. Can be any single network address that can be
   * parsed by Caddy. Default: localhost:2019 */
  listen?: string;
  /**
   * If true, CORS headers will be emitted, and requests to the
   * API will be rejected if their `Host` and `Origin` headers
   * do not match the expected value(s). Use `origins` to
   * customize which origins/hosts are allowed. If `origins` is
   * not set, the listen address is the only value allowed by
   * default. Enforced only on local (plaintext) endpoint. */
  enforce_origin?: boolean;
  origins?: Array<string>;
  config?: IConfigSettings;
  identity?: IIdentityConfig;
  remote?: IRemoteAdmin;
  [key: string]: any;
}

/**
    * DiscardWriter discards all writes.
 
    */
export type IDiscardWriter = Record<string, any>;

/**
    * StderrWriter writes logs to standard error.
 
    */
export type IStderrWriter = Record<string, any>;

/**
    * StdoutWriter writes logs to standard out.
 
    */
export type IStdoutWriter = Record<string, any>;

/**
 * FileWriter can write logs to files. By default, log files
 * are rotated ("rolled") when they get large, and old log
 * files get deleted, to ensure that the process does not
 * exhaust disk space. */
export interface IModulesLoggingFileWriter {
  /**
   * Filename is the name of the file to write. */
  filename?: string;
  /**
   * Roll toggles log rolling or rotation, which is
   * enabled by default. */
  roll?: boolean;
  /**
   * When a log file reaches approximately this size,
   * it will be rotated. */
  roll_size_mb?: number;
  /**
   * Whether to compress rolled files. Default: true */
  roll_gzip?: boolean;
  /**
   * Whether to use local timestamps in rolled filenames.
   * Default: false */
  roll_local_time?: boolean;
  /**
   * The maximum number of rolled log files to keep.
   * Default: 10 */
  roll_keep?: number;
  /**
   * How many days to keep rolled log files. Default: 90 */
  roll_keep_days?: number;
  [key: string]: any;
}

/**
 * NetWriter implements a log writer that outputs to a network socket. If
 * the socket goes down, it will dump logs to stderr while it attempts to
 * reconnect. */
export interface IModulesLoggingNetWriter {
  /**
   * The address of the network socket to which to connect. */
  address?: string;
  /**
   * The timeout to wait while connecting to the socket.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  dial_timeout?: IDuration;
  /**
   * If enabled, allow connections errors when first opening the
   * writer. The error and subsequent log entries will be reported
   * to stderr instead until a connection can be re-established. */
  soft_start?: boolean;
  [key: string]: any;
}

export interface IGithubComNeodymeLabsInfluxLogInfluxLog {
  host?: string;
  token?: string;
  org?: string;
  bucket?: string;
  measurement?: string;
  tags?: Record<string, string>;
  [key: string]: any;
}

/**
    * Writer is a influxdb client to write time series data
 
    */
export type IGithubComSillygodCdpCacheExtendsInfluxlogWriter = Record<
  string,
  any
>;

/**
 * GraphiteLog is a Caddy logger used to send server activity to a Graphite
 * database.
 * Templating is available as follow :
 * 	.Level
 * 	.Date
 * 	.Logger
 * 	.Msg
 * 	.Request
 * 		.RemoteIP
 * 		.RemotePort
 * 		.ClientIP
 * 		.Proto
 * 		.Method
 * 		.Host
 * 		.URI
 * 		.Headers
 * 	.BytesRead
 * 	.UserID
 * 	.Duration
 * 	.Size
 * 	.Status
 * 	.RespHeaders map[string][]string
 * 	.DirName
 * 	.FileName */
export interface IGithubComYbizeulCaddyLoggerGraphiteGraphiteLog {
  /**
   * IP address or host name of the graphite server */
  server?: string;
  /**
   * Port number to be used (usually 2003) */
  port?: number;
  /**
   * Metrics Path, can be templated */
  path?: string;
  /**
   * Value to be sent, can be templated */
  value?: string;
  methods?: Array<string>;
  [key: string]: any;
}

export type IWriters =
  | IDiscardWriter
  | IStderrWriter
  | IStdoutWriter
  | IModulesLoggingFileWriter
  | IModulesLoggingNetWriter
  | IGithubComNeodymeLabsInfluxLogInfluxLog
  | IGithubComSillygodCdpCacheExtendsInfluxlogWriter
  | IGithubComYbizeulCaddyLoggerGraphiteGraphiteLog;

/**
 * Sink is the destination for all unstructured logs emitted
 * from Go's standard library logger. These logs are common
 * in dependencies that are not designed specifically for use
 * in Caddy. Because it is global and unstructured, the sink
 * lacks most advanced features and customizations.
 * StandardLibLog configures the default Go standard library
 * global logger in the log package. This is necessary because
 * module dependencies which are not built specifically for
 * Caddy will use the standard logger. This is also known as
 * the "sink" logger. */
export interface IStandardLibLog {
  /**
   * The module that writes out log entries for the sink. */
  writer?: IWriters;
  [key: string]: any;
}

/**
 * AppendEncoder can be used to add fields to all log entries
 * that pass through it. It is a wrapper around another
 * encoder, which it uses to actually encode the log entries.
 * It is most useful for adding information about the Caddy
 * instance that is producing the log entries, possibly via
 * an environment variable. */
export interface IModulesLoggingAppendEncoder {
  wrap: IEncoders;
  fields?: Record<string, unknown>;
  [key: string]: any;
}

/**
 * ConsoleEncoder encodes log entries that are mostly human-readable. */
export interface IModulesLoggingConsoleEncoder {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  /**
   * Recognized values are: unix_seconds_float, unix_milli_float, unix_nano, iso8601, rfc3339, rfc3339_nano, wall, wall_milli, wall_nano, common_log.
   * The value may also be custom format per the Go `time` package layout specification, as described [here](https://pkg.go.dev/time#pkg-constants). */
  time_format?: string;
  time_local?: boolean;
  /**
   * Recognized values are: s/second/seconds, ns/nano/nanos, ms/milli/millis, string.
   * Empty and unrecognized value default to seconds. */
  duration_format?: string;
  /**
   * Recognized values are: lower, upper, color.
   * Empty and unrecognized value default to lower. */
  level_format?: string;
  [key: string]: any;
}

/**
 * A list of actions to apply to the cookies. */
export interface IModulesLoggingCookieFilterAction {
  /**
   * `replace` to replace the value of the cookie, `hash` to replace it with the 4 initial bytes of the SHA-256 of its content or `delete` to remove it entirely. */
  type?: string;
  /**
   * The name of the cookie. */
  name?: string;
  /**
   * The value to use as replacement if the action is `replace`. */
  value?: string;
  [key: string]: any;
}

/**
 * CookieFilter is a Caddy log field filter that filters
 * cookies.
 * This filter updates the logged HTTP header string
 * to remove, replace or hash cookies containing sensitive data. For instance,
 * it can be used to redact any kind of secrets, such as session IDs.
 * If several actions are configured for the same cookie name, only the first
 * will be applied. */
export interface IModulesLoggingCookieFilter {
  actions?: Array<IModulesLoggingCookieFilterAction>;
  [key: string]: any;
}

/**
    * DeleteFilter is a Caddy log field filter that
 deletes the field.
 
    */
export type IModulesLoggingDeleteFilter = Record<string, any>;

/**
    * HashFilter is a Caddy log field filter that
 replaces the field with the initial 4 bytes
 of the SHA-256 hash of the content. Operates
 on string fields, or on arrays of strings
 where each string is hashed.
 
    */
export type IModulesLoggingHashFilter = Record<string, any>;

/**
 * IPMaskFilter is a Caddy log field filter that
 * masks IP addresses in a string, or in an array
 * of strings. The string may be a comma separated
 * list of IP addresses, where all of the values
 * will be masked. */
export interface IModulesLoggingIpMaskFilter {
  /**
   * The IPv4 mask, as an subnet size CIDR. */
  ipv4_cidr?: number;
  /**
   * The IPv6 mask, as an subnet size CIDR. */
  ipv6_cidr?: number;
  [key: string]: any;
}

/**
 * A list of actions to apply to the query parameters of the URL. */
export interface IModulesLoggingQueryFilterAction {
  /**
   * `replace` to replace the value(s) associated with the parameter(s), `hash` to replace them with the 4 initial bytes of the SHA-256 of their content or `delete` to remove them entirely. */
  type?: string;
  /**
   * The name of the query parameter. */
  parameter?: string;
  /**
   * The value to use as replacement if the action is `replace`. */
  value?: string;
  [key: string]: any;
}

/**
 * QueryFilter is a Caddy log field filter that filters
 * query parameters from a URL.
 * This filter updates the logged URL string to remove, replace or hash
 * query parameters containing sensitive data. For instance, it can be
 * used to redact any kind of secrets which were passed as query parameters,
 * such as OAuth access tokens, session IDs, magic link tokens, etc. */
export interface IModulesLoggingQueryFilter {
  actions?: Array<IModulesLoggingQueryFilterAction>;
  [key: string]: any;
}

/**
 * RegexpFilter is a Caddy log field filter that
 * replaces the field matching the provided regexp
 * with the indicated string. If the field is an
 * array of strings, each of them will have the
 * regexp replacement applied. */
export interface IModulesLoggingRegexpFilter {
  /**
   * The regular expression pattern defining what to replace. */
  regexp?: string;
  /**
   * The value to use as replacement */
  value?: string;
  [key: string]: any;
}

/**
 * RenameFilter is a Caddy log field filter that
 * renames the field's key with the indicated name. */
export interface IModulesLoggingRenameFilter {
  name?: string;
  [key: string]: any;
}

/**
 * ReplaceFilter is a Caddy log field filter that
 * replaces the field with the indicated string. */
export interface IModulesLoggingReplaceFilter {
  value?: string;
  [key: string]: any;
}

/**
    * BasicAuthFilter is a Caddy log field filter that replaces the a base64 encoded authorization
 header with just the user name.
 
    */
export type IGithubComUeffelCaddyBasicAuthFilterBasicAuthFilter = Record<
  string,
  any
>;

/**
    * TLSCipherFilter is Caddy log field filter that replaces the numeric TLS cipher_suite value with
 the string representation.
 
    */
export type IGithubComUeffelCaddyTlsFormatTlsCipherFilter = Record<string, any>;

/**
 * TLSVersionFilter is a Caddy log field filter that replaces the numeric TLS version with the
 * string version and optionally adds a prefix. */
export interface IGithubComUeffelCaddyTlsFormatTlsVersionFilter {
  /**
   * Prefix is a constant string that will be added before the replaced version string. */
  prefix?: string;
  [key: string]: any;
}

export interface IFilter {
  cookie?: IModulesLoggingCookieFilter;
  delete?: IModulesLoggingDeleteFilter;
  hash?: IModulesLoggingHashFilter;
  ip_mask?: IModulesLoggingIpMaskFilter;
  query?: IModulesLoggingQueryFilter;
  regexp?: IModulesLoggingRegexpFilter;
  rename?: IModulesLoggingRenameFilter;
  replace?: IModulesLoggingReplaceFilter;
  basic_auth_user?: IGithubComUeffelCaddyBasicAuthFilterBasicAuthFilter;
  tls_cipher?: IGithubComUeffelCaddyTlsFormatTlsCipherFilter;
  tls_version?: IGithubComUeffelCaddyTlsFormatTlsVersionFilter;
  [key: string]: any;
}

/**
 * FilterEncoder can filter (manipulate) fields on
 * log entries before they are actually encoded by
 * an underlying encoder. */
export interface IModulesLoggingFilterEncoder {
  wrap: IEncoders;
  /**
   * A map of field names to their filters. Note that this
   * is not a module map; the keys are field names.
   * Nested fields can be referenced by representing a
   * layer of nesting with `>`. In other words, for an
   * object like `{"a":{"b":0}}`, the inner field can
   * be referenced as `a>b`.
   * The following fields are fundamental to the log and
   * cannot be filtered because they are added by the
   * underlying logging library as special cases: ts,
   * level, logger, and msg. */
  fields: IFilter;
  [key: string]: any;
}

/**
 * JSONEncoder encodes entries as JSON. */
export interface IModulesLoggingJsonEncoder {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  /**
   * Recognized values are: unix_seconds_float, unix_milli_float, unix_nano, iso8601, rfc3339, rfc3339_nano, wall, wall_milli, wall_nano, common_log.
   * The value may also be custom format per the Go `time` package layout specification, as described [here](https://pkg.go.dev/time#pkg-constants). */
  time_format?: string;
  time_local?: boolean;
  /**
   * Recognized values are: s/second/seconds, ns/nano/nanos, ms/milli/millis, string.
   * Empty and unrecognized value default to seconds. */
  duration_format?: string;
  /**
   * Recognized values are: lower, upper, color.
   * Empty and unrecognized value default to lower. */
  level_format?: string;
  [key: string]: any;
}

/**
 * LogfmtEncoder encodes log entries as logfmt:
 * https://www.brandur.org/logfmt
 * Note that logfmt does not encode nested structures
 * properly, so it is not a good fit for most logs.
 * ⚠️ DEPRECATED. Do not use. It will eventually be removed
 * from the standard Caddy modules. For more information,
 * see https://github.com/caddyserver/caddy/issues/3575. */
export interface IModulesLoggingLogfmtEncoder {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  time_format?: string;
  duration_format?: string;
  level_format?: string;
  [key: string]: any;
}

/**
 * SingleFieldEncoder writes a log entry that consists entirely
 * of a single string field in the log entry. This is useful
 * for custom, self-encoded log entries that consist of a
 * single field in the structured log entry. */
export interface IModulesLoggingSingleFieldEncoder {
  field?: string;
  fallback: IEncoders;
  [key: string]: any;
}

export interface IGithubComCaddyserverTransformEncoderCompat {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  time_format?: string;
  duration_format?: string;
  level_format?: string;
  template?: string;
  placeholder?: string;
  [key: string]: any;
}

/**
 * TransformEncoder allows the user to provide custom template for log prints. The
 * encoder builds atop the json encoder, thus it follows its message structure. The placeholders
 * are namespaced by the name of the app logging the message. */
export interface IGithubComCaddyserverTransformEncoderTransformEncoder {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  time_format?: string;
  duration_format?: string;
  level_format?: string;
  template?: string;
  placeholder?: string;
  [key: string]: any;
}

export interface IGithubComFirecowCaddyElasticEncoderElasticEncoder {
  message_key?: string;
  level_key?: string;
  time_key?: string;
  name_key?: string;
  caller_key?: string;
  stacktrace_key?: string;
  line_ending?: string;
  time_format?: string;
  duration_format?: string;
  level_format?: string;
  [key: string]: any;
}

export type IEncoders =
  | IModulesLoggingAppendEncoder
  | IModulesLoggingConsoleEncoder
  | IModulesLoggingFilterEncoder
  | IModulesLoggingJsonEncoder
  | IModulesLoggingLogfmtEncoder
  | IModulesLoggingSingleFieldEncoder
  | IGithubComCaddyserverTransformEncoderCompat
  | IGithubComCaddyserverTransformEncoderTransformEncoder
  | IGithubComFirecowCaddyElasticEncoderElasticEncoder;

/**
 * Sampling configures log entry sampling. If enabled,
 * only some log entries will be emitted. This is useful
 * for improving performance on extremely high-pressure
 * servers.
 * LogSampling configures log entry sampling. */
export interface ILogSampling {
  /**
   * The window over which to conduct sampling.
   * A Duration represents the elapsed time between two instants
   * as an int64 nanosecond count. The representation limits the
   * largest representable duration to approximately 290 years. */
  interval?: ITimeDuration;
  /**
   * Log this many entries within a given level and
   * message for each interval. */
  first?: number;
  /**
   * If more entries with the same level and message
   * are seen during the same interval, keep one in
   * this many entries until the end of the interval. */
  thereafter?: number;
  [key: string]: any;
}

/**
 * Logs are your logs, keyed by an arbitrary name of your
 * choosing. The default log can be customized by defining
 * a log called "default". You can further define other logs
 * and filter what kinds of entries they accept.
 * CustomLog represents a custom logger configuration.
 * By default, a log will emit all log entries. Some entries
 * will be skipped if sampling is enabled. Further, the Include
 * and Exclude parameters define which loggers (by name) are
 * allowed or rejected from emitting in this log. If both Include
 * and Exclude are populated, their values must be mutually
 * exclusive, and longer namespaces have priority. If neither
 * are populated, all logs are emitted. */
export interface ICustomLog {
  writer: IWriters;
  /**
   * The encoder is how the log entries are formatted or encoded. */
  encoder?: IEncoders;
  /**
   * Level is the minimum level to emit, and is inclusive.
   * Possible levels: DEBUG, INFO, WARN, ERROR, PANIC, and FATAL */
  level?: string;
  sampling?: ILogSampling;
  include?: Array<string>;
  exclude?: Array<string>;
  [key: string]: any;
}

/**
 * Logging facilitates logging within Caddy. The default log is
 * called "default" and you can customize it. You can also define
 * additional logs.
 * By default, all logs at INFO level and higher are written to
 * standard error ("stderr" writer) in a human-readable format
 * ("console" encoder if stdout is an interactive terminal, "json"
 * encoder otherwise).
 * All defined logs accept all log entries by default, but you
 * can filter by level and module/logger names. A logger's name
 * is the same as the module's name, but a module may append to
 * logger names for more specificity. For example, you can
 * filter logs emitted only by HTTP handlers using the name
 * "http.handlers", because all HTTP handler module names have
 * that prefix.
 * Caddy logs (except the sink) are zero-allocation, so they are
 * very high-performing in terms of memory and CPU time. Enabling
 * sampling can further increase throughput on extremely high-load
 * servers. */
export interface ILogging {
  sink?: IStandardLibLog;
  logs?: Record<string, ICustomLog>;
  [key: string]: any;
}

/**
 * Cmd is the module configuration */
export interface IGithubComAbiosoftCaddyExecCmd {
  /**
   * The command to run. */
  command?: string;
  args?: Array<string>;
  /**
   * The directory to run the command from.
   * Defaults to current directory. */
  directory?: string;
  /**
   * If the command should run in the foreground.
   * By default, commands run in the background and doesn't
   * affect Caddy.
   * Setting this makes the command run in the foreground.
   * Note that failure of a startup command running in the
   * foreground may prevent Caddy from starting. */
  foreground?: boolean;
  /**
   * Timeout for the command. The command will be killed
   * after timeout has elapsed if it is still running.
   * Defaults to 10s. */
  timeout?: string;
  at?: Array<string>;
  log: IWriters;
  err_log: IWriters;
  [key: string]: any;
}

/**
 * App is top level module that runs shell commands. */
export interface IGithubComAbiosoftCaddyExecApp {
  commands?: Array<IGithubComAbiosoftCaddyExecCmd>;
  [key: string]: any;
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
export type IGithubComAnapayaCaddyReconnectReconnect = Record<string, any>;

/**
 * RedirectStdout is the file where Command stdout is written. Use "stdout" to redirect to caddy stdout. */
export interface IGithubComBaldinofCaddySupervisorOutputTarget {
  /**
   * Type is how the output should be redirected
   * Valid values:
   *   - **null**: discard outputs
   *   - **stdout**: redirect output to caddy process stdout
   *   - **stderr**: redirect output to caddy process stderr
   *   - **file**: redirect output to a file, if selected File field is required */
  type?: string;
  /**
   * File is the file where outputs should be written. This is used only when Type is "file". */
  file?: string;
  [key: string]: any;
}

/**
 * Definition is the configuration for process to supervise */
export interface IGithubComBaldinofCaddySupervisorDefinition {
  command?: Array<string>;
  /**
   * Replicas control how many instances of Command should run. */
  replicas?: number;
  /**
   * Dir defines the working directory the command should be executed in.
   * Supports template.
   * Default: current working dir */
  dir?: string;
  env?: Record<string, string>;
  redirect_stdout?: IGithubComBaldinofCaddySupervisorOutputTarget;
  redirect_stderr: IGithubComBaldinofCaddySupervisorOutputTarget;
  /**
   * RestartPolicy define under which conditions the command should be restarted after exit.
   * Valid values:
   *  - **never**: do not restart the command
   *  - **on_failure**: restart if exit code is not 0
   *  - **always**: always restart
   * RestartPolicy determines when a supervised process should be restarted */
  restart_policy?: string;
  /**
   * TerminationGracePeriod defines the amount of time to wait for Command graceful termination before killing it. Ex: 10s */
  termination_grace_period?: string;
  [key: string]: any;
}

export interface IGithubComBaldinofCaddySupervisorApp {
  supervise?: Array<IGithubComBaldinofCaddySupervisorDefinition>;
  [key: string]: any;
}

/**
 * Subscriptions bind handlers to one or more events
 * either globally or scoped to specific modules or module
 * namespaces.
 * Subscription represents binding of one or more handlers to
 * one or more events. */
export interface IModulesCaddyeventsSubscription {
  events?: Array<string>;
  modules?: Array<string>;
  handlers?: Array<unknown>;
  [key: string]: any;
}

/**
 * App implements a global eventing system within Caddy.
 * Modules can emit and subscribe to events, providing
 * hooks into deep parts of the code base that aren't
 * otherwise accessible. Events provide information about
 * what and when things are happening, and this facility
 * allows handlers to take action when events occur,
 * add information to the event's metadata, and even
 * control program flow in some cases.
 * Events are propagated in a DOM-like fashion. An event
 * emitted from module `a.b.c` (the "origin") will first
 * invoke handlers listening to `a.b.c`, then `a.b`,
 * then `a`, then those listening regardless of origin.
 * If a handler returns the special error Aborted, then
 * propagation immediately stops and the event is marked
 * as aborted. Emitters may optionally choose to adjust
 * program flow based on an abort.
 * Modules can subscribe to events by origin and/or name.
 * A handler is invoked only if it is subscribed to the
 * event by name and origin. Subscriptions should be
 * registered during the provisioning phase, before apps
 * are started.
 * Event handlers are fired synchronously as part of the
 * regular flow of the program. This allows event handlers
 * to control the flow of the program if the origin permits
 * it and also allows handlers to convey new information
 * back into the origin module before it continues.
 * In essence, event handlers are similar to HTTP
 * middleware handlers.
 * Event bindings/subscribers are unordered; i.e.
 * event handlers are invoked in an arbitrary order.
 * Event handlers should not rely on the logic of other
 * handlers to succeed.
 * The entirety of this app module is EXPERIMENTAL and
 * subject to change. Pay attention to release notes. */
export interface IModulesCaddyeventsApp {
  subscriptions?: Array<IModulesCaddyeventsSubscription>;
  [key: string]: any;
}

/**
 * Routes describes how this server will handle requests.
 * Routes are executed sequentially. First a route's matchers
 * are evaluated, then its grouping. If it matches and has
 * not been mutually-excluded by its grouping, then its
 * handlers are executed sequentially. The sequence of invoked
 * handlers comprises a compiled middleware chain that flows
 * from each matching route and its handlers to the next.
 * By default, all unrouted requests receive a 200 OK response
 * to indicate the server is working.
 * Route consists of a set of rules for matching HTTP requests,
 * a list of handlers to execute, and optional flow control
 * parameters which customize the handling of HTTP requests
 * in a highly flexible and performant manner. */
export interface IModulesCaddyhttpRoute {
  /**
   * Group is an optional name for a group to which this
   * route belongs. Grouping a route makes it mutually
   * exclusive with others in its group; if a route belongs
   * to a group, only the first matching route in that group
   * will be executed. */
  group?: string;
  /**
   * RawMatcherSets is a group of matcher sets
   * in their raw, JSON form. */
  match?: Array<unknown>;
  handle?: Array<unknown>;
  /**
   * If true, no more routes will be executed after this one. */
  terminal?: boolean;
  [key: string]: any;
}

/**
 * Errors is how this server will handle errors returned from any
 * of the handlers in the primary routes. If the primary handler
 * chain returns an error, the error along with its recommended
 * status code are bubbled back up to the HTTP server which
 * executes a separate error route, specified using this property.
 * The error routes work exactly like the normal routes.
 * HTTPErrorConfig determines how to handle errors
 * from the HTTP handlers. */
export interface IModulesCaddyhttpHttpErrorConfig {
  /**
   * RouteList is a list of server routes that can
   * create a middleware chain. */
  routes?: Array<IModulesCaddyhttpRoute>;
  [key: string]: any;
}

/**
 * MatchLocalIP matches based on the IP address of the interface
 * receiving the connection. Specific IPs or CIDR ranges can be specified. */
export interface IModulesCaddytlsMatchLocalIp {
  ranges?: Array<string>;
  [key: string]: any;
}

/**
 * MatchRemoteIP matches based on the remote IP of the
 * connection. Specific IPs or CIDR ranges can be specified.
 * Note that IPs can sometimes be spoofed, so do not rely
 * on this as a replacement for actual authentication. */
export interface IModulesCaddytlsMatchRemoteIp {
  ranges?: Array<string>;
  not_ranges?: Array<string>;
  [key: string]: any;
}

export interface IHandshakeMatch {
  local_ip?: IModulesCaddytlsMatchLocalIp;
  remote_ip?: IModulesCaddytlsMatchRemoteIp;
  sni?: IModulesCaddytlsMatchServerName;
  alpn?: IGithubComMholtCaddyL4ModulesL4tlsMatchAlpn;
  [key: string]: any;
}

/**
    * The certificate must have one of these serial numbers.
 
 
 bigInt is a big.Int type that interops with JSON encodings as a string.
    */
export type IModulesCaddytlsBigInt = Record<string, any>;

/**
 * The certificate must use this public key algorithm.
 * PublicKeyAlgorithm is a JSON-unmarshalable wrapper type. */
export type IModulesCaddytlsPublicKeyAlgorithm = number;

/**
 * How to choose a certificate if more than one matched
 * the given ServerName (SNI) value.
 * CustomCertSelectionPolicy represents a policy for selecting the certificate
 * used to complete a handshake when there may be multiple options. All fields
 * specified must match the candidate certificate for it to be chosen.
 * This was needed to solve https://github.com/caddyserver/caddy/issues/2588. */
export interface IModulesCaddytlsCustomCertSelectionPolicy {
  serial_number?: Array<IModulesCaddytlsBigInt>;
  subject_organization?: Array<string>;
  /**
   * The certificate must use this public key algorithm.
   * PublicKeyAlgorithm is a JSON-unmarshalable wrapper type. */
  public_key_algorithm?: IModulesCaddytlsPublicKeyAlgorithm;
  any_tag?: Array<string>;
  all_tags?: Array<string>;
  [key: string]: any;
}

/**
 * FileCAPool generates trusted root certificates pool from the designated DER and PEM file */
export interface IModulesCaddytlsFileCaPool {
  pem_files?: Array<string>;
  [key: string]: any;
}

/**
 * Customize the TLS connection knobs to used during the HTTP call
 * TLSConfig holds configuration related to the TLS configuration for the
 * transport/client.
 * copied from with minor modifications: modules/caddyhttp/reverseproxy/httptransport.go */
export interface IModulesCaddytlsTlsConfig {
  ca: ISource;
  /**
   * If true, TLS verification of server certificates will be disabled.
   * This is insecure and may be removed in the future. Do not use this
   * option except in testing or local development environments. */
  insecure_skip_verify?: boolean;
  /**
   * The duration to allow a TLS handshake to a server. Default: No timeout.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  handshake_timeout?: IDuration;
  /**
   * The server name used when verifying the certificate received in the TLS
   * handshake. By default, this will use the upstream address' host part.
   * You only need to override this if your upstream address does not match the
   * certificate the upstream is likely to use. For example if the upstream
   * address is an IP address, then you would need to configure this to the
   * hostname being served by the upstream server. Currently, this does not
   * support placeholders because the TLS config is not provisioned on each
   * connection, so a static value must be used. */
  server_name?: string;
  /**
   * TLS renegotiation level. TLS renegotiation is the act of performing
   * subsequent handshakes on a connection after the first.
   * The level can be:
   *  - "never": (the default) disables renegotiation.
   *  - "once": allows a remote server to request renegotiation once per connection.
   *  - "freely": allows a remote server to repeatedly request renegotiation. */
  renegotiation?: string;
  [key: string]: any;
}

/**
 * The HTTPCertPool fetches the trusted root certificates from HTTP(S)
 * endpoints. The TLS connection properties can be customized, including custom
 * trusted root certificate. One example usage of this module is to get the trusted
 * certificates from another Caddy instance that is running the PKI app and ACME server. */
export interface IModulesCaddytlsHttpCertPool {
  endpoints?: Array<string>;
  tls?: IModulesCaddytlsTlsConfig;
  [key: string]: any;
}

/**
 * InlineCAPool is a certificate authority pool provider coming from
 * a DER-encoded certificates in the config */
export interface IModulesCaddytlsInlineCaPool {
  trusted_ca_certs?: Array<string>;
  [key: string]: any;
}

/**
 * LazyCertPool defers the generation of the certificate pool from the
 * guest module to demand-time rather than at provisionig time. The gain of the
 * lazy load adds a risk of failure to load the certificates at demand time
 * because the validation that's typically done at provisioning is deferred.
 * The validation can be enforced to run before runtime by setting
 * `EagerValidation`/`eager_validation` to `true`. It is the operator's responsibility
 * to ensure the resources are available if `EagerValidation`/`eager_validation`
 * is set to `true`. The module also incurs performance cost at every demand. */
export interface IModulesCaddytlsLazyCertPool {
  ca: ISource;
  /**
   * Whether the validation step should try to load and provision the guest module to validate
   * the correctness of the configuration. Depeneding on the type of the guest module,
   * the resources may not be available at validation time. It is the
   * operator's responsibility to ensure the resources are available if `EagerValidation`/`eager_validation`
   * is set to `true`. */
  eager_validation?: boolean;
  [key: string]: any;
}

/**
 * PKIIntermediateCAPool extracts the trusted intermediate certificates from Caddy's native 'pki' app */
export interface IModulesCaddytlsPkiIntermediateCaPool {
  authority?: Array<string>;
  [key: string]: any;
}

/**
 * PKIRootCAPool extracts the trusted root certificates from Caddy's native 'pki' app */
export interface IModulesCaddytlsPkiRootCaPool {
  authority?: Array<string>;
  [key: string]: any;
}

/**
 * StoragePool extracts the trusted certificates root from Caddy storage */
export interface IModulesCaddytlsStoragePool {
  storage: IStorage;
  pem_keys?: Array<string>;
  [key: string]: any;
}

export type ISource =
  | IModulesCaddytlsFileCaPool
  | IModulesCaddytlsHttpCertPool
  | IModulesCaddytlsInlineCaPool
  | IModulesCaddytlsLazyCertPool
  | IModulesCaddytlsPkiIntermediateCaPool
  | IModulesCaddytlsPkiRootCaPool
  | IModulesCaddytlsStoragePool;

/**
 * Enables and configures TLS client authentication.
 * ClientAuthentication configures TLS client auth. */
export interface IModulesCaddytlsClientAuthentication {
  /**
   * Certificate authority module which provides the certificate pool of trusted certificates */
  ca?: ISource;
  trusted_ca_certs?: Array<string>;
  trusted_ca_certs_pem_files?: Array<string>;
  trusted_leaf_certs?: Array<string>;
  verifiers?: Array<unknown>;
  /**
   * The mode for authenticating the client. Allowed values are:
   * Mode | Description
   * -----|---------------
   * `request` | Ask clients for a certificate, but allow even if there isn't one; do not verify it
   * `require` | Require clients to present a certificate, but do not verify it
   * `verify_if_given` | Ask clients for a certificate; allow even if there isn't one, but verify it if there is
   * `require_and_verify` | Require clients to present a valid certificate that is verified
   * The default mode is `require_and_verify` if any
   * TrustedCACerts or TrustedCACertPEMFiles or TrustedLeafCerts
   * are provided; otherwise, the default mode is `require`. */
  mode?: string;
  [key: string]: any;
}

/**
 * How to handle TLS connections. At least one policy is
 * required to enable HTTPS on this server if automatic
 * HTTPS is disabled or does not apply.
 * ConnectionPolicy specifies the logic for handling a TLS handshake.
 * An empty policy is valid; safe and sensible defaults will be used. */
export interface IModulesCaddytlsConnectionPolicy {
  /**
   * How to match this policy with a TLS ClientHello. If
   * this policy is the first to match, it will be used.
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  match: IHandshakeMatch;
  certificate_selection?: IModulesCaddytlsCustomCertSelectionPolicy;
  cipher_suites?: Array<string>;
  curves?: Array<string>;
  alpn?: Array<string>;
  /**
   * Minimum TLS protocol version to allow. Default: `tls1.2` */
  protocol_min?: string;
  /**
   * Maximum TLS protocol version to allow. Default: `tls1.3` */
  protocol_max?: string;
  /**
   * Reject TLS connections. EXPERIMENTAL: May change. */
  drop?: boolean;
  client_authentication?: IModulesCaddytlsClientAuthentication;
  /**
   * DefaultSNI becomes the ServerName in a ClientHello if there
   * is no policy configured for the empty SNI value. */
  default_sni?: string;
  /**
   * FallbackSNI becomes the ServerName in a ClientHello if
   * the original ServerName doesn't match any certificates
   * in the cache. The use cases for this are very niche;
   * typically if a client is a CDN and passes through the
   * ServerName of the downstream handshake but can accept
   * a certificate with the origin's hostname instead, then
   * you would set this to your origin's hostname. Note that
   * Caddy must be managing a certificate for this name.
   * This feature is EXPERIMENTAL and subject to change or removal. */
  fallback_sni?: string;
  /**
   * Also known as "SSLKEYLOGFILE", TLS secrets will be written to
   * this file in NSS key log format which can then be parsed by
   * Wireshark and other tools. This is INSECURE as it allows other
   * programs or tools to decrypt TLS connections. However, this
   * capability can be useful for debugging and troubleshooting.
   * **ENABLING THIS LOG COMPROMISES SECURITY!**
   * This feature is EXPERIMENTAL and subject to change or removal. */
  insecure_secrets_log?: string;
  [key: string]: any;
}

/**
 * AutoHTTPS configures or disables automatic HTTPS within this server.
 * HTTPS is enabled automatically and by default when qualifying names
 * are present in a Host matcher and/or when the server is listening
 * only on the HTTPS port.
 * AutoHTTPSConfig is used to disable automatic HTTPS
 * or certain aspects of it for a specific server.
 * HTTPS is enabled automatically and by default when
 * qualifying hostnames are available from the config. */
export interface IModulesCaddyhttpAutoHttpsConfig {
  /**
   * If true, automatic HTTPS will be entirely disabled,
   * including certificate management and redirects. */
  disable?: boolean;
  /**
   * If true, only automatic HTTP->HTTPS redirects will
   * be disabled, but other auto-HTTPS features will
   * remain enabled. */
  disable_redirects?: boolean;
  /**
   * If true, automatic certificate management will be
   * disabled, but other auto-HTTPS features will
   * remain enabled. */
  disable_certificates?: boolean;
  skip?: Array<string>;
  skip_certificates?: Array<string>;
  /**
   * By default, automatic HTTPS will obtain and renew
   * certificates for qualifying hostnames. However, if
   * a certificate with a matching SAN is already loaded
   * into the cache, certificate management will not be
   * enabled. To force automated certificate management
   * regardless of loaded certificates, set this to true. */
  ignore_loaded_certificates?: boolean;
  [key: string]: any;
}

/**
 * CloudflareIPRange provides a range of IP address prefixes (CIDRs) retrieved from cloudflare. */
export interface IGithubComWeidiDengCaddyCloudflareIpCloudflareIpRange {
  /**
   * refresh Interval
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  /**
   * request Timeout
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  timeout?: IDuration;
  [key: string]: any;
}

/**
 * StaticIPRange provides a static range of IP address prefixes (CIDRs). */
export interface IModulesCaddyhttpStaticIpRange {
  ranges?: Array<string>;
  [key: string]: any;
}

/**
 * BunnyIPRange provides a range of IP address prefixes (CIDRs) retrieved from https://api.bunny.net/system/edgeserverlist and https://api.bunny.net/system/edgeserverlist/ipv6. */
export interface IGithubComDigilolnetCaddyBunnyIpBunnyIpRange {
  /**
   * refresh Interval
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  /**
   * request Timeout
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  timeout?: IDuration;
  [key: string]: any;
}

/**
 * This module combines the prefixes returned by several other IP source plugins.
 * In a caddyfile, you can specify these in the block following the "combine" tag. */
export interface IGithubComFvbommelCaddyCombineIpRangesCombinedIpRange {
  parts?: Array<unknown>;
  [key: string]: any;
}

/**
 * DNSRange provides a range of IP addresses associated with a DNS name.
 * Each range will only contain a single IP. */
export interface IGithubComFvbommelCaddyDnsIpRangeDnsRange {
  hosts?: Array<string>;
  /**
   * The refresh interval. Defaults to DefaultInterval.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  [key: string]: any;
}

/**
 * The module that auto trusted_proxies `AWS CloudFront EDGE servers` from CloudFront.
 * Doc: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
 * Range from: https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips */
export interface IGithubComXcaddypluginsCaddyTrustedCloudfrontCaddyTrustedCloudFront {
  /**
   * Interval to update the trusted proxies list. default: 1d
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  [key: string]: any;
}

/**
 * The module auto trusted_proxies `GCP CloudCDN EDGE servers` from `_cloud-eoips.googleusercontent.com` TXT record
 * Doc: https://cloud.google.com/cdn/docs/set-up-external-backend-internet-neg
 * Range from: _cloud-eoips.googleusercontent.com */
export interface IGithubComXcaddypluginsCaddyTrustedGcpCloudcdnCaddyTrustedGcpCloudCdn {
  /**
   * Interval to update the trusted proxies list. default: 1d
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  [key: string]: any;
}

export type IIpSources =
  | IGithubComWeidiDengCaddyCloudflareIpCloudflareIpRange
  | IModulesCaddyhttpStaticIpRange
  | IGithubComDigilolnetCaddyBunnyIpBunnyIpRange
  | IGithubComFvbommelCaddyCombineIpRangesCombinedIpRange
  | IGithubComFvbommelCaddyDnsIpRangeDnsRange
  | IGithubComXcaddypluginsCaddyTrustedCloudfrontCaddyTrustedCloudFront
  | IGithubComXcaddypluginsCaddyTrustedGcpCloudcdnCaddyTrustedGcpCloudCdn;

/**
 * Enables access logging and configures how access logs are handled
 * in this server. To minimally enable access logs, simply set this
 * to a non-null, empty struct.
 * ServerLogConfig describes a server's logging configuration. If
 * enabled without customization, all requests to this server are
 * logged to the default logger; logger destinations may be
 * customized per-request-host. */
export interface IModulesCaddyhttpServerLogConfig {
  /**
   * The default logger name for all logs emitted by this server for
   * hostnames that are not in the logger_names map. */
  default_logger_name?: string;
  logger_names?: Record<string, Array<string>>;
  skip_hosts?: Array<string>;
  /**
   * If true, requests to any host not appearing in the
   * logger_names map will not be logged. */
  skip_unmapped_hosts?: boolean;
  /**
   * If true, credentials that are otherwise omitted, will be logged.
   * The definition of credentials is defined by https://fetch.spec.whatwg.org/#credentials,
   * and this includes some request and response headers, i.e `Cookie`,
   * `Set-Cookie`, `Authorization`, and `Proxy-Authorization`. */
  should_log_credentials?: boolean;
  /**
   * Log each individual handler that is invoked.
   * Requires that the log emit at DEBUG level.
   * NOTE: This may log the configuration of your
   * HTTP handler modules; do not enable this in
   * insecure contexts when there is sensitive
   * data in the configuration.
   * EXPERIMENTAL: Subject to change or removal. */
  trace?: boolean;
  [key: string]: any;
}

/**
    * If set, metrics observations will be enabled.
 This setting is EXPERIMENTAL and subject to change.
 
 
 Metrics configures metrics observations.
 EXPERIMENTAL and subject to change or removal.
    */
export type IModulesCaddyhttpMetrics = Record<string, any>;

/**
 * Servers is the list of servers, keyed by arbitrary names chosen
 * at your discretion for your own convenience; the keys do not
 * affect functionality.
 * Server describes an HTTP server. */
export interface IModulesCaddyhttpServer {
  listen?: Array<string>;
  listener_wrappers?: Array<unknown>;
  /**
   * How long to allow a read from a client's upload. Setting this
   * to a short, non-zero value can mitigate slowloris attacks, but
   * may also affect legitimately slow clients.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  read_timeout?: IDuration;
  /**
   * ReadHeaderTimeout is like ReadTimeout but for request headers.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  read_header_timeout?: IDuration;
  /**
   * WriteTimeout is how long to allow a write to a client. Note
   * that setting this to a small value when serving large files
   * may negatively affect legitimately slow clients.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  write_timeout?: IDuration;
  /**
   * IdleTimeout is the maximum time to wait for the next request
   * when keep-alives are enabled. If zero, a default timeout of
   * 5m is applied to help avoid resource exhaustion.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  idle_timeout?: IDuration;
  /**
   * KeepAliveInterval is the interval at which TCP keepalive packets
   * are sent to keep the connection alive at the TCP layer when no other
   * data is being transmitted. The default is 15s.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  keepalive_interval?: IDuration;
  /**
   * MaxHeaderBytes is the maximum size to parse from a client's
   * HTTP request headers. */
  max_header_bytes?: number;
  /**
   * Enable full-duplex communication for HTTP/1 requests.
   * Only has an effect if Caddy was built with Go 1.21 or later.
   * For HTTP/1 requests, the Go HTTP server by default consumes any
   * unread portion of the request body before beginning to write the
   * response, preventing handlers from concurrently reading from the
   * request and writing the response. Enabling this option disables
   * this behavior and permits handlers to continue to read from the
   * request while concurrently writing the response.
   * For HTTP/2 requests, the Go HTTP server always permits concurrent
   * reads and responses, so this option has no effect.
   * Test thoroughly with your HTTP clients, as some older clients may
   * not support full-duplex HTTP/1 which can cause them to deadlock.
   * See https://github.com/golang/go/issues/57786 for more info.
   * TODO: This is an EXPERIMENTAL feature. Subject to change or removal. */
  enable_full_duplex?: boolean;
  /**
   * RouteList is a list of server routes that can
   * create a middleware chain. */
  routes?: Array<IModulesCaddyhttpRoute>;
  errors?: IModulesCaddyhttpHttpErrorConfig;
  named_routes?: Record<string, IModulesCaddyhttpRoute>;
  /**
   * ConnectionPolicies govern the establishment of TLS connections. It is
   * an ordered group of connection policies; the first matching policy will
   * be used to configure TLS connections at handshake-time. */
  tls_connection_policies?: Array<IModulesCaddytlsConnectionPolicy>;
  automatic_https?: IModulesCaddyhttpAutoHttpsConfig;
  /**
   * If true, will require that a request's Host header match
   * the value of the ServerName sent by the client's TLS
   * ClientHello; often a necessary safeguard when using TLS
   * client authentication. */
  strict_sni_host?: boolean;
  /**
   * A module which provides a source of IP ranges, from which
   * requests should be trusted. By default, no proxies are
   * trusted.
   * On its own, this configuration will not do anything,
   * but it can be used as a default set of ranges for
   * handlers or matchers in routes to pick up, instead
   * of needing to configure each of them. See the
   * `reverse_proxy` handler for example, which uses this
   * to trust sensitive incoming `X-Forwarded-*` headers. */
  trusted_proxies?: IIpSources;
  client_ip_headers?: Array<string>;
  /**
   * If greater than zero, enables strict ClientIPHeaders
   * (default X-Forwarded-For) parsing. If enabled, the
   * ClientIPHeaders will be parsed from right to left, and
   * the first value that is both valid and doesn't match the
   * trusted proxy list will be used as client IP. If zero,
   * the ClientIPHeaders will be parsed from left to right,
   * and the first value that is a valid IP address will be
   * used as client IP.
   * This depends on `trusted_proxies` being configured.
   * This option is disabled by default. */
  trusted_proxies_strict?: number;
  logs?: IModulesCaddyhttpServerLogConfig;
  protocols?: Array<string>;
  metrics: IModulesCaddyhttpMetrics;
  [key: string]: any;
}

/**
 * App is a robust, production-ready HTTP server.
 * HTTPS is enabled by default if host matchers with qualifying names are used
 * in any of routes; certificates are automatically provisioned and renewed.
 * Additionally, automatic HTTPS will also enable HTTPS for servers that listen
 * only on the HTTPS port but which do not have any TLS connection policies
 * defined by adding a good, default TLS connection policy.
 * In HTTP routes, additional placeholders are available (replace any `*`):
 * Placeholder | Description
 * ------------|---------------
 * `{http.request.body}` | The request body (⚠️ inefficient; use only for debugging)
 * `{http.request.cookie.*}` | HTTP request cookie
 * `{http.request.duration}` | Time up to now spent handling the request (after decoding headers from client)
 * `{http.request.duration_ms}` | Same as 'duration', but in milliseconds.
 * `{http.request.uuid}` | The request unique identifier
 * `{http.request.header.*}` | Specific request header field
 * `{http.request.host}` | The host part of the request's Host header
 * `{http.request.host.labels.*}` | Request host labels (0-based from right); e.g. for foo.example.com: 0=com, 1=example, 2=foo
 * `{http.request.hostport}` | The host and port from the request's Host header
 * `{http.request.method}` | The request method
 * `{http.request.orig_method}` | The request's original method
 * `{http.request.orig_uri}` | The request's original URI
 * `{http.request.orig_uri.path}` | The request's original path
 * `{http.request.orig_uri.path.*}` | Parts of the original path, split by `/` (0-based from left)
 * `{http.request.orig_uri.path.dir}` | The request's original directory
 * `{http.request.orig_uri.path.file}` | The request's original filename
 * `{http.request.orig_uri.query}` | The request's original query string (without `?`)
 * `{http.request.port}` | The port part of the request's Host header
 * `{http.request.proto}` | The protocol of the request
 * `{http.request.local.host}` | The host (IP) part of the local address the connection arrived on
 * `{http.request.local.port}` | The port part of the local address the connection arrived on
 * `{http.request.local}` | The local address the connection arrived on
 * `{http.request.remote.host}` | The host (IP) part of the remote client's address
 * `{http.request.remote.port}` | The port part of the remote client's address
 * `{http.request.remote}` | The address of the remote client
 * `{http.request.scheme}` | The request scheme, typically `http` or `https`
 * `{http.request.tls.version}` | The TLS version name
 * `{http.request.tls.cipher_suite}` | The TLS cipher suite
 * `{http.request.tls.resumed}` | The TLS connection resumed a previous connection
 * `{http.request.tls.proto}` | The negotiated next protocol
 * `{http.request.tls.proto_mutual}` | The negotiated next protocol was advertised by the server
 * `{http.request.tls.server_name}` | The server name requested by the client, if any
 * `{http.request.tls.client.fingerprint}` | The SHA256 checksum of the client certificate
 * `{http.request.tls.client.public_key}` | The public key of the client certificate.
 * `{http.request.tls.client.public_key_sha256}` | The SHA256 checksum of the client's public key.
 * `{http.request.tls.client.certificate_pem}` | The PEM-encoded value of the certificate.
 * `{http.request.tls.client.certificate_der_base64}` | The base64-encoded value of the certificate.
 * `{http.request.tls.client.issuer}` | The issuer DN of the client certificate
 * `{http.request.tls.client.serial}` | The serial number of the client certificate
 * `{http.request.tls.client.subject}` | The subject DN of the client certificate
 * `{http.request.tls.client.san.dns_names.*}` | SAN DNS names(index optional)
 * `{http.request.tls.client.san.emails.*}` | SAN email addresses (index optional)
 * `{http.request.tls.client.san.ips.*}` | SAN IP addresses (index optional)
 * `{http.request.tls.client.san.uris.*}` | SAN URIs (index optional)
 * `{http.request.uri}` | The full request URI
 * `{http.request.uri.path}` | The path component of the request URI
 * `{http.request.uri.path.*}` | Parts of the path, split by `/` (0-based from left)
 * `{http.request.uri.path.dir}` | The directory, excluding leaf filename
 * `{http.request.uri.path.file}` | The filename of the path, excluding directory
 * `{http.request.uri.query}` | The query string (without `?`)
 * `{http.request.uri.query.*}` | Individual query string value
 * `{http.response.header.*}` | Specific response header field
 * `{http.vars.*}` | Custom variables in the HTTP handler chain
 * `{http.shutting_down}` | True if the HTTP app is shutting down
 * `{http.time_until_shutdown}` | Time until HTTP server shutdown, if scheduled */
export interface IModulesCaddyhttpApp {
  /**
   * HTTPPort specifies the port to use for HTTP (as opposed to HTTPS),
   * which is used when setting up HTTP->HTTPS redirects or ACME HTTP
   * challenge solvers. Default: 80. */
  http_port?: number;
  /**
   * HTTPSPort specifies the port to use for HTTPS, which is used when
   * solving the ACME TLS-ALPN challenges, or whenever HTTPS is needed
   * but no specific port number is given. Default: 443. */
  https_port?: number;
  /**
   * GracePeriod is how long to wait for active connections when shutting
   * down the servers. During the grace period, no new connections are
   * accepted, idle connections are closed, and active connections will
   * be given the full length of time to become idle and close.
   * Once the grace period is over, connections will be forcefully closed.
   * If zero, the grace period is eternal. Default: 0.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  grace_period?: IDuration;
  /**
   * ShutdownDelay is how long to wait before initiating the grace
   * period. When this app is stopping (e.g. during a config reload or
   * process exit), all servers will be shut down. Normally this immediately
   * initiates the grace period. However, if this delay is configured, servers
   * will not be shut down until the delay is over. During this time, servers
   * continue to function normally and allow new connections. At the end, the
   * grace period will begin. This can be useful to allow downstream load
   * balancers time to move this instance out of the rotation without hiccups.
   * When shutdown has been scheduled, placeholders {http.shutting_down} (bool)
   * and {http.time_until_shutdown} (duration) may be useful for health checks.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  shutdown_delay?: IDuration;
  servers?: Record<string, IModulesCaddyhttpServer>;
  [key: string]: any;
}

/**
 * The root certificate to use; if null, one will be generated.
 * KeyPair represents a public-private key pair, where the
 * public key is also called a certificate. */
export interface IModulesCaddypkiKeyPair {
  /**
   * The certificate. By default, this should be the path to
   * a PEM file unless format is something else. */
  certificate?: string;
  /**
   * The private key. By default, this should be the path to
   * a PEM file unless format is something else. */
  private_key?: string;
  /**
   * The format in which the certificate and private
   * key are provided. Default: pem_file */
  format?: string;
  [key: string]: any;
}

/**
 * The certificate authorities to manage. Each CA is keyed by an
 * ID that is used to uniquely identify it from other CAs.
 * At runtime, the GetCA() method should be used instead to ensure
 * the default CA is provisioned if it hadn't already been.
 * The default CA ID is "local".
 * CA describes a certificate authority, which consists of
 * root/signing certificates and various settings pertaining
 * to the issuance of certificates and trusting them. */
export interface IModulesCaddypkiCa {
  /**
   * The user-facing name of the certificate authority. */
  name?: string;
  /**
   * The name to put in the CommonName field of the
   * root certificate. */
  root_common_name?: string;
  /**
   * The name to put in the CommonName field of the
   * intermediate certificates. */
  intermediate_common_name?: string;
  /**
   * The lifetime for the intermediate certificates
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  intermediate_lifetime?: IDuration;
  /**
   * Whether Caddy will attempt to install the CA's root
   * into the system trust store, as well as into Java
   * and Mozilla Firefox trust stores. Default: true. */
  install_trust?: boolean;
  root?: IModulesCaddypkiKeyPair;
  intermediate: IModulesCaddypkiKeyPair;
  storage: IStorage;
  [key: string]: any;
}

/**
 * PKI provides Public Key Infrastructure facilities for Caddy.
 * This app can define certificate authorities (CAs) which are capable
 * of signing certificates. Other modules can be configured to use
 * the CAs defined by this app for issuing certificates or getting
 * key information needed for establishing trust. */
export interface IModulesCaddypkiPki {
  certificate_authorities?: Record<string, IModulesCaddypkiCa>;
  [key: string]: any;
}

/**
 * CertKeyFilePair pairs certificate and key file names along with their
 * encoding format so that they can be loaded from disk. */
export interface IModulesCaddytlsCertKeyFilePair {
  /**
   * Path to the certificate (public key) file. */
  certificate?: string;
  /**
   * Path to the private key file. */
  key?: string;
  /**
   * The format of the cert and key. Can be "pem". Default: "pem" */
  format?: string;
  tags?: Array<string>;
  [key: string]: any;
}

/**
 * CertKeyPEMPair pairs certificate and key PEM blocks. */
export interface IModulesCaddytlsCertKeyPemPair {
  /**
   * The certificate (public key) in PEM format. */
  certificate?: string;
  /**
   * The private key in PEM format. */
  key?: string;
  tags?: Array<string>;
  [key: string]: any;
}

/**
 * StorageLoader loads certificates and their associated keys
 * from the globally configured storage module. */
export interface IModulesCaddytlsStorageLoader {
  pairs?: Array<IModulesCaddytlsCertKeyFilePair>;
  [key: string]: any;
}

export interface ICertificates {
  automate?: IModulesCaddytlsAutomateLoader;
  load_files?: IModulesCaddytlsFileLoader;
  load_folders?: IModulesCaddytlsFolderLoader;
  load_pem?: IModulesCaddytlsPemLoader;
  load_storage?: IModulesCaddytlsStorageLoader;
  [key: string]: any;
}

/**
 * The list of automation policies. The first policy matching
 * a certificate or subject name will be applied.
 * AutomationPolicy designates the policy for automating the
 * management (obtaining, renewal, and revocation) of managed
 * TLS certificates.
 * An AutomationPolicy value is not valid until it has been
 * provisioned; use the `AddAutomationPolicy()` method on the
 * TLS app to properly provision a new policy. */
export interface IModulesCaddytlsAutomationPolicy {
  subjects?: Array<string>;
  issuers?: Array<unknown>;
  get_certificate?: Array<unknown>;
  /**
   * If true, certificates will be requested with MustStaple. Not all
   * CAs support this, and there are potentially serious consequences
   * of enabling this feature without proper threat modeling. */
  must_staple?: boolean;
  /**
   * How long before a certificate's expiration to try renewing it,
   * as a function of its total lifetime. As a general and conservative
   * rule, it is a good idea to renew a certificate when it has about
   * 1/3 of its total lifetime remaining. This utilizes the majority
   * of the certificate's lifetime while still saving time to
   * troubleshoot problems. However, for extremely short-lived certs,
   * you may wish to increase the ratio to ~1/2. */
  renewal_window_ratio?: number;
  /**
   * The type of key to generate for certificates.
   * Supported values: `ed25519`, `p256`, `p384`, `rsa2048`, `rsa4096`. */
  key_type?: string;
  storage: IStorage;
  /**
   * If true, certificates will be managed "on demand"; that is, during
   * TLS handshakes or when needed, as opposed to at startup or config
   * load. This enables On-Demand TLS for this policy. */
  on_demand?: boolean;
  /**
   * If true, private keys already existing in storage
   * will be reused. Otherwise, a new key will be
   * created for every new certificate to mitigate
   * pinning and reduce the scope of key compromise.
   * TEMPORARY: Key pinning is against industry best practices.
   * This property will likely be removed in the future.
   * Do not rely on it forever; watch the release notes. */
  reuse_private_keys?: boolean;
  /**
   * Disables OCSP stapling. Disabling OCSP stapling puts clients at
   * greater risk, reduces their privacy, and usually lowers client
   * performance. It is NOT recommended to disable this unless you
   * are able to justify the costs.
   * EXPERIMENTAL. Subject to change. */
  disable_ocsp_stapling?: boolean;
  ocsp_overrides?: Record<string, string>;
  [key: string]: any;
}

/**
 * PermissionByHTTP determines permission for a TLS certificate by
 * making a request to an HTTP endpoint. */
export interface IModulesCaddytlsPermissionByHttp {
  /**
   * The endpoint to access. It should be a full URL.
   * A query string parameter "domain" will be added to it,
   * containing the domain (or IP) for the desired certificate,
   * like so: `?domain=example.com`. Generally, this endpoint
   * is not exposed publicly to avoid a minor information leak
   * (which domains are serviced by your application).
   * The endpoint must return a 200 OK status if a certificate
   * is allowed; anything else will cause it to be denied.
   * Redirects are not followed. */
  endpoint?: string;
  [key: string]: any;
}

export type IPermission = IModulesCaddytlsPermissionByHttp;

/**
 * DEPRECATED. An optional rate limit to throttle
 * the checking of storage and the issuance of
 * certificates from handshakes if not already in
 * storage. WILL BE REMOVED IN A FUTURE RELEASE.
 * DEPRECATED. WILL LIKELY BE REMOVED SOON.
 * Instead of using this rate limiter, use a proper tool such as a
 * level 3 or 4 firewall and/or a permission module to apply rate limits. */
export interface IModulesCaddytlsRateLimit {
  /**
   * A duration value. Storage may be checked and a certificate may be
   * obtained 'burst' times during this interval.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  interval?: IDuration;
  /**
   * How many times during an interval storage can be checked or a
   * certificate can be obtained. */
  burst?: number;
  [key: string]: any;
}

/**
 * On-Demand TLS defers certificate operations to the
 * moment they are needed, e.g. during a TLS handshake.
 * Useful when you don't know all the hostnames at
 * config-time, or when you are not in control of the
 * domain names you are managing certificates for.
 * In 2015, Caddy became the first web server to
 * implement this experimental technology.
 * Note that this field does not enable on-demand TLS;
 * it only configures it for when it is used. To enable
 * it, create an automation policy with `on_demand`.
 * OnDemandConfig configures on-demand TLS, for obtaining
 * needed certificates at handshake-time. Because this
 * feature can easily be abused, you should use this to
 * establish rate limits and/or an internal endpoint that
 * Caddy can "ask" if it should be allowed to manage
 * certificates for a given hostname. */
export interface IModulesCaddytlsOnDemandConfig {
  /**
   * DEPRECATED. WILL BE REMOVED SOON. Use 'permission' instead. */
  ask?: string;
  /**
   * REQUIRED. A module that will determine whether a
   * certificate is allowed to be loaded from storage
   * or obtained from an issuer on demand. */
  permission?: IPermission;
  rate_limit?: IModulesCaddytlsRateLimit;
  [key: string]: any;
}

/**
 * Configures certificate automation.
 * AutomationConfig governs the automated management of TLS certificates. */
export interface IModulesCaddytlsAutomationConfig {
  policies?: Array<IModulesCaddytlsAutomationPolicy>;
  on_demand?: IModulesCaddytlsOnDemandConfig;
  /**
   * Caddy staples OCSP (and caches the response) for all
   * qualifying certificates by default. This setting
   * changes how often it scans responses for freshness,
   * and updates them if they are getting stale. Default: 1h
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  ocsp_interval?: IDuration;
  /**
   * Every so often, Caddy will scan all loaded, managed
   * certificates for expiration. This setting changes how
   * frequently the scan for expiring certificates is
   * performed. Default: 10m
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  renew_interval?: IDuration;
  /**
   * How often to scan storage units for old or expired
   * assets and remove them. These scans exert lots of
   * reads (and list operations) on the storage module, so
   * choose a longer interval for large deployments.
   * Default: 24h
   * Storage will always be cleaned when the process first
   * starts. Then, a new cleaning will be started this
   * duration after the previous cleaning started if the
   * previous cleaning finished in less than half the time
   * of this interval (otherwise next start will be skipped).
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  storage_clean_interval?: IDuration;
  [key: string]: any;
}

/**
 * Provider implements a distributed STEK provider. This
 * module will obtain STEKs from a storage module instead
 * of generating STEKs internally. This allows STEKs to be
 * coordinated, improving TLS session resumption in a cluster. */
export interface IModulesCaddytlsDistributedstekProvider {
  storage: IStorage;
  [key: string]: any;
}

/**
 * undefined
 */
export type IModulesCaddytlsStandardstekStandardStekProvider = Record<
  string,
  any
>;

export type IStek =
  | IModulesCaddytlsDistributedstekProvider
  | IModulesCaddytlsStandardstekStandardStekProvider;

/**
 * Configures session ticket ephemeral keys (STEKs).
 * SessionTicketService configures and manages TLS session tickets. */
export interface IModulesCaddytlsSessionTicketService {
  /**
   * KeySource is the method by which Caddy produces or obtains
   * TLS session ticket keys (STEKs). By default, Caddy generates
   * them internally using a secure pseudorandom source. */
  key_source?: IStek;
  /**
   * How often Caddy rotates STEKs. Default: 12h.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  rotation_interval?: IDuration;
  /**
   * The maximum number of keys to keep in rotation. Default: 4. */
  max_keys?: number;
  /**
   * Disables STEK rotation. */
  disable_rotation?: boolean;
  /**
   * Disables TLS session resumption by tickets. */
  disabled?: boolean;
  [key: string]: any;
}

/**
 * Configures the in-memory certificate cache.
 * CertCacheOptions configures the certificate cache. */
export interface IModulesCaddytlsCertCacheOptions {
  /**
   * Maximum number of certificates to allow in the
   * cache. If reached, certificates will be randomly
   * evicted to make room for new ones. Default: 10,000 */
  capacity?: number;
  [key: string]: any;
}

/**
 * TLS provides TLS facilities including certificate
 * loading and management, client auth, and more. */
export interface IModulesCaddytlsTls {
  /**
   * Certificates to load into memory for quick recall during
   * TLS handshakes. Each key is the name of a certificate
   * loader module.
   * The "automate" certificate loader module can be used to
   * specify a list of subjects that need certificates to be
   * managed automatically. The first matching automation
   * policy will be applied to manage the certificate(s).
   * All loaded certificates get pooled
   * into the same cache and may be used to complete TLS
   * handshakes for the relevant server names (SNI).
   * Certificates loaded manually (anything other than
   * "automate") are not automatically managed and will
   * have to be refreshed manually before they expire.
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  certificates: ICertificates;
  automation?: IModulesCaddytlsAutomationConfig;
  session_tickets?: IModulesCaddytlsSessionTicketService;
  cache?: IModulesCaddytlsCertCacheOptions;
  /**
   * Disables OCSP stapling for manually-managed certificates only.
   * To configure OCSP stapling for automated certificates, use an
   * automation policy instead.
   * Disabling OCSP stapling puts clients at greater risk, reduces their
   * privacy, and usually lowers client performance. It is NOT recommended
   * to disable this unless you are able to justify the costs.
   * EXPERIMENTAL. Subject to change. */
  disable_ocsp_stapling?: boolean;
  [key: string]: any;
}

/**
 * Workers configures the worker scripts to start. */
export interface IGithubComDunglasFrankenphpCaddyWorkerConfig {
  /**
   * FileName sets the path to the worker script. */
  file_name?: string;
  /**
   * Num sets the number of workers to start. */
  num?: number;
  env?: Record<string, string>;
  [key: string]: any;
}

export interface IGithubComDunglasFrankenphpCaddyFrankenPhpApp {
  /**
   * NumThreads sets the number of PHP threads to start. Default: 2x the number of available CPUs. */
  num_threads?: number;
  workers?: Array<IGithubComDunglasFrankenphpCaddyWorkerConfig>;
  [key: string]: any;
}

/**
 * Generic represents username and password credentials, with optional
 * domain name field. */
export interface IGithubComGreenpauGoAuthcrunchPkgCredentialsGeneric {
  name?: string;
  username?: string;
  password?: string;
  domain?: string;
  [key: string]: any;
}

/**
 * Config represents a collection of various credentials. */
export interface IGithubComGreenpauGoAuthcrunchPkgCredentialsConfig {
  generic?: Array<IGithubComGreenpauGoAuthcrunchPkgCredentialsGeneric>;
  [key: string]: any;
}

/**
 * Link represents a single HTML link. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnUiLink {
  link?: string;
  title?: string;
  style?: string;
  open_new_window?: boolean;
  target?: string;
  target_enabled?: boolean;
  icon_name?: string;
  icon_enabled?: boolean;
  [key: string]: any;
}

/**
 * UserRealm represents a single authentication realm/domain. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnUiUserRealm {
  name?: string;
  label?: string;
  [key: string]: any;
}

/**
 * UI holds the configuration for the user interface.
 * Parameters represent a common set of configuration settings
 * for HTML UI. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnUiParameters {
  theme?: string;
  templates?: Record<string, string>;
  allow_role_selection?: boolean;
  title?: string;
  logo_url?: string;
  logo_description?: string;
  private_links?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthnUiLink>;
  auto_redirect_url?: string;
  realms?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthnUiUserRealm>;
  password_recovery_enabled?: boolean;
  custom_css_path?: string;
  custom_js_path?: string;
  [key: string]: any;
}

/**
 * UserRegistrationConfig holds the configuration for the user registration.
 * Config represents a common set of configuration settings for user registration */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnRegistrationConfig {
  /**
   * The switch determining whether the registration is enabled/disabled. */
  disabled?: boolean;
  /**
   * The title of the registration page */
  title?: string;
  /**
   * The mandatory registration code. It is possible adding multiple
   * codes, comma separated. */
  code?: string;
  /**
   * The file path to registration database. */
  dropbox?: string;
  /**
   * The switch determining whether a user must accept terms and conditions */
  require_accept_terms?: boolean;
  /**
   * The switch determining whether the domain associated with an email has
   * a valid MX DNS record. */
  require_domain_mx?: boolean;
  /**
   * The link to terms and conditions document. */
  terms_conditions_link?: string;
  /**
   * The link to privacy policy document. */
  privacy_policy_link?: string;
  /**
   * The email provider used for the notifications. */
  email_provider?: string;
  admin_emails?: Array<string>;
  [key: string]: any;
}

/**
 * UserTransformerConfig holds the configuration for the user transformer.
 * Config represents a common set of configuration settings
 * applicable to the cookies issued by authn.Authenticator. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnTransformerConfig {
  matchers?: Array<string>;
  actions?: Array<string>;
  [key: string]: any;
}

/**
 * DomainConfig represents a common set of configuration settings
 * applicable to the cookies issued by authn.Authenticator. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnCookieDomainConfig {
  seq?: number;
  domain?: string;
  path?: string;
  lifetime?: number;
  insecure?: boolean;
  same_site?: string;
  [key: string]: any;
}

/**
 * CookieConfig holds the configuration for the cookies issues by Authenticator.
 * Config represents a common set of configuration settings
 * applicable to the cookies issued by authn.Authenticator. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnCookieConfig {
  domains?: Record<
    string,
    IGithubComGreenpauGoAuthcrunchPkgAuthnCookieDomainConfig
  >;
  path?: string;
  lifetime?: number;
  insecure?: boolean;
  same_site?: string;
  [key: string]: any;
}

/**
 * AccessListConfigs hold the configurations for the ACL of the token validator.
 * RuleConfiguration consists of a list of conditions and and actions */
export interface IGithubComGreenpauGoAuthcrunchPkgAclRuleConfiguration {
  comment?: string;
  conditions?: Array<string>;
  action?: string;
  [key: string]: any;
}

/**
 * TokenValidatorOptions holds the configuration for the token validator.
 * TokenValidatorOptions provides options for TokenValidator. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthzOptionsTokenValidatorOptions {
  validate_source_address?: boolean;
  validate_bearer_header?: boolean;
  validate_method_path?: boolean;
  validate_access_list_path_claim?: boolean;
  [key: string]: any;
}

/**
 * CryptoKeyConfigs hold the configurations for the keys used to issue and validate user tokens.
 * CryptoKeyConfig is common token-related configuration settings. */
export interface IGithubComGreenpauGoAuthcrunchPkgKmsCryptoKeyConfig {
  /**
   * Seq is the order in which a key would be processed. */
  seq?: number;
  /**
   * ID is the key ID, aka kid. */
  id?: string;
  /**
   * Usage is the intended key usage. The values are: sign, verify, both,
   * or auto. */
  usage?: string;
  /**
   * TokenName is the token name associated with the key. */
  token_name?: string;
  /**
   * Source is either config or env. */
  source?: string;
  /**
   * Algorithm is either hmac, rsa, or ecdsa. */
  algorithm?: string;
  /**
   * EnvVarName is the name of environment variables holding either the value of
   * a key or the path a directory or file containing a key. */
  env_var_name?: string;
  /**
   * EnvVarType indicates how to interpret the value found in the EnvVarName. If
   * it is blank, then the assumption is the environment variable value
   * contains either public or private key. */
  env_var_type?: string;
  /**
   * EnvVarValue is the value associated with the environment variable set by EnvVarName. */
  env_var_value?: string;
  /**
   * FilePath is the path of a file containing either private or public key. */
  file_path?: string;
  /**
   * DirPath is the path to a directory containing crypto keys. */
  dir_path?: string;
  /**
   * TokenLifetime is the expected token grant lifetime in seconds. */
  token_lifetime?: number;
  /**
   * Secret is the shared key used with HMAC algorithm. */
  token_secret?: string;
  /**
   * PreferredSignMethod is the preferred method to sign tokens, e.g.
   * all HMAC keys could use HS256, HS384, and HS512 methods. By default,
   * the preferred method is HS512. However, one may prefer using HS256. */
  token_sign_method?: string;
  token_eval_expr?: Array<string>;
  [key: string]: any;
}

/**
 * TokenGrantorOptions holds the configuration for the tokens issues by Authenticator.
 * TokenGrantorOptions provides options for TokenGrantor. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthzOptionsTokenGrantorOptions {
  enable_source_address?: boolean;
  [key: string]: any;
}

/**
 * API holds the configuration for API endpoints.
 * APIConfig holds the configuration for API endpoints. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnApiConfig {
  enabled?: boolean;
  [key: string]: any;
}

/**
 * PortalConfig represents Portal configuration. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthnPortalConfig {
  name?: string;
  ui?: IGithubComGreenpauGoAuthcrunchPkgAuthnUiParameters;
  user_registration_config?: IGithubComGreenpauGoAuthcrunchPkgAuthnRegistrationConfig;
  user_transformer_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthnTransformerConfig>;
  cookie_config?: IGithubComGreenpauGoAuthcrunchPkgAuthnCookieConfig;
  identity_stores?: Array<string>;
  identity_providers?: Array<string>;
  access_list_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgAclRuleConfiguration>;
  token_validator_options?: IGithubComGreenpauGoAuthcrunchPkgAuthzOptionsTokenValidatorOptions;
  crypto_key_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgKmsCryptoKeyConfig>;
  crypto_key_store_config?: Record<string, unknown>;
  token_grantor_options?: IGithubComGreenpauGoAuthcrunchPkgAuthzOptionsTokenGrantorOptions;
  api?: IGithubComGreenpauGoAuthcrunchPkgAuthnApiConfig;
  [key: string]: any;
}

/**
 * The list of URI prefixes which bypass authorization.
 * Config contains the entry for the authorization bypass. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthzBypassConfig {
  match_type?: string;
  uri?: string;
  [key: string]: any;
}

/**
 * The list of mappings between header names and field names.
 * Config contains the entry for the HTTP header injection. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthzInjectorConfig {
  header?: string;
  field?: string;
  [key: string]: any;
}

/**
 * BasicAuthConfig is a config for basic authentication. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthproxyBasicAuthConfig {
  enabled?: boolean;
  realms?: Record<string, unknown>;
  [key: string]: any;
}

/**
 * APIKeyAuthConfig is a config for API key-based authentication. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthproxyApiKeyAuthConfig {
  enabled?: boolean;
  realms?: Record<string, unknown>;
  [key: string]: any;
}

/**
 * Config is a config for an identity provider. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthproxyConfig {
  portal_name?: string;
  basic_auth?: IGithubComGreenpauGoAuthcrunchPkgAuthproxyBasicAuthConfig;
  api_key_auth?: IGithubComGreenpauGoAuthcrunchPkgAuthproxyApiKeyAuthConfig;
  [key: string]: any;
}

/**
 * PolicyConfig is Gatekeeper configuration. */
export interface IGithubComGreenpauGoAuthcrunchPkgAuthzPolicyConfig {
  name?: string;
  auth_url_path?: string;
  disable_auth_redirect?: boolean;
  disable_auth_redirect_query?: boolean;
  auth_redirect_query_param?: string;
  /**
   * The status code for the HTTP redirect for non-authorized users. */
  auth_redirect_status_code?: number;
  /**
   * Enable the redirect with Javascript, as opposed to HTTP redirect. */
  redirect_with_javascript?: boolean;
  bypass_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthzBypassConfig>;
  header_injection_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthzInjectorConfig>;
  access_list_rules?: Array<IGithubComGreenpauGoAuthcrunchPkgAclRuleConfiguration>;
  crypto_key_configs?: Array<IGithubComGreenpauGoAuthcrunchPkgKmsCryptoKeyConfig>;
  crypto_key_store_config?: Record<string, unknown>;
  auth_proxy_config?: IGithubComGreenpauGoAuthcrunchPkgAuthproxyConfig;
  allowed_token_sources?: Array<string>;
  strip_token_enabled?: boolean;
  forbidden_url?: string;
  user_identity_field?: string;
  /**
   * Validate HTTP Authorization header. */
  validate_bearer_header?: boolean;
  /**
   * Validate HTTP method and path. */
  validate_method_path?: boolean;
  /**
   * Validate HTTP path derived from JWT token. */
  validate_access_list_path_claim?: boolean;
  /**
   * Validate source address matches between HTTP request and JWT token. */
  validate_source_address?: boolean;
  /**
   * Pass claims from JWT token via HTTP X- headers. */
  pass_claims_with_headers?: boolean;
  login_hint_validators?: Array<string>;
  [key: string]: any;
}

/**
 * EmailProvider represents email messaging provider. */
export interface IGithubComGreenpauGoAuthcrunchPkgMessagingEmailProvider {
  name?: string;
  address?: string;
  protocol?: string;
  credentials?: string;
  sender_email?: string;
  sender_name?: string;
  templates?: Record<string, string>;
  passwordless?: boolean;
  blind_carbon_copy?: Array<string>;
  [key: string]: any;
}

/**
 * FileProvider represents file messaging provider which writes messages
 * to a local file system, */
export interface IGithubComGreenpauGoAuthcrunchPkgMessagingFileProvider {
  name?: string;
  root_dir?: string;
  templates?: Record<string, string>;
  [key: string]: any;
}

/**
 * Config represents a collection of various messaging providers. */
export interface IGithubComGreenpauGoAuthcrunchPkgMessagingConfig {
  email_providers?: Array<IGithubComGreenpauGoAuthcrunchPkgMessagingEmailProvider>;
  file_providers?: Array<IGithubComGreenpauGoAuthcrunchPkgMessagingFileProvider>;
  [key: string]: any;
}

/**
 * IdentityStoreConfig represents an identity store configuration. */
export interface IGithubComGreenpauGoAuthcrunchPkgIdsIdentityStoreConfig {
  name?: string;
  kind?: string;
  params?: Record<string, unknown>;
  [key: string]: any;
}

/**
 * IdentityProviderConfig represents an identity provider configuration. */
export interface IGithubComGreenpauGoAuthcrunchPkgIdpIdentityProviderConfig {
  name?: string;
  kind?: string;
  params?: Record<string, unknown>;
  [key: string]: any;
}

/**
 * Config is a configuration of Server. */
export interface IGithubComGreenpauGoAuthcrunchConfig {
  credentials?: IGithubComGreenpauGoAuthcrunchPkgCredentialsConfig;
  authentication_portals?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthnPortalConfig>;
  authorization_policies?: Array<IGithubComGreenpauGoAuthcrunchPkgAuthzPolicyConfig>;
  messaging?: IGithubComGreenpauGoAuthcrunchPkgMessagingConfig;
  identity_stores?: Array<IGithubComGreenpauGoAuthcrunchPkgIdsIdentityStoreConfig>;
  identity_providers?: Array<IGithubComGreenpauGoAuthcrunchPkgIdpIdentityProviderConfig>;
  [key: string]: any;
}

/**
 * App implements security manager. */
export interface IGithubComGreenpauCaddySecurityApp {
  config?: IGithubComGreenpauGoAuthcrunchConfig;
  [key: string]: any;
}

/**
 * CrowdSec is a Caddy App that functions as a CrowdSec bouncer. It acts
 * as a CrowdSec API client as well as a local cache for CrowdSec decisions,
 * which can be used by the HTTP handler and Layer4 matcher to decide if
 * a request or connection is allowed or not. */
export interface IGithubComHslatmanCaddyCrowdsecBouncerCrowdsecCrowdSec {
  /**
   * APIKey for the CrowdSec Local API */
  api_key?: string;
  /**
   * APIUrl for the CrowdSec Local API. Defaults to http://127.0.0.1:8080/ */
  api_url?: string;
  /**
   * TickerInterval is the interval the StreamBouncer uses for querying
   * the CrowdSec Local API. Defaults to "10s". */
  ticker_interval?: string;
  /**
   * EnableStreaming indicates whether the StreamBouncer should be used.
   * If it's false, the LiveBouncer is used. The StreamBouncer keeps
   * CrowdSec decisions in memory, resulting in quicker lookups. The
   * LiveBouncer will perform an API call to your CrowdSec instance.
   * Defaults to true. */
  enable_streaming?: boolean;
  /**
   * EnableHardFails indicates whether calls to the CrowdSec API should
   * result in hard failures, resulting in Caddy quitting vs.
   * Caddy continuing operation (with a chance of not performing)
   * validations. Defaults to false. */
  enable_hard_fails?: boolean;
  [key: string]: any;
}

/**
    * Allow is PortForwardingAsker module which always allows the session
 
    */
export type IGithubComKadeesshKadeesshInternalLocalforwardAllow = Record<
  string,
  any
>;

/**
    * Allow is PortForwardingAsker module which always rejects the session
 
    */
export type IGithubComKadeesshKadeesshInternalLocalforwardDeny = Record<
  string,
  any
>;

export type ILocalforward =
  | IGithubComKadeesshKadeesshInternalLocalforwardAllow
  | IGithubComKadeesshKadeesshInternalLocalforwardDeny;

/**
 * undefined
 */
export type IGithubComKadeesshKadeesshInternalReverseforwardAllow = Record<
  string,
  any
>;

/**
 * undefined
 */
export type IGithubComKadeesshKadeesshInternalReverseforwardDeny = Record<
  string,
  any
>;

export type IReverseforward =
  | IGithubComKadeesshKadeesshInternalReverseforwardAllow
  | IGithubComKadeesshKadeesshInternalReverseforwardDeny;

/**
    * Allow is PtyAsker module which always allows the PTY session
 
    */
export type IGithubComKadeesshKadeesshInternalPtyAllow = Record<string, any>;

/**
    * Allow is PtyAsker module which always rejects the PTY session
 
    */
export type IGithubComKadeesshKadeesshInternalPtyDeny = Record<string, any>;

export type IPty =
  | IGithubComKadeesshKadeesshInternalPtyAllow
  | IGithubComKadeesshKadeesshInternalPtyDeny;

/**
 * Chained is a multi-authorizer module that authorizes a session against multiple authorizers */
export interface IGithubComKadeesshKadeesshInternalAuthorizationChained {
  authorize?: Array<unknown>;
  [key: string]: any;
}

/**
 * MaxSession is an authorizer that permits sessions so long as the
 * number of active sessions is below the specified maximum. */
export interface IGithubComKadeesshKadeesshInternalAuthorizationMaxSession {
  /**
   * The maximum number of active sessions */
  max_sessions?: number;
  [key: string]: any;
}

/**
    * Public authorizes all sessions
 
    */
export type IGithubComKadeesshKadeesshInternalAuthorizationPublic = Record<
  string,
  any
>;

/**
    * Reject rejects all sessions
 
    */
export type IGithubComKadeesshKadeesshInternalAuthorizationReject = Record<
  string,
  any
>;

export type IAuthorizers =
  | IGithubComKadeesshKadeesshInternalAuthorizationChained
  | IGithubComKadeesshKadeesshInternalAuthorizationMaxSession
  | IGithubComKadeesshKadeesshInternalAuthorizationPublic
  | IGithubComKadeesshKadeesshInternalAuthorizationReject;

/**
    * InMemSFTP is an in-memory SFTP server allowing shared space
 between all users. It starts with an empty space.
 Warning: For illustration purposes only!
 
    */
export type IGithubComKadeesshKadeesshInternalSubsystemInMemSftp = Record<
  string,
  any
>;

export interface ISubsystem {
  inmem_sftp?: IGithubComKadeesshKadeesshInternalSubsystemInMemSftp;
  [key: string]: any;
}

/**
 * Fallback signer checks if the RSA, Ed25519, and ECDSA private keys exist in the storage to load. If they're absent,
 * RSA-4096 and Ed25519 keys are generated and stored. The ECDSA key is only loaded, not generated.
 * It is the default signer. */
export interface IGithubComKadeesshKadeesshInternalSignerFallback {
  storage: IStorage;
  [key: string]: any;
}

/**
 * The `git` filesystem module uses a git repository as the
 * virtual filesystem. */
export interface IGithubComMohammed90CaddyGitFsRepo {
  /**
   * The URL of the git repository */
  url?: string;
  /**
   * The reference to clone the repository at.
   * An empty value means HEAD. */
  ref?: string;
  /**
   * The period between ref refreshes
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  refresh_period?: IDuration;
  [key: string]: any;
}

/**
 * FS is a Caddy virtual filesystem module for AWS S3 (and compatible) object store. */
export interface IGithubComSagikazarmarkCaddyFsS3Fs {
  /**
   * The name of the S3 bucket. */
  bucket?: string;
  /**
   * The AWS region the bucket is hosted in. */
  region?: string;
  /**
   * The AWS profile to use if mulitple profiles are specified. */
  profile?: string;
  /**
   * Use non-standard endpoint for S3. */
  endpoint?: string;
  /**
   * Set this to `true` to enable the client to use path-style addressing. */
  use_path_style?: boolean;
  /**
   * DEPRECATED: please use 'use_path_style' instead.
   * Set this to `true` to force the request to use path-style addressing. */
  force_path_style?: boolean;
  [key: string]: any;
}

export type IFs =
  | IGithubComMohammed90CaddyGitFsRepo
  | IGithubComSagikazarmarkCaddyFsS3Fs;

/**
 * The collection of `signer.Key` resources.
 * Relative paths are appended to the path of the current working directory.
 * The supported PEM types and algorithms are:
 * - RSA PRIVATE KEY: RSA
 * - PRIVATE KEY: RSA, ECDSA, ed25519
 * - EC PRIVATE KEY: ECDSA
 * - DSA PRIVATE KEY: DSA
 * - OPENSSH PRIVATE KEY: RSA, ed25519, ECDSA
 * Key is a generic holder of the location and passphrase of key (abstract) files */
export interface IGithubComKadeesshKadeesshInternalSignerKey {
  /**
   * Source is the identifying path of the key depending on the source. In the case of `file` signer,
   * `Source` refers to the path to the file on disk in relative or absolute path forms. Other signers
   * are free to define the semantics of the field. */
  source?: string;
  /**
   * A non-empty value means the key is protected with a passphrase */
  passphrase?: string;
  [key: string]: any;
}

/**
 * File is a session signer that uses pre-existing keys, which may be backed
 * as files */
export interface IGithubComKadeesshKadeesshInternalSignerFile {
  /**
   * The file system implementation to use. The default is the local disk file system.
   * File system modules used here must implement the fs.FS interface */
  file_system?: IFs;
  keys?: Array<IGithubComKadeesshKadeesshInternalSignerKey>;
  [key: string]: any;
}

export type ISigners =
  | IGithubComKadeesshKadeesshInternalSignerFallback
  | IGithubComKadeesshKadeesshInternalSignerFile;

/**
    * BcryptHash implements the bcrypt hash.
 
    */
export type IModulesCaddyhttpCaddyauthBcryptHash = Record<string, any>;

/**
 * ScryptHash implements the scrypt KDF as a hash.
 * DEPRECATED, please use 'bcrypt' instead. */
export interface IModulesCaddyhttpCaddyauthScryptHash {
  /**
   * scrypt's N parameter. If unset or 0, a safe default is used. */
  N?: number;
  /**
   * scrypt's r parameter. If unset or 0, a safe default is used. */
  r?: number;
  /**
   * scrypt's p parameter. If unset or 0, a safe default is used. */
  p?: number;
  /**
   * scrypt's key length parameter (in bytes). If unset or 0, a
   * safe default is used. */
  key_length?: number;
  [key: string]: any;
}

export type IHashes =
  | IModulesCaddyhttpCaddyauthBcryptHash
  | IModulesCaddyhttpCaddyauthScryptHash;

/**
 * The list of accounts to authenticate.
 * Account contains a username, password, and salt (if applicable). */
export interface IGithubComKadeesshKadeesshInternalAuthenticationStaticAccount {
  /**
   * The ID for the user to be identified with. If empty, UUID will be generated at provision-time. */
  id?: string;
  /**
   * A user's username. */
  name?: string;
  /**
   * The user's hashed password, base64-encoded. */
  password?: string;
  /**
   * The user's password salt, base64-encoded; for
   * algorithms where external salt is needed. */
  salt?: string;
  /**
   * The $HOME directory of the user. If empty, the app defaults to `C:\Users\Public` on Windows and `/var/empty` otherwise. */
  home?: string;
  custom?: Record<string, unknown>;
  [key: string]: any;
}

export interface IGithubComKadeesshKadeesshInternalAuthenticationStaticStatic {
  /**
   * The algorithm with which the passwords are hashed. Default: bcrypt */
  hash?: IHashes;
  accounts?: Array<IGithubComKadeesshKadeesshInternalAuthenticationStaticAccount>;
  [key: string]: any;
}

export interface IPassword {
  static?: IGithubComKadeesshKadeesshInternalAuthenticationStaticStatic;
  [key: string]: any;
}

/**
 * UsernamePassword holds the configuration of the password-based
 * authentication flow. nil value disables the authentication flow.
 * // PasswordAuthFlow holds the password-based authentication providers */
export interface IGithubComKadeesshKadeesshInternalAuthenticationPasswordAuthFlow {
  /**
   * A set of authentication providers implementing the UserPasswordAuthenticator interface. If none are specified,
   * all requests will always be unauthenticated.
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  providers: IPassword;
  permit_empty_passwords?: boolean;
  [key: string]: any;
}

/**
    * PublicKey is an authenticator that authenticates the user based on the `.ssh/authorized_keys` in
 the user's $HOME
 
    */
export type IGithubComKadeesshKadeesshInternalAuthenticationOsPublicKey =
  Record<string, any>;

/**
 * the user list along ith their keys sources */
export interface IGithubComKadeesshKadeesshInternalAuthenticationStaticUser {
  /**
   * the login username identifying the user */
  username?: string;
  keys?: Array<string>;
  [key: string]: any;
}

export interface IGithubComKadeesshKadeesshInternalAuthenticationStaticStaticPublicKeyProvider {
  users?: Array<IGithubComKadeesshKadeesshInternalAuthenticationStaticUser>;
  [key: string]: any;
}

export interface IPublicKey {
  os?: IGithubComKadeesshKadeesshInternalAuthenticationOsPublicKey;
  static?: IGithubComKadeesshKadeesshInternalAuthenticationStaticStaticPublicKeyProvider;
  [key: string]: any;
}

/**
 * PublicKey holds the configuration of the public-key-based
 * authentication flow. nil value disables the authentication flow.
 * PublicKeyFlow holds the public key authentication providers */
export interface IGithubComKadeesshKadeesshInternalAuthenticationPublicKeyFlow {
  /**
   * A set of authentication providers implementing the UserPublicKeyAuthenticator interface. If none are specified,
   * all requests will always be unauthenticated.
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  providers: IPublicKey;
  [key: string]: any;
}

/**
 * Interactive holds the configuration of the interactive-based
 * authentication flow. nil value disables the authentication flow.
 * InteractiveFlow holds the interactive authentication providers */
export interface IGithubComKadeesshKadeesshInternalAuthenticationInteractiveFlow {
  providers: Record<string, any>; // namespace not found: ssh.providers.interactive
  [key: string]: any;
}

/**
 * This holds the authentication suite for the various flows
 * Config holds the configuration of the various authentication flows, including
 * allow/deny users/groups. */
export interface IGithubComKadeesshKadeesshInternalAuthenticationConfig {
  allow_users?: Array<string>;
  deny_users?: Array<string>;
  allow_groups?: Array<string>;
  deny_groups?: Array<string>;
  username_password?: IGithubComKadeesshKadeesshInternalAuthenticationPasswordAuthFlow;
  public_key?: IGithubComKadeesshKadeesshInternalAuthenticationPublicKeyFlow;
  interactive?: IGithubComKadeesshKadeesshInternalAuthenticationInteractiveFlow;
  [key: string]: any;
}

/**
 * Lifted and merged from golang.org/x/crypto/ssh
 * ProvidedConfig holds server specific configuration data. */
export interface IGithubComKadeesshKadeesshInternalProvidedConfig {
  /**
   * The session signers to be loaded. The field takes the form:
   * "signer": {
   * 		"module": "<signer module name>"
   * 		... signer module config
   * }
   * If empty, the default module is "fallback", which will load existing keys, or generates and stores them if non-existent. */
  signer?: ISigners;
  key_exchanges?: Array<string>;
  ciphers?: Array<string>;
  ma_cs?: Array<string>;
  /**
   * NoClientAuth is true if clients are allowed to connect without
   * authenticating. */
  no_client_auth?: boolean;
  /**
   * MaxAuthTries specifies the maximum number of authentication attempts
   * permitted per connection. If set to a negative number, the number of
   * attempts are unlimited. If set to zero, the number of attempts are limited
   * to 6. */
  max_auth_tries?: number;
  authentication?: IGithubComKadeesshKadeesshInternalAuthenticationConfig;
  /**
   * ServerVersion is the version identification string to announce in
   * the public handshake.
   * If empty, a reasonable default is used.
   * Note that RFC 4253 section 4.2 requires that this string start with
   * "SSH-2.0-". */
  server_version?: string;
  [key: string]: any;
}

export type ILoaders = IGithubComKadeesshKadeesshInternalProvidedConfig;

/**
 * List of configurators that could configure the server per matchers and config providers
 * Configurator holds the set of matchers and configurators that will apply custom server
 * configurations if matched */
export interface IGithubComKadeesshKadeesshInternalConfigurator {
  /**
   * RawConfigMatcherSet is a group of matcher sets in their raw, JSON form. */
  match?: Array<unknown>;
  /**
   * The config provider that shall configure the server for the matched session.
   * "config": {
   * 		"loader": "<actor name>"
   * 		... config loader config
   * } */
  config?: ILoaders;
  [key: string]: any;
}

/**
 * StaticResponse is an actor that writes a static value to the client */
export interface IGithubComKadeesshKadeesshInternalActorsStaticResponse {
  response?: string;
  [key: string]: any;
}

/**
 * Shell is an `ssh.actors` module providing "shell" to a session. The module spawns a process
 * using the user's default shell, as defined in the OS. On *nix, except for macOS, the module parses `/etc/passwd`,
 * for the details and caches the result for future logins. On macOS, the module calls `dscl . -read` for the necessary
 * user details and caches them for future logins. On Windows, the module uses the
 * [`os/user` package](https://pkg.go.dev/os/user?GOOS=windows) from the Go standard library. */
export interface IGithubComKadeesshKadeesshInternalPtyShell {
  /**
   * Executes the designated command using the user's default shell, regardless of
   * the supplied command. It follows the OpenSSH semantics specified for
   * the [`ForceCommand`](https://man.openbsd.org/OpenBSD-current/man5/sshd_config.5#ForceCommand) except for
   * the part about `internal-sftp`. */
  force_command?: string;
  env?: Record<string, string>;
  /**
   * whether the server should check for explicit pty request */
  force_pty?: boolean;
  [key: string]: any;
}

export type IActors =
  | IGithubComKadeesshKadeesshInternalActorsStaticResponse
  | IGithubComKadeesshKadeesshInternalPtyShell;

/**
 * The actors that can act on a session per the matching criteria
 * Actor is a collection of actor matchers and actors of an ssh session */
export interface IGithubComKadeesshKadeesshInternalActor {
  /**
   * RawActorMatcherSet is a group of matcher sets in their raw, JSON form. */
  match?: Array<unknown>;
  /**
   * The actor that shall act on the matched session.
   * "act": {
   * 		"action": "<actor name>"
   * 		... actor config
   * } */
  act?: IActors;
  /**
   * Whether the session shoul be closed upon execution of the actor */
  final?: boolean;
  [key: string]: any;
}

/**
 * The set of ssh servers keyed by custom names */
export interface IGithubComKadeesshKadeesshInternalServer {
  /**
   * Socket addresses to which to bind listeners. Accepts
   * [network addresses](/docs/conventions#network-addresses)
   * that may include port ranges. Listener addresses must
   * be unique; they cannot be repeated across all defined
   * servers. TCP is the only acceptable network (for now, perhaps). */
  address?: string;
  /**
   * The configuration of local-forward permission module. The config structure is:
   * "localforward": {
   * 		"forward": "<module name>"
   * 		... config
   * }
   * defaults to: { "forward": "deny" } */
  localforward?: ILocalforward;
  /**
   * The configuration of reverse-forward permission module. The config structure is:
   * "reverseforward": {
   * 		"forward": "<module name>"
   * 		... config
   * }
   * defaults to: { "reverseforward": "deny" } */
  reverseforward?: IReverseforward;
  /**
   * The configuration of PTY permission module. The config structure is:
   * "pty": {
   * 		"pty": "<module name>"
   * 		... config
   * }
   * defaults to: { "forward": "deny" } */
  pty?: IPty;
  /**
   * connection timeout when no activity, none if empty
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  idle_timeout?: IDuration;
  /**
   * absolute connection timeout, none if empty
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  max_timeout?: IDuration;
  /**
   * The configuration of the authorizer module. The config structure is:
   * "authorize": {
   * 		"authorizer": "<module name>"
   * 		... config
   * }
   * default to: { "authorizer": "public" }. */
  authorize?: IAuthorizers;
  /**
   * The list of defined subsystems in a json structure keyed by the arbitrary name of the subsystem.
   * TODO: The current implementation is naive and can be expanded to follow the Authorzation and Actors model
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  subsystems: ISubsystem;
  /**
   * ConfigList is a list of server config providers that can
   * custom configure the server based on the session */
  configs?: Array<IGithubComKadeesshKadeesshInternalConfigurator>;
  /**
   * ActorList is a list of server actors that can
   * take an action on a session */
  actors?: Array<IGithubComKadeesshKadeesshInternalActor>;
  [key: string]: any;
}

/**
 * SSH is the app providing ssh services */
export interface IGithubComKadeesshKadeesshInternalSsh {
  /**
   * GracePeriod is the duration a server should wait for open connections to close during shutdown
   * before closing them forcefully
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  grace_period?: IDuration;
  servers?: Record<string, IGithubComKadeesshKadeesshInternalServer>;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComAnxuanziCaddyDnsClouDnsProvider {
  auth_id?: string;
  sub_auth_id?: string;
  auth_password?: string;
  [key: string]: any;
}

/**
 * Provider.Configs defines a map from domain string to
 * DomainConfig. It uses the same structure as ACME-DNS client
 * JSON storage file (https://github.com/acme-dns/acme-dns-client). */
export interface IGithubComLibdnsAcmednsDomainConfig {
  username?: string;
  password?: string;
  subdomain?: string;
  fulldomain?: string;
  server_url?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsAcmednsProvider {
  config?: Record<string, IGithubComLibdnsAcmednsDomainConfig>;
  /**
   * ACME-DNS account username as returned by ACME-DNS API /register endpoint. */
  username?: string;
  /**
   * ACME-DNS account password as returned by ACME-DNS API /register endpoint. */
  password?: string;
  /**
   * ACME-DNS account subdomain as returned by ACME-DNS API /register endpoint. */
  subdomain?: string;
  /**
   * ACME-DNS API base URL. For example, https://auth.acme-dns.io */
  server_url?: string;
  config_file_path?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsAcmeproxyProvider {
  username?: string;
  password?: string;
  /**
   * Endpoint is the URL of the ACMEProxy server. */
  endpoint?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsAlidnsProvider {
  /**
   * The API Key ID Required by Aliyun's for accessing the Aliyun's API */
  access_key_id?: string;
  /**
   * The API Key Secret Required by Aliyun's for accessing the Aliyun's API */
  access_key_secret?: string;
  /**
   * Optional for identifing the region of the Aliyun's Service,The default is zh-hangzhou */
  region_id?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsAzureProvider {
  /**
   * Subscription ID is the ID of the subscription in which the DNS zone is located. Required. */
  subscription_id?: string;
  /**
   * Resource Group Name is the name of the resource group in which the DNS zone is located. Required. */
  resource_group_name?: string;
  /**
   * (Optional)
   * Tenant ID is the ID of the tenant of the Microsoft Entra ID in which the application is located.
   * Required only when authenticating using a service principal with a secret.
   * Do not set any value to authenticate using a managed identity. */
  tenant_id?: string;
  /**
   * (Optional)
   * Client ID is the ID of the application.
   * Required only when authenticating using a service principal with a secret.
   * Do not set any value to authenticate using a managed identity. */
  client_id?: string;
  /**
   * (Optional)
   * Client Secret is the client secret of the application.
   * Required only when authenticating using a service principal with a secret.
   * Do not set any value to authenticate using a managed identity. */
  client_secret?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsCloudflareProvider {
  /**
   * API token is used for authentication. Make sure to use a
   * scoped API **token**, NOT a global API **key**. It will
   * need two permissions: Zone-Zone-Read and Zone-DNS-Edit,
   * unless you are only using `GetRecords()`, in which case
   * the second can be changed to Read. */
  api_token?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsDdnssProvider {
  api_token?: string;
  username?: string;
  password?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsDesecProvider {
  /**
   * Token is a token created on https://desec.io/tokens. A basic token without the permission
   * to manage tokens is sufficient. */
  token?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsDigitaloceanProvider {
  /**
   * auth_token is the DigitalOcean API token - see https://www.digitalocean.com/docs/apis-clis/api/create-personal-access-token/ */
  auth_token?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsDinahostingProvider {
  username?: string;
  password?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsDnspodProvider {
  /**
   * auth_token is the DNSPOD API token - see https://www.dnspod.cn/docs/info.html#common-parameters */
  auth_token?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsDuckdnsProvider {
  api_token?: string;
  override_domain?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsGandiProvider {
  bearer_token?: string;
  [key: string]: any;
}

/**
    * Provider wraps the provider implementation as a Caddy module.
 
    */
export type IGithubComCaddyDnsGodaddyProvider = Record<string, any>;

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsGoogleDomainsProvider {
  access_token?: string;
  keep_expired_records?: boolean;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsGoogleclouddnsProvider {
  gcp_project?: string;
  gcp_application_default?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsHetznerProvider {
  /**
   * auth_api_token is the Hetzner Auth API token - see https://dns.hetzner.com/api-docs#section/Authentication/Auth-API-Token */
  auth_api_token?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsHexonetProvider {
  username?: string;
  password?: string;
  /**
   * Debug - can set this to stdout or stderr to dump
   * debugging information about the API interaction with
   * hexonet.  This will dump your auth token in plain text
   * so be careful. */
  debug?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsInfomaniakProvider {
  /**
   * infomaniak API token */
  api_token?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by INWX. */
export interface IGithubComCaddyDnsInwxProvider {
  /**
   * Username of your INWX account. */
  username?: string;
  /**
   * Password of your INWX account. */
  password?: string;
  /**
   * The shared secret is used to generate a TAN if you have activated "Mobile TAN" for your INWX account. */
  shared_secret?: string;
  /**
   * URL of the JSON-RPC API endpoint. It defaults to the production endpoint. */
  endpoint_url?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsIonosProvider {
  /**
   * AuthAPIToken is the IONOS Auth API token -
   * see https://dns.ionos.com/api-docs#section/Authentication/Auth-API-Token */
  auth_api_token?: string;
  [key: string]: any;
}

export type ILeaseweb = Record<string, any>;

/**
 * LegoDeprecated is a shim module that allows any and all of the
 * DNS providers in go-acme/lego to be used with Caddy. They must
 * be configured via environment variables, they do not support
 * cancellation in the case of frequent config changes.
 * Even though this module is in the dns.providers namespace, it
 * is only a special case for solving ACME challenges, intended to
 * replace the modules that used to be in the now-defunct tls.dns
 * namespace. Using it in other places of the Caddy config will
 * result in errors.
 * This module will eventually go away in favor of the modules that
 * make use of the libdns APIs: https://github.com/libdns */
export interface IGithubComCaddyDnsLegoDeprecatedLegoDeprecated {
  provider_name?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsLinodeProvider {
  /**
   * APIToken is the Linode Personal Access Token, see https://cloud.linode.com/profile/tokens. */
  api_token?: string;
  /**
   * APIURL is the Linode API hostname, i.e. "api.linode.com". */
  api_url?: string;
  /**
   * APIVersion is the Linode API version, i.e. "v4". */
  api_version?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsMailinaboxProvider {
  /**
   * APIURL is the URL provided by the mailinabox admin interface, found
   * on your box here: https://box.[your-domain.com]/admin#custom_dns
   * https://box.[your-domain.com]/admin/dns/custom */
  api_url?: string;
  /**
   * EmailAddress of an admin account.
   * It's recommended that a dedicated account
   * be created especially for managing DNS. */
  email_address?: string;
  /**
   * Password of the admin account that corresponds to the email. */
  password?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsMetanameProvider {
  api_key?: string;
  account_reference?: string;
  endpoint?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsNamecheapProvider {
  /**
   * APIKey is your namecheap API key.
   * See: https://www.namecheap.com/support/api/intro/
   * for more details. */
  api_key?: string;
  /**
   * User is your namecheap API user. This can be the same as your username. */
  user?: string;
  /**
   * APIEndpoint to use. If testing, you can use the "sandbox" endpoint
   * instead of the production one. */
  api_endpoint?: string;
  /**
   * ClientIP is the IP address of the requesting client.
   * If this is not set, a discovery service will be
   * used to determine the public ip of the machine.
   * You must first whitelist your IP in the namecheap console
   * before using the API. */
  client_ip?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsNamedotcomProvider {
  api_token?: string;
  user?: string;
  server?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsNamesiloProvider {
  api_token?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsNetcupProvider {
  customer_number?: string;
  api_key?: string;
  api_password?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsNetlifyProvider {
  /**
   * Personal Access Token is required to Authenticate
   * yourself to Netlify's API */
  personal_access_token?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsNjallaProvider {
  api_token?: string;
  [key: string]: any;
}

/**
 * AuthOpenStack contains credentials for OpenStack Designate. */
export interface IGithubComLibdnsOpenstackDesignateAuthOpenStack {
  region_name?: string;
  tenant_id?: string;
  identity_api_version?: string;
  password?: string;
  auth_url?: string;
  username?: string;
  tenant_name?: string;
  endpoint_type?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsOpenstackDesignateProvider {
  auth_open_stack?: IGithubComLibdnsOpenstackDesignateAuthOpenStack;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsOvhProvider {
  endpoint?: string;
  application_key?: string;
  application_secret?: string;
  consumer_key?: string;
  [key: string]: any;
}

/**
 * Provider lets Caddy read and manipulate DNS records hosted by this DNS provider. */
export interface IGithubComCaddyDnsPorkbunProvider {
  api_key?: string;
  api_secret_key?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsPowerdnsProvider {
  /**
   * ServerURL is the location of the pdns server. */
  server_url?: string;
  /**
   * ServerID is the id of the server.  localhost will be used
   * if this is omitted. */
  server_id?: string;
  /**
   * APIToken is the auth token. */
  api_token?: string;
  /**
   * Debug - can set this to stdout or stderr to dump
   * debugging information about the API interaction with
   * powerdns.  This will dump your auth token in plain text
   * so be careful. */
  debug?: string;
  [key: string]: any;
}

export interface IGithubComCaddyDnsRfc2136Provider {
  key_name?: string;
  key_alg?: string;
  key?: string;
  server?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsRoute53Provider {
  max_retries?: number;
  [key: string]: any;
}

/**
    * Provider wraps the provider implementation as a Caddy module.
 
    */
export type IGithubComCaddyDnsTencentcloudProvider = Record<string, any>;

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsVercelProvider {
  /**
   * AuthAPIToken is the Vercel Authentication Token - see https://vercel.com/docs/api#api-basics/authentication */
  auth_api_token?: string;
  [key: string]: any;
}

/**
 * Provider wraps the provider implementation as a Caddy module. */
export interface IGithubComCaddyDnsVultrProvider {
  /**
   * auth_token is the Vultr API token
   * see https://my.vultr.com/settings/#settingsapi */
  auth_token?: string;
  [key: string]: any;
}

export type IProviders =
  | IGithubComAnxuanziCaddyDnsClouDnsProvider
  | IGithubComCaddyDnsAcmednsProvider
  | IGithubComCaddyDnsAcmeproxyProvider
  | IGithubComCaddyDnsAlidnsProvider
  | IGithubComCaddyDnsAzureProvider
  | IGithubComCaddyDnsCloudflareProvider
  | IGithubComCaddyDnsDdnssProvider
  | IGithubComCaddyDnsDesecProvider
  | IGithubComCaddyDnsDigitaloceanProvider
  | IGithubComCaddyDnsDinahostingProvider
  | IGithubComCaddyDnsDnspodProvider
  | IGithubComCaddyDnsDuckdnsProvider
  | IGithubComCaddyDnsGandiProvider
  | IGithubComCaddyDnsGodaddyProvider
  | IGithubComCaddyDnsGoogleDomainsProvider
  | IGithubComCaddyDnsGoogleclouddnsProvider
  | IGithubComCaddyDnsHetznerProvider
  | IGithubComCaddyDnsHexonetProvider
  | IGithubComCaddyDnsInfomaniakProvider
  | IGithubComCaddyDnsInwxProvider
  | IGithubComCaddyDnsIonosProvider
  | ILeaseweb
  | IGithubComCaddyDnsLegoDeprecatedLegoDeprecated
  | IGithubComCaddyDnsLinodeProvider
  | IGithubComCaddyDnsMailinaboxProvider
  | IGithubComCaddyDnsMetanameProvider
  | IGithubComCaddyDnsNamecheapProvider
  | IGithubComCaddyDnsNamedotcomProvider
  | IGithubComCaddyDnsNamesiloProvider
  | IGithubComCaddyDnsNetcupProvider
  | IGithubComCaddyDnsNetlifyProvider
  | IGithubComCaddyDnsNjallaProvider
  | IGithubComCaddyDnsOpenstackDesignateProvider
  | IGithubComCaddyDnsOvhProvider
  | IGithubComCaddyDnsPorkbunProvider
  | IGithubComCaddyDnsPowerdnsProvider
  | IGithubComCaddyDnsRfc2136Provider
  | IGithubComCaddyDnsRoute53Provider
  | IGithubComCaddyDnsTencentcloudProvider
  | IGithubComCaddyDnsVercelProvider
  | IGithubComCaddyDnsVultrProvider;

/**
 * The IP versions to enable. By default, both "ipv4" and "ipv6" will be enabled.
 * To disable IPv6, specify {"ipv6": false}.
 * IPVersions is the IP versions to enable for dynamic DNS.
 * Versions are enabled if true or nil, set to false to disable. */
export interface IGithubComMholtCaddyDynamicdnsIpVersions {
  ipv4?: boolean;
  ipv6?: boolean;
  [key: string]: any;
}

/**
 * App is a Caddy app that keeps your DNS records updated with the public
 * IP address of your instance. It updates A and AAAA records. */
export interface IGithubComMholtCaddyDynamicdnsApp {
  ip_sources?: Array<unknown>;
  /**
   * The configuration for the DNS provider with which the DNS
   * records will be updated. */
  dns_provider?: IProviders;
  domains?: Record<string, Array<string>>;
  /**
   * If enabled, the "http" app's config will be scanned to assemble the list
   * of domains for which to enable dynamic DNS updates. */
  dynamic_domains?: boolean;
  versions?: IGithubComMholtCaddyDynamicdnsIpVersions;
  /**
   * How frequently to check the public IP address. Default: 30m
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  check_interval?: IDuration;
  /**
   * The TTL to set on DNS records.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  ttl?: IDuration;
  [key: string]: any;
}

/**
 * Route represents a collection of handlers that are gated
 * by matching and other kinds of logic. */
export interface IGithubComMholtCaddyL4Layer4Route {
  match?: Array<unknown>;
  handle?: Array<unknown>;
  [key: string]: any;
}

/**
 * Server represents a Caddy layer4 server. */
export interface IGithubComMholtCaddyL4Layer4Server {
  listen?: Array<string>;
  /**
   * RouteList is a list of connection routes that can create
   * a middleware chain. */
  routes?: Array<IGithubComMholtCaddyL4Layer4Route>;
  [key: string]: any;
}

/**
 * App is a Caddy app that operates closest to layer 4 of the OSI model. */
export interface IGithubComMholtCaddyL4Layer4App {
  servers?: Record<string, IGithubComMholtCaddyL4Layer4Server>;
  [key: string]: any;
}

/**
 * The profiling parameters to be reported to Profefe.
 * The paramters cpu_profile_rate, block_profile_rate, and mutex_profile_fraction are inherited from the `profiling` app if `profefe`
 * is configured as a child module. The `profile_types` field is inherited if not configured explicitly.
 * If `profefe` is configured as an app, all the parameters are instated as-is.
 * Common profiling paramters */
export interface IGithubComMohammed90CaddyProfilingParameters {
  /**
   * The hertz rate for CPU profiling, as accepted by the [`SetCPUProfileRate`](https://pkg.go.dev/runtime#SetCPUProfileRate) function. */
  cpu_profile_rate?: number;
  /**
   * The hertz rate for CPU profiling, as accepted by the [`SetBlockProfileRate`](https://pkg.go.dev/runtime#SetBlockProfileRate) function. */
  block_profile_rate?: number;
  /**
   * The the fraction of mutex contention events, as accepted by the [`SetMutexProfileFraction`](https://pkg.go.dev/runtime#SetMutexProfileFraction) function. */
  mutex_profile_fraction?: number;
  profile_types?: Array<string>;
  [key: string]: any;
}

/**
 * The `profefe` app collects profiling data during the life-time of the process
 * and uploads them to the profefe server. */
export interface IGithubComMohammed90CaddyProfilingProfefeApp {
  /**
   * The URL of the Profefe service. The config value may be a [placeholder](https://caddyserver.com/docs/conventions#placeholders). */
  address?: string;
  /**
   * The service name reported to Profefe. The config value may be a [placeholder](https://caddyserver.com/docs/conventions#placeholders). */
  service?: string;
  /**
   * The timeout for the upload call. Setting the value to `0` disables the timeout and the call waits indefinitely until the upload is finished.
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  timeout?: IDuration;
  parameters?: IGithubComMohammed90CaddyProfilingParameters;
  [key: string]: any;
}

/**
 * The `profiling` app hosts the collection of push-based profiling agents with common profiling parameters acorss the Caddy instance. */
export interface IGithubComMohammed90CaddyProfilingProfilingApp {
  /**
   * The hertz rate for CPU profiling, as accepted by the [`SetCPUProfileRate`](https://pkg.go.dev/runtime#SetCPUProfileRate) function. */
  cpu_profile_rate?: number;
  /**
   * The hertz rate for CPU profiling, as accepted by the [`SetBlockProfileRate`](https://pkg.go.dev/runtime#SetBlockProfileRate) function. */
  block_profile_rate?: number;
  /**
   * The the fraction of mutex contention events, as accepted by the [`SetMutexProfileFraction`](https://pkg.go.dev/runtime#SetMutexProfileFraction) function. */
  mutex_profile_fraction?: number;
  profile_types?: Array<string>;
  profilers?: Array<unknown>;
  [key: string]: any;
}

/**
 * The `pyroscope` app collects profiling data during the life-time of the process
 * and uploads them to the Pyroscope server. */
export interface IGithubComMohammed90CaddyProfilingPyroscopeApp {
  /**
   * The application name reported to Pyroscope. The config value may be a [placeholder](https://caddyserver.com/docs/conventions#placeholders). */
  application_name?: string;
  /**
   * The URL of the Pyroscope service. The config value may be a [placeholder](https://caddyserver.com/docs/conventions#placeholders). */
  server_address?: string;
  /**
   * The token for Pyroscope Cloud. The config value may be a [placeholder](https://caddyserver.com/docs/conventions#placeholders). */
  auth_token?: string;
  /**
   * The Basic Auth username of the Phlare server */
  basic_auth_user?: string;
  /**
   * The Basic Auth  of the Phlare server */
  basic_auth_password?: string;
  /**
   * The tenant ID to support the case of multi-tenant Phlare server */
  tenant_id?: string;
  /**
   * Disable automatic runtime.GC runs between getting the heap profiles */
  disable_gc_runs?: boolean;
  /**
   * The frequency of upload to the Phlare server
   * Duration can be an integer or a string. An integer is
   * interpreted as nanoseconds. If a string, it is a Go
   * time.Duration value such as `300ms`, `1.5h`, or `2h45m`;
   * valid units are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h`, and `d`. */
  upload_rate?: IDuration;
  parameters: IGithubComMohammed90CaddyProfilingParameters;
  [key: string]: any;
}

/**
    * SCION implements a caddy module. Currently, it is used to initialize the
 logger for the global network. In the future, additional configuration can be
 parsed with this component.
 
    */
export type IGithubComScionprotoContribCaddyScionScion = Record<string, any>;

/**
 * geoip2 is global caddy app with http.handlers.geoip2
 * it update geoip2 data automatically by the params */
export interface IGithubComZhangjiayinCaddyGeoip2GeoIp2State {
  /**
   * Your MaxMind account ID. This was formerly known as UserId. */
  accountId?: number;
  /**
   * The directory to store the database files. Defaults to DATADIR */
  databaseDirectory?: string;
  /**
   * Your case-sensitive MaxMind license key. */
  licenseKey?: string;
  /**
   * The lock file to use. This ensures only one geoipupdate process can run at a
   * time.
   * Note: Once created, this lockfile is not removed from the filesystem. */
  lockFile?: string;
  /**
   * Enter the edition IDs of the databases you would like to update.
   * Should be  GeoLite2-City */
  editionID?: string;
  /**
   * update url to use. Defaults to https://updates.maxmind.com */
  updateUrl?: string;
  /**
   * The Frequency in seconds to run update. Default to 0, only update On Start */
  updateFrequency?: number;
  [key: string]: any;
}

export interface IApps {
  exec?: IGithubComAbiosoftCaddyExecApp;
  reconnect?: IGithubComAnapayaCaddyReconnectReconnect;
  supervisor?: IGithubComBaldinofCaddySupervisorApp;
  events?: IModulesCaddyeventsApp;
  http?: IModulesCaddyhttpApp;
  pki?: IModulesCaddypkiPki;
  tls?: IModulesCaddytlsTls;
  frankenphp?: IGithubComDunglasFrankenphpCaddyFrankenPhpApp;
  security?: IGithubComGreenpauCaddySecurityApp;
  crowdsec?: IGithubComHslatmanCaddyCrowdsecBouncerCrowdsecCrowdSec;
  ssh?: IGithubComKadeesshKadeesshInternalSsh;
  dynamic_dns?: IGithubComMholtCaddyDynamicdnsApp;
  layer4?: IGithubComMholtCaddyL4Layer4App;
  profefe?: IGithubComMohammed90CaddyProfilingProfefeApp;
  profiling?: IGithubComMohammed90CaddyProfilingProfilingApp;
  pyroscope?: IGithubComMohammed90CaddyProfilingPyroscopeApp;
  scion?: IGithubComScionprotoContribCaddyScionScion;
  geoip2?: IGithubComZhangjiayinCaddyGeoip2GeoIp2State;
  [key: string]: any;
}

/**
 * Config is the top (or beginning) of the Caddy configuration structure.
 * Caddy config is expressed natively as a JSON document. If you prefer
 * not to work with JSON directly, there are [many config adapters](/docs/config-adapters)
 * available that can convert various inputs into Caddy JSON.
 * Many parts of this config are extensible through the use of Caddy modules.
 * Fields which have a json.RawMessage type and which appear as dots (•••) in
 * the online docs can be fulfilled by modules in a certain module
 * namespace. The docs show which modules can be used in a given place.
 * Whenever a module is used, its name must be given either inline as part of
 * the module, or as the key to the module's value. The docs will make it clear
 * which to use.
 * Generally, all config settings are optional, as it is Caddy convention to
 * have good, documented default values. If a parameter is required, the docs
 * should say so.
 * Go programs which are directly building a Config struct value should take
 * care to populate the JSON-encodable fields of the struct (i.e. the fields
 * with `json` struct tags) if employing the module lifecycle (e.g. Provision
 * method calls). */
export interface IConfig {
  admin?: IAdminConfig;
  logging?: ILogging;
  storage: IStorage;
  /**
   * AppsRaw are the apps that Caddy will load and run. The
   * app module name is the key, and the app's config is the
   * associated value.
   * ModuleMap is a map that can contain multiple modules,
   * where the map key is the module's name. (The namespace
   * is usually read from an associated field's struct tag.)
   * Because the module's name is given as the key in a
   * module map, the name does not have to be given in the
   * json.RawMessage. */
  apps: IApps;
  [key: string]: any;
}
