import * as cfw from "cloudflare:workers";
import { DurableObject, RpcTarget, tracing } from "cloudflare:workers";
import path from "node:path/posix";
// node_modules/@cloudflare/sandbox/dist/dist-CqPJfREN.js
/**
* Safely extract a string value from an environment object
*
* @param env - Environment object with dynamic keys
* @param key - The environment variable key to access
* @returns The string value if present and is a string, undefined otherwise
*/
function getEnvString(env, key) {
	const value = env?.[key];
	return typeof value === "string" ? value : void 0;
}
/**
* Filter environment variables object to only include string values.
* Skips undefined, null, and non-string values.
*
* Use this when you only need the defined values (e.g., for per-command env
* where undefined means "don't override").
*
* @param envVars - Object that may contain undefined values
* @returns Clean object with only string values
*/
function filterEnvVars(envVars) {
	const filtered = {};
	for (const [key, value] of Object.entries(envVars)) if (value != null && typeof value === "string") filtered[key] = value;
	return filtered;
}
/**
* Partition environment variables into values to set and keys to unset.
*
* - String values → toSet (will be exported)
* - undefined/null → toUnset (will be unset)
*
* This enables idiomatic JS patterns where undefined means "remove":
* ```typescript
* await sandbox.setEnvVars({
*   API_KEY: 'new-key',        // will be set
*   OLD_VAR: undefined,        // will be unset
* });
* ```
*/
function partitionEnvVars(envVars) {
	const toSet = {};
	const toUnset = [];
	for (const [key, value] of Object.entries(envVars)) if (value != null && typeof value === "string") toSet[key] = value;
	else toUnset.push(key);
	return {
		toSet,
		toUnset
	};
}
/**
* Log-only sanitization helpers
*
* These functions redact sensitive values for logging output.
* They MUST NOT be used to mutate command strings before execution.
*/
/**
* Sensitive query parameter names to redact from URLs.
* Anchored to query string context ([?&]) to avoid matching path segments.
* Value matching stops at & and common URL/command delimiters.
*/
var SENSITIVE_PARAMS = /([?&])(X-Amz-Credential|X-Amz-Signature|X-Amz-Security-Token|token|secret|password)=[^&\s"'`<>]*/gi;
/**
* Redact credentials from URLs for secure logging
*
* Replaces any credentials (username:password, tokens, etc.) embedded
* in URLs with ****** to prevent sensitive data exposure in logs.
* Works with URLs embedded in text.
*
* @param text - String that may contain URLs with credentials
* @returns String with credentials redacted from any URLs
*/
function redactCredentials(text) {
	let result = text;
	let pos = 0;
	while (pos < result.length) {
		const httpPos = result.indexOf("http://", pos);
		const httpsPos = result.indexOf("https://", pos);
		let protocolPos = -1;
		let protocolLen = 0;
		if (httpPos === -1 && httpsPos === -1) break;
		if (httpPos !== -1 && (httpsPos === -1 || httpPos < httpsPos)) {
			protocolPos = httpPos;
			protocolLen = 7;
		} else {
			protocolPos = httpsPos;
			protocolLen = 8;
		}
		const searchStart = protocolPos + protocolLen;
		const atPos = result.indexOf("@", searchStart);
		let urlEnd = searchStart;
		while (urlEnd < result.length) {
			const char = result[urlEnd];
			if (/[\s"'`<>,;{}[\]]/.test(char)) break;
			urlEnd++;
		}
		if (atPos !== -1 && atPos < urlEnd) {
			result = `${result.substring(0, searchStart)}******${result.substring(atPos)}`;
			pos = searchStart + 6;
		} else pos = protocolPos + protocolLen;
	}
	return result;
}
/**
* Redact sensitive query parameters from URLs
*
* Strips X-Amz-Credential, X-Amz-Signature, X-Amz-Security-Token,
* token, secret, and password query params from URLs. Returns
* non-URL strings unchanged.
*
* @param input - String that may contain URLs with sensitive params
* @returns String with sensitive params replaced by REDACTED
*/
function redactSensitiveParams(input) {
	if (!input.includes("?") || !input.includes("=")) return input;
	return input.replace(SENSITIVE_PARAMS, "$1$2=REDACTED");
}
/**
* Redact sensitive data from a command string for logging
*
* Composes redactCredentials (URL credentials) and redactSensitiveParams
* (presigned URL query params). For log values only — never mutate
* command strings before execution.
*
* @param command - Command string to sanitize for logging
* @returns Sanitized command string
*/
function redactCommand(command) {
	return redactSensitiveParams(redactCredentials(command));
}
/**
* Fallback repository name used when URL parsing fails
*/
var FALLBACK_REPO_NAME = "repository";
/**
* Extract repository name from a Git URL
*
* Supports multiple URL formats:
* - HTTPS: https://github.com/user/repo.git → repo
* - HTTPS without .git: https://github.com/user/repo → repo
* - SSH: git@github.com:user/repo.git → repo
* - GitLab/others: https://gitlab.com/org/project.git → project
*
* @param repoUrl - Git repository URL (HTTPS or SSH format)
* @returns Repository name extracted from URL, or 'repository' as fallback
*/
function extractRepoName(repoUrl) {
	try {
		const pathParts = new URL(repoUrl).pathname.split("/");
		const lastPart = pathParts[pathParts.length - 1];
		if (lastPart) return lastPart.replace(/\.git$/, "");
	} catch {}
	if (repoUrl.includes(":") || repoUrl.includes("/")) {
		const segments = repoUrl.split(/[:/]/).filter(Boolean);
		const lastSegment = segments[segments.length - 1];
		if (lastSegment) return lastSegment.replace(/\.git$/, "");
	}
	return FALLBACK_REPO_NAME;
}
/**
* Sanitize data by redacting credentials from any strings
* Recursively processes objects and arrays to ensure credentials are never leaked
*/
function sanitizeGitData(data) {
	if (typeof data === "string") return redactCommand(data);
	if (data === null || data === void 0) return data;
	if (Array.isArray(data)) return data.map((item) => sanitizeGitData(item));
	if (typeof data === "object") {
		const result = {};
		for (const [key, value] of Object.entries(data)) result[key] = sanitizeGitData(value);
		return result;
	}
	return data;
}
/**
* Logger wrapper that automatically sanitizes git credentials
*/
var GitLogger = class GitLogger {
	baseLogger;
	constructor(baseLogger) {
		this.baseLogger = baseLogger;
	}
	sanitizeContext(context) {
		return context ? sanitizeGitData(context) : context;
	}
	sanitizeError(error) {
		if (!error) return error;
		const sanitized = new Error(redactCommand(error.message));
		sanitized.name = error.name;
		if (error.stack) sanitized.stack = redactCommand(error.stack);
		const sanitizedRecord = sanitized;
		const errorRecord = error;
		for (const key of Object.keys(error)) if (key !== "message" && key !== "stack" && key !== "name") sanitizedRecord[key] = sanitizeGitData(errorRecord[key]);
		return sanitized;
	}
	debug(message, context) {
		this.baseLogger.debug(message, this.sanitizeContext(context));
	}
	info(message, context) {
		this.baseLogger.info(message, this.sanitizeContext(context));
	}
	warn(message, context) {
		this.baseLogger.warn(message, this.sanitizeContext(context));
	}
	error(message, error, context) {
		this.baseLogger.error(message, this.sanitizeError(error), this.sanitizeContext(context));
	}
	child(context) {
		const sanitized = sanitizeGitData(context);
		return new GitLogger(this.baseLogger.child(sanitized));
	}
};
var Execution = class {
	code;
	context;
	/**
	* All results from the execution
	*/
	results = [];
	/**
	* Accumulated stdout and stderr
	*/
	logs = {
		stdout: [],
		stderr: []
	};
	/**
	* Execution error if any
	*/
	error;
	/**
	* Execution count (for interpreter)
	*/
	executionCount;
	constructor(code, context) {
		this.code = code;
		this.context = context;
	}
	/**
	* Convert to a plain object for serialization
	*/
	toJSON() {
		return {
			code: this.code,
			logs: this.logs,
			error: this.error,
			executionCount: this.executionCount,
			results: this.results.map((result) => ({
				text: result.text,
				html: result.html,
				png: result.png,
				jpeg: result.jpeg,
				svg: result.svg,
				latex: result.latex,
				markdown: result.markdown,
				javascript: result.javascript,
				json: result.json,
				chart: result.chart,
				data: result.data
			}))
		};
	}
};
var ResultImpl = class {
	text;
	html;
	png;
	jpeg;
	svg;
	latex;
	markdown;
	javascript;
	json;
	chart;
	data;
	constructor(raw) {
		this.text = raw.text || raw.data?.["text/plain"];
		this.html = raw.html || raw.data?.["text/html"];
		this.png = raw.png || raw.data?.["image/png"];
		this.jpeg = raw.jpeg || raw.data?.["image/jpeg"];
		this.svg = raw.svg || raw.data?.["image/svg+xml"];
		this.latex = raw.latex || raw.data?.["text/latex"];
		this.markdown = raw.markdown || raw.data?.["text/markdown"];
		this.javascript = raw.javascript || raw.data?.["application/javascript"];
		this.json = raw.json || raw.data?.["application/json"];
		this.chart = raw.chart;
		this.data = raw.data;
	}
	formats() {
		const fmts = [];
		if (this.text) fmts.push("text");
		if (this.html) fmts.push("html");
		if (this.png) fmts.push("png");
		if (this.jpeg) fmts.push("jpeg");
		if (this.svg) fmts.push("svg");
		if (this.latex) fmts.push("latex");
		if (this.markdown) fmts.push("markdown");
		if (this.javascript) fmts.push("javascript");
		if (this.json) fmts.push("json");
		if (this.chart) fmts.push("chart");
		return fmts;
	}
};
/** Events that are low-value at info on success */
var DEBUG_ON_SUCCESS = /* @__PURE__ */ new Set([
	"session.create",
	"session.destroy",
	"file.read",
	"file.write",
	"file.delete",
	"file.mkdir"
]);
function resolveLogLevel(payload, options) {
	if (payload.outcome === "error") return "error";
	if (options?.successLevel) return options.successLevel;
	if (payload.origin === "internal") return "debug";
	if (DEBUG_ON_SUCCESS.has(payload.event)) return "debug";
	return "info";
}
/**
* Sanitize an Error object by redacting sensitive data from message and stack.
* Produces a copy so the caller's original Error is not mutated.
*/
function sanitizeError(error) {
	if (!error) return void 0;
	const sanitized = new Error(redactCommand(error.message));
	sanitized.name = error.name;
	sanitized.stack = error.stack ? redactCommand(error.stack) : void 0;
	return sanitized;
}
/**
* Build a human-readable canonical event message for dashboards and log viewers.
*
* Format: `{event} {outcome} {key_context} [— {reason}] ({durationMs}ms[, {sizeBytes}B])`
*
* The if/else chain for key context has implicit priority: path > sessionId >
* port > repoUrl > pid. If a payload has multiple, only the highest-priority
* one appears in the message. All fields are still present as discrete
* queryable keys in the structured log context.
*/
function buildMessage(payload) {
	const { event } = payload;
	if (event === "version.check") {
		const parts$1 = ["version.check"];
		if (payload.sdkVersion) parts$1.push(`sdk=${payload.sdkVersion}`);
		if (payload.containerVersion) parts$1.push(`container=${payload.containerVersion}`);
		if (payload.versionOutcome && payload.versionOutcome !== "compatible") parts$1.push(`(${payload.versionOutcome})`);
		return parts$1.join(" ");
	}
	const parts = [event, payload.outcome];
	if (payload.path !== void 0) parts.push(payload.path);
	else if (event.includes("session") && payload.sessionId !== void 0) parts.push(payload.sessionId);
	else if (payload.port !== void 0) parts.push(String(payload.port));
	else if (payload.repoUrl !== void 0) {
		let gitContext = payload.repoUrl;
		if (payload.branch !== void 0) gitContext += ` ${payload.branch}`;
		parts.push(gitContext);
	} else if (payload.pid !== void 0) parts.push(String(payload.pid));
	else if (payload.backupId !== void 0) parts.push(payload.backupId);
	else if (payload.repoPath !== void 0) {
		let gitContext = payload.repoPath;
		if (payload.branch !== void 0) gitContext += ` branch=${payload.branch}`;
		parts.push(gitContext);
	} else if (payload.mountsProcessed !== void 0) {
		let destroyContext = `${payload.mountsProcessed} mounts`;
		if (payload.mountFailures) destroyContext += `, ${payload.mountFailures} failed`;
		parts.push(destroyContext);
	} else if (payload.mountPath !== void 0) parts.push(payload.mountPath);
	if (payload.outcome === "error") {
		if (payload.errorMessage !== void 0) parts.push(`\u2014 ${payload.errorMessage}`);
		else if (payload.exitCode !== void 0) parts.push(`\u2014 exitCode=${payload.exitCode}`);
	}
	const durationSuffix = payload.sizeBytes !== void 0 ? `(${payload.durationMs}ms, ${payload.sizeBytes}B)` : `(${payload.durationMs}ms)`;
	parts.push(durationSuffix);
	return parts.join(" ");
}
/**
* Log a canonical event — the single entry point for all structured operational events.
*
* Redacts error text, builds the message, selects log level from outcome, and
* emits a structured log entry with the full payload as context.
*/
function logCanonicalEvent(logger, payload, options) {
	const resolvedErrorMessage = payload.errorMessage ?? payload.error?.message;
	const sanitizedErrorMessage = resolvedErrorMessage ? redactCommand(resolvedErrorMessage) : void 0;
	const enrichedPayload = sanitizedErrorMessage !== void 0 ? {
		...payload,
		errorMessage: sanitizedErrorMessage
	} : payload;
	const message = buildMessage(enrichedPayload);
	const context = {};
	for (const [key, value] of Object.entries(enrichedPayload)) {
		if (key === "error") continue;
		context[key] = value;
	}
	const level = resolveLogLevel(enrichedPayload, options);
	if (level === "error") logger.error(message, sanitizeError(payload.error), context);
	else if (level === "warn") logger.warn(message, context);
	else if (level === "debug") logger.debug(message, context);
	else logger.info(message, context);
}
/**
* Logger types for Cloudflare Sandbox SDK
*
* Provides structured, trace-aware logging across Worker, Durable Object, and Container.
*/
/**
* Log levels (from most to least verbose)
*/
var LogLevel;
(function(LogLevel$1) {
	LogLevel$1[LogLevel$1["DEBUG"] = 0] = "DEBUG";
	LogLevel$1[LogLevel$1["INFO"] = 1] = "INFO";
	LogLevel$1[LogLevel$1["WARN"] = 2] = "WARN";
	LogLevel$1[LogLevel$1["ERROR"] = 3] = "ERROR";
})(LogLevel || (LogLevel = {}));
/**
* Logger implementation
*/
/**
* ANSI color codes for terminal output
*/
var COLORS = {
	reset: "\x1B[0m",
	debug: "\x1B[36m",
	info: "\x1B[32m",
	warn: "\x1B[33m",
	error: "\x1B[31m",
	dim: "\x1B[2m"
};
/**
* CloudflareLogger implements structured logging with support for
* both JSON output (production) and pretty printing (development).
*/
var CloudflareLogger = class CloudflareLogger {
	baseContext;
	minLevel;
	outputMode;
	/**
	* Create a new CloudflareLogger
	*
	* @param baseContext Base context included in all log entries
	* @param minLevel Minimum log level to output (default: INFO)
	* @param outputMode How log entries are formatted and emitted (default: 'structured')
	*/
	constructor(baseContext, minLevel = LogLevel.INFO, outputMode = "structured") {
		this.baseContext = baseContext;
		this.minLevel = minLevel;
		this.outputMode = outputMode;
	}
	/**
	* Log debug-level message
	*/
	debug(message, context) {
		if (this.shouldLog(LogLevel.DEBUG)) {
			const logData = this.buildLogData("debug", message, context);
			this.output(console.log, logData);
		}
	}
	/**
	* Log info-level message
	*/
	info(message, context) {
		if (this.shouldLog(LogLevel.INFO)) {
			const logData = this.buildLogData("info", message, context);
			this.output(console.log, logData);
		}
	}
	/**
	* Log warning-level message
	*/
	warn(message, context) {
		if (this.shouldLog(LogLevel.WARN)) {
			const logData = this.buildLogData("warn", message, context);
			this.output(console.warn, logData);
		}
	}
	/**
	* Log error-level message
	*/
	error(message, error, context) {
		if (this.shouldLog(LogLevel.ERROR)) {
			const logData = this.buildLogData("error", message, context, error);
			this.output(console.error, logData);
		}
	}
	/**
	* Create a child logger with additional context
	*/
	child(context) {
		return new CloudflareLogger({
			...this.baseContext,
			...context
		}, this.minLevel, this.outputMode);
	}
	/**
	* Check if a log level should be output
	*/
	shouldLog(level) {
		return level >= this.minLevel;
	}
	/**
	* Build log data object
	*/
	buildLogData(level, message, context, error) {
		const logData = {
			level,
			message,
			...this.baseContext,
			...context,
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		};
		if (error) logData.error = {
			message: error.message,
			stack: error.stack,
			name: error.name
		};
		return logData;
	}
	/**
	* Output log data using the configured output mode
	*/
	output(consoleFn, data) {
		switch (this.outputMode) {
			case "pretty":
				this.outputPretty(consoleFn, data);
				break;
			case "json-line":
				this.outputJsonLine(consoleFn, data);
				break;
			case "structured": this.outputStructured(consoleFn, data);
		}
	}
	/**
	* Output as JSON string (container stdout — parsed by Containers pipeline)
	*/
	outputJsonLine(consoleFn, data) {
		consoleFn(JSON.stringify(data));
	}
	/**
	* Output as raw object (Workers/DOs — Workers Logs auto-indexes fields)
	*/
	outputStructured(consoleFn, data) {
		consoleFn(data);
	}
	/**
	* Output as pretty-printed, colored text (development)
	*
	* Each log event is a single consoleFn() call so it appears as one entry
	* in the Cloudflare dashboard. Context is rendered inline as compact key=value pairs.
	*
	* Format: LEVEL [component] message trace=tr_... key=value key=value
	*/
	outputPretty(consoleFn, data) {
		const { level, message: msg, timestamp, traceId, component, sandboxId, sessionId, processId, commandId, durationMs, serviceVersion, instanceId, error, ...rest } = data;
		const levelStr = String(level || "INFO").toUpperCase();
		const levelColor = this.getLevelColor(levelStr);
		const componentBadge = component ? `[${component}]` : "";
		let logLine = `${timestamp ? `${COLORS.dim}${new Date(timestamp).toISOString().substring(11, 23)}${COLORS.reset} ` : ""}${levelColor}${levelStr.padEnd(5)}${COLORS.reset} ${componentBadge} ${msg}`;
		const pairs = [];
		if (traceId) pairs.push(`trace=${String(traceId).substring(0, 12)}`);
		if (commandId) pairs.push(`cmd=${String(commandId).substring(0, 12)}`);
		if (sandboxId) pairs.push(`sandbox=${sandboxId}`);
		if (sessionId) pairs.push(`session=${String(sessionId).substring(0, 12)}`);
		if (processId) pairs.push(`proc=${processId}`);
		if (durationMs !== void 0) pairs.push(`dur=${durationMs}ms`);
		for (const [key, value] of Object.entries(rest)) {
			if (value === void 0 || value === null) continue;
			const v = typeof value === "object" ? JSON.stringify(value) : this.sanitizePrettyValue(String(value));
			pairs.push(`${key}=${v}`);
		}
		if (error && typeof error === "object") {
			const errorObj = error;
			if (errorObj.name) pairs.push(`err.name=${this.sanitizePrettyValue(errorObj.name)}`);
			if (errorObj.message) pairs.push(`err.msg=${this.sanitizePrettyValue(errorObj.message)}`);
			if (errorObj.stack) pairs.push(`err.stack=${this.sanitizePrettyValue(errorObj.stack)}`);
		}
		if (pairs.length > 0) logLine += ` ${COLORS.dim}${pairs.join(" ")}${COLORS.reset}`;
		consoleFn(logLine);
	}
	/**
	* Collapse newlines so a single consoleFn() call stays on one line.
	* Cloudflare's log pipeline splits on literal newlines, which fragments
	* stack traces and multi-line error messages into separate entries.
	*/
	sanitizePrettyValue(value) {
		return value.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
	}
	/**
	* Get ANSI color code for log level
	*/
	getLevelColor(level) {
		switch (level.toLowerCase()) {
			case "debug": return COLORS.debug;
			case "info": return COLORS.info;
			case "warn": return COLORS.warn;
			case "error": return COLORS.error;
			default: return COLORS.reset;
		}
	}
};
/**
* Trace context utilities for request correlation
*
* Trace IDs enable correlating logs across distributed components:
* Worker → Durable Object → Container → back
*
* The trace ID is propagated via the X-Trace-Id HTTP header.
*/
/**
* Utility for managing trace context across distributed components
*/
var TraceContext = class TraceContext {
	/**
	* HTTP header name for trace ID propagation
	*/
	static TRACE_HEADER = "X-Trace-Id";
	/**
	* Generate a new trace ID
	*
	* Format: "tr_" + 16 random hex characters
	* Example: "tr_7f3a9b2c4e5d6f1a"
	*
	* @returns Newly generated trace ID
	*/
	static generate() {
		return `tr_${crypto.randomUUID().replace(/-/g, "").substring(0, 16)}`;
	}
	/**
	* Extract trace ID from HTTP request headers
	*
	* @param headers Request headers
	* @returns Trace ID if present, null otherwise
	*/
	static fromHeaders(headers) {
		return headers.get(TraceContext.TRACE_HEADER);
	}
	/**
	* Create headers object with trace ID for outgoing requests
	*
	* @param traceId Trace ID to include
	* @returns Headers object with X-Trace-Id set
	*/
	static toHeaders(traceId) {
		return { [TraceContext.TRACE_HEADER]: traceId };
	}
	/**
	* Get the header name used for trace ID propagation
	*
	* @returns Header name ("X-Trace-Id")
	*/
	static getHeaderName() {
		return TraceContext.TRACE_HEADER;
	}
};
/**
* Logger module
*
* Provides structured, trace-aware logging with:
* - Explicit logger passing via constructor injection
* - Three output modes: structured (Workers/DOs), json-line (container), pretty (local dev)
* - Environment auto-detection
* - Log level configuration
*
* Usage:
*
* ```typescript
* // Create a logger at entry point
* const logger = createLogger({ component: 'sandbox-do', traceId: 'tr_abc123' });
*
* // Pass to classes via constructor
* const service = new MyService(logger);
*
* // Create child loggers for additional context
* const execLogger = logger.child({ commandId: 'cmd-456' });
* execLogger.info('Operation started');
* ```
*/
/**
* Create a no-op logger for testing
*
* Returns a logger that implements the Logger interface but does nothing.
* Useful for tests that don't need actual logging output.
*
* @returns No-op logger instance
*
* @example
* ```typescript
* // In tests
* const client = new HttpClient({
*   baseUrl: 'http://test.com',
*   logger: createNoOpLogger() // Optional - tests can enable real logging if needed
* });
* ```
*/
function createNoOpLogger() {
	return {
		debug: () => {},
		info: () => {},
		warn: () => {},
		error: () => {},
		child: () => createNoOpLogger()
	};
}
/**
* Create a new logger instance
*
* @param context Base context for the logger. Must include 'component'.
*                TraceId will be auto-generated if not provided.
* @returns New logger instance
*
* @example
* ```typescript
* // In Durable Object
* const logger = createLogger({
*   component: 'sandbox-do',
*   traceId: TraceContext.fromHeaders(request.headers) || TraceContext.generate(),
*   sandboxId: this.id
* });
*
* // In Container
* const logger = createLogger({
*   component: 'container',
*   traceId: TraceContext.fromHeaders(request.headers)!,
*   sessionId: this.id
* });
* ```
*/
function createLogger(context) {
	const minLevel = getLogLevelFromEnv();
	const outputMode = getOutputMode(context.component);
	return new CloudflareLogger({
		...context,
		traceId: context.traceId || TraceContext.generate(),
		component: context.component,
		serviceVersion: context.serviceVersion || getEnvVar("SANDBOX_VERSION") || void 0,
		instanceId: context.instanceId || getEnvVar("HOSTNAME") || getEnvVar("SANDBOX_INSTANCE_ID") || void 0
	}, minLevel, outputMode);
}
/**
* Get log level from environment variable
*
* Checks SANDBOX_LOG_LEVEL env var, falls back to default based on environment.
* Default: 'debug' for development, 'info' for production
*/
function getLogLevelFromEnv() {
	switch ((getEnvVar("SANDBOX_LOG_LEVEL") || "info").toLowerCase()) {
		case "debug": return LogLevel.DEBUG;
		case "info": return LogLevel.INFO;
		case "warn": return LogLevel.WARN;
		case "error": return LogLevel.ERROR;
		default: return LogLevel.INFO;
	}
}
/**
* Determine output mode based on component and environment:
* - SANDBOX_LOG_FORMAT=pretty → 'pretty' for all components (local wrangler dev)
* - Container/Executor without pretty → 'json-line' (Bun stdout → Containers pipeline)
* - Everything else without pretty → 'structured' (Workers/DOs → Workers Logs)
*
* In local dev, setting SANDBOX_LOG_FORMAT=pretty gives readable terminal
* output on both the DO side and container side. In production (where the
* var isn't set), DOs emit structured objects and containers emit single-line
* JSON — both queryable by their respective observability pipelines.
*/
function getOutputMode(component) {
	if (getEnvVar("SANDBOX_LOG_FORMAT")?.toLowerCase() === "pretty") return "pretty";
	if (component === "container" || component === "executor") return "json-line";
	return "structured";
}
/**
* Get environment variable value
*
* Supports both Node.js (process.env) and Bun (Bun.env)
*/
function getEnvVar(name) {
	if (typeof process !== "undefined" && process.env) return process.env[name];
	if (typeof Bun !== "undefined") {
		const bunEnv = Bun.env;
		if (bunEnv) return bunEnv[name];
	}
}
/**
* Escapes a string for safe use in shell commands using POSIX single-quote escaping.
* Prevents command injection by wrapping the string in single quotes and escaping
* any single quotes within the string.
*/
function shellEscape(str) {
	return `'${str.replace(/'/g, "'\\''")}'`;
}
/**
* Shared SSE parsing utilities.
*
* Parses SSE frames from arbitrary text chunks while preserving partial state
* across chunk boundaries.
*/
/**
* Parse SSE frames from a buffer.
*
* Returns parsed events, remaining unparsed text, and the current partial event
* so callers can continue parsing on the next chunk. `comments` counts comment
* lines (`: keepalive`), which carry no event but show the stream is alive.
*/
function parseSSEFrames(buffer, currentEvent = { data: [] }) {
	const events = [];
	let comments = 0;
	let i = 0;
	while (i < buffer.length) {
		const newlineIndex = buffer.indexOf("\n", i);
		if (newlineIndex === -1) break;
		const rawLine = buffer.substring(i, newlineIndex);
		const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
		i = newlineIndex + 1;
		if (line === "" && currentEvent.data.length > 0) {
			events.push({
				event: currentEvent.event,
				data: currentEvent.data.join("\n")
			});
			currentEvent = { data: [] };
			continue;
		}
		if (line.startsWith(":")) {
			comments++;
			continue;
		}
		if (line.startsWith("event:")) {
			currentEvent.event = line.startsWith("event: ") ? line.substring(7) : line.substring(6);
			continue;
		}
		if (line.startsWith("data:")) {
			const value = line.startsWith("data: ") ? line.substring(6) : line.substring(5);
			currentEvent.data.push(value);
		}
	}
	return {
		events,
		remaining: buffer.substring(i),
		currentEvent,
		comments
	};
}
/**
* Type guard for WSResponse
*
* Note: Only validates the discriminator field (type === 'response').
*/
function isWSResponse(msg) {
	return typeof msg === "object" && msg !== null && "type" in msg && msg.type === "response";
}
/**
* Type guard for WSStreamChunk
*
* Note: Only validates the discriminator field (type === 'stream').
*/
function isWSStreamChunk(msg) {
	return typeof msg === "object" && msg !== null && "type" in msg && msg.type === "stream";
}
/**
* Type guard for WSError
*
* Note: Only validates the discriminator field (type === 'error').
*/
function isWSError(msg) {
	return typeof msg === "object" && msg !== null && "type" in msg && msg.type === "error";
}
/**
* Generate a unique request ID
*/
function generateRequestId() {
	return `ws_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}
// node_modules/@cloudflare/sandbox/dist/errors-CHhwDJNh.js
/**
* Centralized error code registry
* Each code maps to a specific error type with consistent semantics
*/
var ErrorCode = {
	FILE_NOT_FOUND: "FILE_NOT_FOUND",
	PERMISSION_DENIED: "PERMISSION_DENIED",
	FILE_EXISTS: "FILE_EXISTS",
	IS_DIRECTORY: "IS_DIRECTORY",
	NOT_DIRECTORY: "NOT_DIRECTORY",
	FILE_TOO_LARGE: "FILE_TOO_LARGE",
	NO_SPACE: "NO_SPACE",
	TOO_MANY_FILES: "TOO_MANY_FILES",
	RESOURCE_BUSY: "RESOURCE_BUSY",
	READ_ONLY: "READ_ONLY",
	NAME_TOO_LONG: "NAME_TOO_LONG",
	TOO_MANY_LINKS: "TOO_MANY_LINKS",
	FILESYSTEM_ERROR: "FILESYSTEM_ERROR",
	COMMAND_NOT_FOUND: "COMMAND_NOT_FOUND",
	COMMAND_PERMISSION_DENIED: "COMMAND_PERMISSION_DENIED",
	INVALID_COMMAND: "INVALID_COMMAND",
	COMMAND_EXECUTION_ERROR: "COMMAND_EXECUTION_ERROR",
	STREAM_START_ERROR: "STREAM_START_ERROR",
	PROCESS_NOT_FOUND: "PROCESS_NOT_FOUND",
	PROCESS_PERMISSION_DENIED: "PROCESS_PERMISSION_DENIED",
	PROCESS_ERROR: "PROCESS_ERROR",
	SESSION_ALREADY_EXISTS: "SESSION_ALREADY_EXISTS",
	SESSION_DESTROYED: "SESSION_DESTROYED",
	SESSION_TERMINATED: "SESSION_TERMINATED",
	PORT_ALREADY_EXPOSED: "PORT_ALREADY_EXPOSED",
	PORT_IN_USE: "PORT_IN_USE",
	PORT_NOT_EXPOSED: "PORT_NOT_EXPOSED",
	INVALID_PORT_NUMBER: "INVALID_PORT_NUMBER",
	INVALID_PORT: "INVALID_PORT",
	SERVICE_NOT_RESPONDING: "SERVICE_NOT_RESPONDING",
	PORT_OPERATION_ERROR: "PORT_OPERATION_ERROR",
	CUSTOM_DOMAIN_REQUIRED: "CUSTOM_DOMAIN_REQUIRED",
	GIT_REPOSITORY_NOT_FOUND: "GIT_REPOSITORY_NOT_FOUND",
	GIT_BRANCH_NOT_FOUND: "GIT_BRANCH_NOT_FOUND",
	GIT_AUTH_FAILED: "GIT_AUTH_FAILED",
	GIT_NETWORK_ERROR: "GIT_NETWORK_ERROR",
	INVALID_GIT_URL: "INVALID_GIT_URL",
	GIT_CLONE_FAILED: "GIT_CLONE_FAILED",
	GIT_CHECKOUT_FAILED: "GIT_CHECKOUT_FAILED",
	GIT_OPERATION_FAILED: "GIT_OPERATION_FAILED",
	BUCKET_MOUNT_ERROR: "BUCKET_MOUNT_ERROR",
	BUCKET_UNMOUNT_ERROR: "BUCKET_UNMOUNT_ERROR",
	S3FS_MOUNT_ERROR: "S3FS_MOUNT_ERROR",
	MISSING_CREDENTIALS: "MISSING_CREDENTIALS",
	INVALID_MOUNT_CONFIG: "INVALID_MOUNT_CONFIG",
	TUNNEL_NOT_FOUND: "TUNNEL_NOT_FOUND",
	TUNNEL_ALREADY_RUNNING: "TUNNEL_ALREADY_RUNNING",
	TUNNEL_RUN_CONFLICT: "TUNNEL_RUN_CONFLICT",
	TUNNEL_START_ERROR: "TUNNEL_START_ERROR",
	CLOUDFLARED_NOT_FOUND: "CLOUDFLARED_NOT_FOUND",
	BACKUP_CREATE_FAILED: "BACKUP_CREATE_FAILED",
	BACKUP_RESTORE_FAILED: "BACKUP_RESTORE_FAILED",
	BACKUP_NOT_FOUND: "BACKUP_NOT_FOUND",
	BACKUP_EXPIRED: "BACKUP_EXPIRED",
	INVALID_BACKUP_CONFIG: "INVALID_BACKUP_CONFIG",
	INTERPRETER_NOT_READY: "INTERPRETER_NOT_READY",
	CONTEXT_NOT_FOUND: "CONTEXT_NOT_FOUND",
	CODE_EXECUTION_ERROR: "CODE_EXECUTION_ERROR",
	PYTHON_NOT_AVAILABLE: "PYTHON_NOT_AVAILABLE",
	JAVASCRIPT_NOT_AVAILABLE: "JAVASCRIPT_NOT_AVAILABLE",
	OPENCODE_STARTUP_FAILED: "OPENCODE_STARTUP_FAILED",
	PROCESS_READY_TIMEOUT: "PROCESS_READY_TIMEOUT",
	PROCESS_EXITED_BEFORE_READY: "PROCESS_EXITED_BEFORE_READY",
	WATCH_NOT_FOUND: "WATCH_NOT_FOUND",
	WATCH_START_ERROR: "WATCH_START_ERROR",
	WATCH_STOP_ERROR: "WATCH_STOP_ERROR",
	VALIDATION_FAILED: "VALIDATION_FAILED",
	INVALID_JSON_RESPONSE: "INVALID_JSON_RESPONSE",
	UNKNOWN_ERROR: "UNKNOWN_ERROR",
	INTERNAL_ERROR: "INTERNAL_ERROR",
	RPC_TRANSPORT_ERROR: "RPC_TRANSPORT_ERROR",
	CONTAINER_UNAVAILABLE: "CONTAINER_UNAVAILABLE",
	OPERATION_INTERRUPTED: "OPERATION_INTERRUPTED"
};
/**
* Maps error codes to HTTP status codes
* Centralized mapping ensures consistency across SDK
*/
var ERROR_STATUS_MAP = {
	[ErrorCode.FILE_NOT_FOUND]: 404,
	[ErrorCode.COMMAND_NOT_FOUND]: 404,
	[ErrorCode.PROCESS_NOT_FOUND]: 404,
	[ErrorCode.PORT_NOT_EXPOSED]: 404,
	[ErrorCode.GIT_REPOSITORY_NOT_FOUND]: 404,
	[ErrorCode.GIT_BRANCH_NOT_FOUND]: 404,
	[ErrorCode.CONTEXT_NOT_FOUND]: 404,
	[ErrorCode.WATCH_NOT_FOUND]: 404,
	[ErrorCode.IS_DIRECTORY]: 400,
	[ErrorCode.NOT_DIRECTORY]: 400,
	[ErrorCode.INVALID_COMMAND]: 400,
	[ErrorCode.INVALID_PORT_NUMBER]: 400,
	[ErrorCode.INVALID_PORT]: 400,
	[ErrorCode.INVALID_GIT_URL]: 400,
	[ErrorCode.CUSTOM_DOMAIN_REQUIRED]: 400,
	[ErrorCode.INVALID_JSON_RESPONSE]: 400,
	[ErrorCode.NAME_TOO_LONG]: 400,
	[ErrorCode.VALIDATION_FAILED]: 400,
	[ErrorCode.MISSING_CREDENTIALS]: 400,
	[ErrorCode.INVALID_MOUNT_CONFIG]: 400,
	[ErrorCode.GIT_AUTH_FAILED]: 401,
	[ErrorCode.PERMISSION_DENIED]: 403,
	[ErrorCode.COMMAND_PERMISSION_DENIED]: 403,
	[ErrorCode.PROCESS_PERMISSION_DENIED]: 403,
	[ErrorCode.READ_ONLY]: 403,
	[ErrorCode.FILE_EXISTS]: 409,
	[ErrorCode.PORT_ALREADY_EXPOSED]: 409,
	[ErrorCode.PORT_IN_USE]: 409,
	[ErrorCode.RESOURCE_BUSY]: 409,
	[ErrorCode.SESSION_ALREADY_EXISTS]: 409,
	[ErrorCode.OPERATION_INTERRUPTED]: 409,
	[ErrorCode.SESSION_DESTROYED]: 410,
	[ErrorCode.SESSION_TERMINATED]: 410,
	[ErrorCode.FILE_TOO_LARGE]: 413,
	[ErrorCode.SERVICE_NOT_RESPONDING]: 502,
	[ErrorCode.GIT_NETWORK_ERROR]: 502,
	[ErrorCode.BACKUP_NOT_FOUND]: 404,
	[ErrorCode.BACKUP_EXPIRED]: 400,
	[ErrorCode.INVALID_BACKUP_CONFIG]: 400,
	[ErrorCode.BACKUP_CREATE_FAILED]: 500,
	[ErrorCode.BACKUP_RESTORE_FAILED]: 500,
	[ErrorCode.TUNNEL_NOT_FOUND]: 404,
	[ErrorCode.TUNNEL_ALREADY_RUNNING]: 409,
	[ErrorCode.TUNNEL_RUN_CONFLICT]: 409,
	[ErrorCode.TUNNEL_START_ERROR]: 500,
	[ErrorCode.CLOUDFLARED_NOT_FOUND]: 501,
	[ErrorCode.PYTHON_NOT_AVAILABLE]: 501,
	[ErrorCode.JAVASCRIPT_NOT_AVAILABLE]: 501,
	[ErrorCode.INTERPRETER_NOT_READY]: 503,
	[ErrorCode.OPENCODE_STARTUP_FAILED]: 503,
	[ErrorCode.RPC_TRANSPORT_ERROR]: 503,
	[ErrorCode.CONTAINER_UNAVAILABLE]: 503,
	[ErrorCode.PROCESS_READY_TIMEOUT]: 408,
	[ErrorCode.PROCESS_EXITED_BEFORE_READY]: 500,
	[ErrorCode.NO_SPACE]: 500,
	[ErrorCode.TOO_MANY_FILES]: 500,
	[ErrorCode.TOO_MANY_LINKS]: 500,
	[ErrorCode.FILESYSTEM_ERROR]: 500,
	[ErrorCode.COMMAND_EXECUTION_ERROR]: 500,
	[ErrorCode.STREAM_START_ERROR]: 500,
	[ErrorCode.PROCESS_ERROR]: 500,
	[ErrorCode.PORT_OPERATION_ERROR]: 500,
	[ErrorCode.GIT_CLONE_FAILED]: 500,
	[ErrorCode.GIT_CHECKOUT_FAILED]: 500,
	[ErrorCode.GIT_OPERATION_FAILED]: 500,
	[ErrorCode.CODE_EXECUTION_ERROR]: 500,
	[ErrorCode.BUCKET_MOUNT_ERROR]: 500,
	[ErrorCode.BUCKET_UNMOUNT_ERROR]: 500,
	[ErrorCode.S3FS_MOUNT_ERROR]: 500,
	[ErrorCode.WATCH_START_ERROR]: 500,
	[ErrorCode.WATCH_STOP_ERROR]: 500,
	[ErrorCode.UNKNOWN_ERROR]: 500,
	[ErrorCode.INTERNAL_ERROR]: 500
};
/**
* Get HTTP status code for an error code
* Falls back to 500 for unknown errors
*/
function getHttpStatus(code) {
	return ERROR_STATUS_MAP[code] || 500;
}
/**
* Get actionable suggestion for an error code
* Used by handlers when enriching ServiceError → ErrorResponse
*/
function getSuggestion(code, context) {
	switch (code) {
		case ErrorCode.FILE_NOT_FOUND: return `Ensure the file exists at ${context.path} before attempting to access it`;
		case ErrorCode.FILE_EXISTS: return `File already exists at ${context.path}. Use a different path or delete the existing file first`;
		case ErrorCode.COMMAND_NOT_FOUND: return `Check that "${context.command}" is installed and available in the system PATH`;
		case ErrorCode.PROCESS_NOT_FOUND: return "Verify the process ID is correct and the process has not already exited";
		case ErrorCode.PORT_NOT_EXPOSED: return `Port ${context.port} is not currently available for this operation`;
		case ErrorCode.PORT_ALREADY_EXPOSED: return `Port ${context.port} already has preview URL authorization or activation state`;
		case ErrorCode.PORT_IN_USE: return `Port ${context.port} is already in use by another service. Choose a different port`;
		case ErrorCode.SESSION_ALREADY_EXISTS: return `Session "${context.sessionId}" already exists. Use a different session ID or reuse the existing session`;
		case ErrorCode.SESSION_DESTROYED: return `Session "${context.sessionId}" was destroyed. Create a new session to continue executing commands`;
		case ErrorCode.SESSION_TERMINATED: return `Session "${context.sessionId}" ended because its shell exited (exit code: ${context.exitCode ?? "unknown"}). Session-local state (env vars, cwd, shell functions) has been lost. Retry the call to start a fresh session, or call createSession() with the same id to recreate it explicitly`;
		case ErrorCode.INVALID_PORT: return `Port must be between 1 and 65535. Port ${context.port} is ${context.reason}`;
		case ErrorCode.GIT_REPOSITORY_NOT_FOUND: return "Verify the repository URL is correct and accessible";
		case ErrorCode.GIT_AUTH_FAILED: return "Check authentication credentials or use a public repository";
		case ErrorCode.GIT_BRANCH_NOT_FOUND: return `Branch "${context.branch}" does not exist in the repository. Check the branch name or use the default branch`;
		case ErrorCode.INTERPRETER_NOT_READY: return context.retryAfter ? `Code interpreter is starting up. Retry after ${context.retryAfter} seconds` : "Code interpreter is not ready. Please wait a moment and try again";
		case ErrorCode.CONTEXT_NOT_FOUND: return `Context "${context.contextId}" does not exist. Create a context first using createContext()`;
		case ErrorCode.VALIDATION_FAILED: return "Check the request parameters and ensure they match the required format";
		case ErrorCode.NO_SPACE: return "Not enough disk space available. Consider cleaning up temporary files or increasing storage";
		case ErrorCode.PERMISSION_DENIED: return "Operation not permitted. Check file/directory permissions";
		case ErrorCode.IS_DIRECTORY: return `Cannot perform this operation on a directory. Path ${context.path} is a directory`;
		case ErrorCode.NOT_DIRECTORY: return `Expected a directory but found a file at ${context.path}`;
		case ErrorCode.RESOURCE_BUSY: return "Resource is currently in use. Wait for the current operation to complete";
		case ErrorCode.READ_ONLY: return "Cannot modify a read-only resource";
		case ErrorCode.SERVICE_NOT_RESPONDING: return "Service is not responding. Check if the service is running and accessible";
		case ErrorCode.BACKUP_NOT_FOUND: return `Backup "${context.backupId}" does not exist. Verify the backup ID is correct`;
		case ErrorCode.BACKUP_EXPIRED: return `Backup "${context.backupId}" has expired. Create a new backup`;
		case ErrorCode.INVALID_BACKUP_CONFIG: return `Invalid backup configuration: ${context.reason}`;
		case ErrorCode.BACKUP_CREATE_FAILED: return "Backup creation failed. Check that the directory exists and you have sufficient disk space";
		case ErrorCode.BACKUP_RESTORE_FAILED: return "Backup restoration failed. The archive may be corrupted or the target directory may be in use";
		case ErrorCode.CONTAINER_UNAVAILABLE: return "The sandbox container is temporarily unavailable. Retry the same operation — it will succeed once the container is ready.";
		case ErrorCode.OPERATION_INTERRUPTED: return "The sandbox operation was interrupted by a runtime change. Retry only if the operation is idempotent, or verify sandbox state before retrying.";
		case ErrorCode.RPC_TRANSPORT_ERROR: switch (context.kind) {
			case "peer_closed": return "The container closed the WebSocket mid-call (likely a container restart, eviction, or crash). Retry the call — the SDK will open a fresh connection.";
			case "connection_failed": return "The WebSocket connection failed. Retry the call; if the failure persists, check container health and network connectivity.";
			case "upgrade_failed": return "The WebSocket upgrade was rejected by the container. Verify the container is running and reachable on the configured port.";
			case "invalid_frame": return "The container sent a frame the RPC transport cannot handle. This usually indicates a version mismatch between the SDK and the container image.";
			case "protocol_error": return "The peer sent a malformed RPC message (could not parse the wire format). This usually indicates a version mismatch between the SDK and the container image.";
			case "session_disposed": return "The RPC session was disposed while a call was in flight. Avoid reusing stubs after disconnect(); the next method call will reconnect automatically.";
			default: return "The RPC transport raised an error. Retry the call — the SDK will open a fresh connection.";
		}
		default: return;
	}
}
// node_modules/@cloudflare/containers/dist/lib/helpers.js
/**
* Generates a random ID of a specified length using a url-friendly alphabet
* Can be run without node:crypto
* @param length - The length of the ID to generate (default: 9)
* @returns A random string ID
*/
function generateId(length = 9) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	const bytes = new Uint8Array(length);
	crypto.getRandomValues(bytes);
	let result = "";
	for (let i = 0; i < length; i++) result += alphabet[bytes[i] % 62];
	return result;
}
/**
* Parse a time expression into seconds
* @param timeExpression Time expression (number or string like "5m", "30s", "1h")
* @returns Number of seconds
*/
function parseTimeExpression(timeExpression) {
	if (typeof timeExpression === "number") return timeExpression;
	if (typeof timeExpression === "string") {
		const match = timeExpression.match(/^(\d+)([smh])$/);
		if (!match) throw new Error(`invalid time expression ${timeExpression}`);
		const value = parseInt(match[1]);
		const unit = match[2];
		switch (unit) {
			case "s": return value;
			case "m": return value * 60;
			case "h": return value * 60 * 60;
			default: throw new Error(`unknown time unit ${unit}`);
		}
	}
	throw new Error(`invalid type for a time expression: ${typeof timeExpression}`);
}
// node_modules/@cloudflare/containers/dist/lib/container.js
var NO_CONTAINER_INSTANCE_ERROR = "there is no container instance that can be provided to this durable object";
var RATE_LIMITED_ERROR = "you are requesting too many containers per second";
var RUNTIME_SIGNALLED_ERROR = "runtime signalled the container to exit:";
var UNEXPECTED_EXIT_ERROR = "container exited with unexpected exit code:";
var NOT_LISTENING_ERROR = "the container is not listening";
var CONTAINER_STATE_KEY = "__CF_CONTAINER_STATE";
var OUTBOUND_CONFIGURATION_KEY = "OUTBOUND_CONFIGURATION";
var MAX_ALARM_RETRIES = 3;
var PING_TIMEOUT_MS = 5e3;
var DEFAULT_SLEEP_AFTER = "10m";
var INSTANCE_POLL_INTERVAL_MS = 300;
var TIMEOUT_TO_GET_CONTAINER_MS = 8e3;
var TIMEOUT_TO_GET_PORTS_MS = 2e4;
var FALLBACK_PORT_TO_CHECK = 33;
var outboundHandlersRegistry = /* @__PURE__ */ new Map();
var defaultOutboundHandlerNameRegistry = /* @__PURE__ */ new Map();
var outboundByHostRegistry = /* @__PURE__ */ new Map();
var signalToNumbers = {
	SIGINT: 2,
	SIGTERM: 15,
	SIGKILL: 9
};
function isErrorOfType(e, matchingString) {
	return (e instanceof Error ? e.message : String(e)).toLowerCase().includes(matchingString);
}
var isNoInstanceError = (error) => isErrorOfType(error, NO_CONTAINER_INSTANCE_ERROR);
var isRateLimitedError = (error) => isErrorOfType(error, RATE_LIMITED_ERROR);
var isRuntimeSignalledError = (error) => isErrorOfType(error, RUNTIME_SIGNALLED_ERROR);
var isNotListeningError = (error) => isErrorOfType(error, NOT_LISTENING_ERROR);
var isContainerExitNonZeroError = (error) => isErrorOfType(error, UNEXPECTED_EXIT_ERROR);
function getExitCodeFromError(error) {
	if (!(error instanceof Error)) return null;
	if (isRuntimeSignalledError(error)) return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(RUNTIME_SIGNALLED_ERROR) + 40 + 1);
	if (isContainerExitNonZeroError(error)) return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(UNEXPECTED_EXIT_ERROR) + 43 + 1);
	return null;
}
/**
* Combines the existing user-defined signal with a signal that aborts after the timeout specified by waitInterval
*/
function addTimeoutSignal(existingSignal, timeoutMs) {
	const controller = new AbortController();
	if (existingSignal?.aborted) {
		controller.abort();
		return controller.signal;
	}
	existingSignal?.addEventListener("abort", () => controller.abort());
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	controller.signal.addEventListener("abort", () => clearTimeout(timeoutId));
	return controller.signal;
}
/**
* ContainerState is a wrapper around a DO storage to store and get
* the container state.
* It's useful to track which kind of events have been handled by the user,
* a transition to a new state won't be successful unless the user's hook has been
* triggered and waited for.
* A user hook might be repeated multiple times if they throw errors.
*/
var ContainerState = class {
	storage;
	status;
	constructor(storage) {
		this.storage = storage;
	}
	async setRunning() {
		await this.setStatusAndupdate("running");
	}
	async setHealthy() {
		await this.setStatusAndupdate("healthy");
	}
	async setStopping() {
		await this.setStatusAndupdate("stopping");
	}
	async setStopped() {
		await this.setStatusAndupdate("stopped");
	}
	async setStoppedIfUnchanged(previousState) {
		if (this.status !== previousState) return;
		await this.setStopped();
	}
	async setStoppedWithCode(exitCode) {
		this.status = {
			status: "stopped_with_code",
			lastChange: Date.now(),
			exitCode
		};
		await this.update();
	}
	async getState() {
		if (!this.status) {
			const state = await this.storage.get(CONTAINER_STATE_KEY);
			if (!state) {
				this.status = {
					status: "stopped",
					lastChange: Date.now()
				};
				await this.update();
			} else this.status = state;
		}
		return this.status;
	}
	async setStatusAndupdate(status) {
		this.status = {
			status,
			lastChange: Date.now()
		};
		await this.update();
	}
	async update() {
		if (!this.status) throw new Error("status should be init");
		await this.storage.put(CONTAINER_STATE_KEY, this.status);
	}
};
var Container = class extends DurableObject {
	static get outboundByHost() {
		return outboundByHostRegistry.get(this.name);
	}
	static set outboundByHost(handlers) {
		outboundByHostRegistry.set(this.name, handlers);
	}
	static get outboundHandlers() {
		return outboundHandlersRegistry.get(this.name);
	}
	static set outboundHandlers(handlers) {
		const existing = outboundHandlersRegistry.get(this.name) ?? {};
		outboundHandlersRegistry.set(this.name, {
			...existing,
			...handlers
		});
	}
	static get outbound() {
		const handlerName = defaultOutboundHandlerNameRegistry.get(this.name);
		if (!handlerName) return void 0;
		return outboundHandlersRegistry.get(this.name)?.[handlerName];
	}
	static set outbound(handler) {
		const key = "__outbound__";
		const existing = outboundHandlersRegistry.get(this.name) ?? {};
		outboundHandlersRegistry.set(this.name, {
			...existing,
			[key]: handler
		});
		defaultOutboundHandlerNameRegistry.set(this.name, key);
	}
	static get outboundProxies() {
		return this.outboundHandlers;
	}
	static set outboundProxies(handlers) {
		this.outboundHandlers = handlers;
	}
	static get outboundProxy() {
		return this.outbound;
	}
	static set outboundProxy(handler) {
		this.outbound = handler;
	}
	defaultPort;
	requiredPorts;
	sleepAfter = DEFAULT_SLEEP_AFTER;
	envVars = {};
	entrypoint;
	enableInternet = true;
	labels = {};
	interceptHttps = false;
	allowedHosts;
	deniedHosts;
	pingEndpoint = "ping";
	applyOutboundInterceptionPromise = Promise.resolve();
	usingInterception = false;
	constructor(ctx, env, options) {
		super(ctx, env);
		if (ctx.container === void 0) throw new Error("Containers have not been enabled for this Durable Object class. Have you correctly setup your Wrangler config? More info: https://developers.cloudflare.com/containers/get-started/#configuration");
		this.state = new ContainerState(this.ctx.storage);
		const persistedOutboundConfiguration = this.restoreOutboundConfiguration();
		this.ctx.blockConcurrencyWhile(async () => {
			await this.scheduleNextAlarm();
			this.renewActivityTimeout();
			const ctor = this.constructor;
			if (persistedOutboundConfiguration !== void 0 || ctor.outboundByHost !== void 0 || ctor.outbound !== void 0 || ctor.outboundHandlers !== void 0 || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0) this.usingInterception = true;
			if (this.container.running) this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
		});
		this.container = ctx.container;
		if (options) {
			if (options.defaultPort !== void 0) this.defaultPort = options.defaultPort;
			if (options.sleepAfter !== void 0) this.sleepAfter = options.sleepAfter;
			if (options.envVars !== void 0) this.envVars = options.envVars;
			if (options.entrypoint !== void 0) this.entrypoint = options.entrypoint;
			if (options.enableInternet !== void 0) this.enableInternet = options.enableInternet;
		}
		this.sql`
      CREATE TABLE IF NOT EXISTS container_schedules (
        id TEXT PRIMARY KEY NOT NULL DEFAULT (randomblob(9)),
        callback TEXT NOT NULL,
        payload TEXT,
        type TEXT NOT NULL CHECK(type IN ('scheduled', 'delayed')),
        time INTEGER NOT NULL,
        delayInSeconds INTEGER,
        created_at INTEGER DEFAULT (unixepoch())
      )
    `;
		if (this.container.running) {
			this.monitor = this.container.monitor();
			this.setupMonitorCallbacks();
		}
	}
	/**
	* Gets the current state of the container
	* @returns Promise<State>
	*/
	async getState() {
		return { ...await this.state.getState() };
	}
	/**
	* Set the catch-all outbound handler to a named method from `outboundHandlers`.
	* Overrides the default `outbound` at runtime via ContainerProxy props.
	*
	* @param methodName - Name of a method defined in `static outboundHandlers`
	* @param params - Optional params passed to the handler as `ctx.params`
	* @throws Error if the method name is not found in `outboundHandlers`
	*/
	async setOutboundHandler(methodName, ...paramsArg) {
		this.validateOutboundHandlerMethodName(methodName);
		this.outboundHandlerOverride = paramsArg.length === 0 ? { method: methodName } : {
			method: methodName,
			params: paramsArg[0]
		};
		await this.refreshOutboundInterception();
	}
	/**
	* Add or override a hostname-specific outbound handler at runtime,
	* referencing a named method from `outboundHandlers`.
	* Overrides any matching entry in `static outboundByHost` for this hostname.
	*
	* @param hostname - The hostname or ip:port to intercept (e.g. `'google.com'`)
	* @param methodName - Name of a method defined in `static outboundHandlers`
	* @param params - Optional params passed to the handler as `ctx.params`
	* @throws Error if the method name is not found in `outboundHandlers`
	*/
	async setOutboundByHost(hostname, methodName, ...paramsArg) {
		this.validateOutboundHandlerMethodName(methodName);
		this.outboundByHostOverrides[hostname] = paramsArg.length === 0 ? { method: methodName } : {
			method: methodName,
			params: paramsArg[0]
		};
		await this.refreshOutboundInterception();
	}
	/**
	* Remove a runtime hostname override added via `setOutboundByHost`.
	* The default handler from `static outboundByHost` (if any) will be used again.
	*
	* @param hostname - The hostname or ip:port to stop overriding
	*/
	async removeOutboundByHost(hostname) {
		delete this.outboundByHostOverrides[hostname];
		await this.refreshOutboundInterception();
	}
	/**
	* Replace all runtime hostname overrides at once.
	* Each value may be either a method name or an object with `method` and `params`.
	*
	* @param handlers - Record mapping hostnames to handler configs in `outboundHandlers`
	* @throws Error if any method name is not found in `outboundHandlers`
	*/
	async setOutboundByHosts(handlers) {
		for (const handler of Object.values(handlers)) {
			const methodName = typeof handler === "string" ? handler : handler.method;
			this.validateOutboundHandlerMethodName(methodName);
		}
		this.outboundByHostOverrides = Object.fromEntries(Object.entries(handlers).map(([hostname, handler]) => [hostname, typeof handler === "string" ? { method: handler } : handler]));
		await this.refreshOutboundInterception();
	}
	/**
	* Replace all allowed hosts at runtime.
	* Allowed hosts get internet access even when `enableInternet` is false.
	*
	* @param hosts - Array of hostnames to allow (e.g. `['api.stripe.com', 'example.com']`)
	*/
	async setAllowedHosts(hosts) {
		this.allowedHostsOverride = [...hosts];
		this.usingInterception = true;
		await this.refreshOutboundInterception();
	}
	/**
	* Replace all denied hosts at runtime.
	* Denied hosts are blocked unconditionally, even when `enableInternet` is true
	* or a catch-all outbound handler is set.
	*
	* @param hosts - Array of hostnames to deny (e.g. `['evil.com', 'blocked.org']`)
	*/
	async setDeniedHosts(hosts) {
		this.deniedHostsOverride = [...hosts];
		this.usingInterception = true;
		await this.refreshOutboundInterception();
	}
	/**
	* Add a single hostname to the allowed hosts list at runtime.
	*
	* @param hostname - The hostname to allow (e.g. `'api.stripe.com'`)
	*/
	async allowHost(hostname) {
		const effective = this.effectiveAllowedHosts ?? [];
		if (!effective.includes(hostname)) this.allowedHostsOverride = [...effective, hostname];
		this.usingInterception = true;
		await this.refreshOutboundInterception();
	}
	/**
	* Add a single hostname to the denied hosts list at runtime.
	*
	* @param hostname - The hostname to deny (e.g. `'evil.com'`)
	*/
	async denyHost(hostname) {
		const effective = this.effectiveDeniedHosts ?? [];
		if (!effective.includes(hostname)) this.deniedHostsOverride = [...effective, hostname];
		this.usingInterception = true;
		await this.refreshOutboundInterception();
	}
	/**
	* Remove a hostname from the allowed hosts list.
	*
	* @param hostname - The hostname to remove from the allow list
	*/
	async removeAllowedHost(hostname) {
		this.allowedHostsOverride = (this.effectiveAllowedHosts ?? []).filter((h) => h !== hostname);
		await this.refreshOutboundInterception();
	}
	/**
	* Remove a hostname from the denied hosts list.
	*
	* @param hostname - The hostname to remove from the deny list
	*/
	async removeDeniedHost(hostname) {
		this.deniedHostsOverride = (this.effectiveDeniedHosts ?? []).filter((h) => h !== hostname);
		await this.refreshOutboundInterception();
	}
	/**
	* Start the container if it's not running and set up monitoring and lifecycle hooks,
	* without waiting for ports to be ready.
	*
	* It will automatically retry if the container fails to start, using the specified waitOptions
	*
	*
	* @example
	* await this.start({
	*   envVars: { DEBUG: 'true', NODE_ENV: 'development' },
	*   entrypoint: ['npm', 'run', 'dev'],
	*   enableInternet: false,
	*   labels: { tenant: 'acme', env: 'prod' },
	* });
	*
	* @param startOptions - Override `envVars`, `entrypoint`, `enableInternet` and `labels` on a per-instance basis
	* @param waitOptions - Optional wait configuration with abort signal for cancellation. Default ~8s timeout.
	* @returns A promise that resolves when the container start command has been issued
	* @throws Error if no container context is available or if all start attempts fail
	*/
	async start(startOptions, waitOptions) {
		const portToCheck = waitOptions?.portToCheck ?? this.defaultPort ?? (this.requiredPorts ? this.requiredPorts[0] : FALLBACK_PORT_TO_CHECK);
		const pollInterval = waitOptions?.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
		await this.startContainerIfNotRunning({
			signal: waitOptions?.signal,
			waitInterval: pollInterval,
			retries: waitOptions?.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval),
			portToCheck
		}, startOptions);
		this.setupMonitorCallbacks();
		await this.ctx.blockConcurrencyWhile(async () => {
			await this.onStart();
		});
	}
	async startAndWaitForPorts(portsOrArgs, cancellationOptions, startOptions) {
		let ports;
		let resolvedCancellationOptions;
		let resolvedStartOptions;
		if (typeof portsOrArgs === "object" && portsOrArgs !== null && !Array.isArray(portsOrArgs)) {
			ports = portsOrArgs.ports;
			resolvedCancellationOptions = portsOrArgs.cancellationOptions;
			resolvedStartOptions = portsOrArgs.startOptions;
		} else {
			ports = portsOrArgs;
			resolvedCancellationOptions = cancellationOptions;
			resolvedStartOptions = startOptions;
		}
		const portsToCheck = await this.getPortsToCheck(ports);
		await this.syncPendingStoppedEvents();
		resolvedCancellationOptions ??= {};
		const containerGetTimeout = resolvedCancellationOptions.instanceGetTimeoutMS ?? TIMEOUT_TO_GET_CONTAINER_MS;
		const pollInterval = resolvedCancellationOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
		const containerGetRetries = Math.ceil(containerGetTimeout / pollInterval);
		const waitOptions = {
			signal: resolvedCancellationOptions.abort,
			retries: containerGetRetries,
			waitInterval: pollInterval,
			portToCheck: portsToCheck[0]
		};
		const triesUsed = await this.startContainerIfNotRunning(waitOptions, resolvedStartOptions);
		let triesLeft = Math.ceil((resolvedCancellationOptions.portReadyTimeoutMS ?? TIMEOUT_TO_GET_PORTS_MS) / pollInterval) - triesUsed;
		for (const port of portsToCheck) triesLeft = await this.waitForPort({
			signal: resolvedCancellationOptions.abort,
			waitInterval: pollInterval,
			retries: triesLeft,
			portToCheck: port
		});
		this.setupMonitorCallbacks();
		await this.ctx.blockConcurrencyWhile(async () => {
			await this.state.setHealthy();
			await this.onStart();
		});
	}
	/**
	*
	* Waits for a specified port to be ready
	*
	* Returns the number of tries used to get the port, or throws if it couldn't get the port within the specified retry limits.
	*
	* @param waitOptions -
	* - `portToCheck`: The port number to check
	* - `abort`: Optional AbortSignal to cancel waiting
	* - `retries`: Number of retries before giving up (default: TRIES_TO_GET_PORTS)
	* - `waitInterval`: Interval between retries in milliseconds (default: INSTANCE_POLL_INTERVAL_MS)
	*/
	async waitForPort(waitOptions) {
		const port = waitOptions.portToCheck;
		const tcpPort = this.container.getTcpPort(port);
		const abortedSignal = new Promise((res) => {
			waitOptions.signal?.addEventListener("abort", () => {
				res(true);
			});
		});
		const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
		const tries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_PORTS_MS / pollInterval);
		for (let i = 0; i < tries; i++) try {
			const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
			await tcpPort.fetch(`http://${this.pingEndpoint}`, { signal: combinedSignal });
			break;
		} catch (e) {
			const errorMessage = e instanceof Error ? e.message : String(e);
			if (!this.container.running) {
				try {
					await this.onError(/* @__PURE__ */ new Error(`Container crashed while checking for ports, did you start the container and setup the entrypoint correctly?`));
				} catch {}
				throw e;
			}
			if (i === tries - 1) {
				try {
					await this.onError(`Failed to verify port ${port} is available after ${(i + 1) * pollInterval}ms, last error: ${errorMessage}`);
				} catch {}
				throw e;
			}
			await Promise.any([new Promise((resolve) => setTimeout(resolve, pollInterval)), abortedSignal]);
			if (waitOptions.signal?.aborted) throw new Error("Container request aborted.", { cause: e });
		}
		return tries;
	}
	/**
	* Send a signal to the container.
	* @param signal - The signal to send to the container (default: 15 for SIGTERM)
	*/
	async stop(signal = "SIGTERM") {
		if (this.container.running) this.container.signal(typeof signal === "string" ? signalToNumbers[signal] : signal);
		await this.syncPendingStoppedEvents();
	}
	/**
	* Destroys the container with a SIGKILL. Triggers onStop.
	*/
	async destroy() {
		await this.container.destroy();
	}
	/**
	* Lifecycle method called when container starts successfully
	* Override this method in subclasses to handle container start events
	*/
	onStart() {}
	/**
	* Lifecycle method called when container shuts down
	* Override this method in subclasses to handle Container stopped events
	* @param params - Object containing exitCode and reason for the stop
	*/
	onStop(params) {}
	/**
	* Lifecycle method called when the container is running, and the activity timeout
	* expiration (set by `sleepAfter`) has been reached.
	*
	* If you want to shutdown the container, you should call this.stop() here
	*
	* By default, this method calls `this.stop()`
	*/
	async onActivityExpired() {
		console.log("Activity expired, signalling container to stop");
		if (!this.container.running) return;
		await this.stop();
	}
	/**
	* Error handler for container errors
	* Override this method in subclasses to handle container errors
	* @param error - The error that occurred
	* @returns Can return any value or throw the error
	*/
	onError(error) {
		console.error("Container error:", error);
		throw error;
	}
	/**
	* Renew the container's activity timeout
	*
	* Call this method whenever there is activity on the container
	*/
	renewActivityTimeout() {
		const timeoutInMs = parseTimeExpression(this.sleepAfter) * 1e3;
		this.sleepAfterMs = Date.now() + timeoutInMs;
	}
	/**
	* Decrement the inflight request counter.
	* When the counter transitions to 0, renew the activity timeout so the
	* inactivity window starts fresh from the moment the last request completes.
	*/
	decrementInflight() {
		this.inflightRequests = Math.max(0, this.inflightRequests - 1);
		if (this.inflightRequests === 0) this.renewActivityTimeout();
	}
	/**
	* Schedule a task to be executed in the future.
	*
	* We strongly recommend using this instead of the `alarm` handler.
	*
	* @template T Type of the payload data
	* @param when When to execute the task (Date object or number of seconds delay)
	* @param callback Name of the method to call
	* @param payload Data to pass to the callback
	* @returns Schedule object representing the scheduled task
	*/
	async schedule(when, callback, payload) {
		const id = generateId(9);
		if (typeof callback !== "string") throw new Error("Callback must be a string (method name)");
		if (typeof this[callback] !== "function") throw new Error(`this.${callback} is not a function`);
		if (when instanceof Date) {
			const timestamp = Math.floor(when.getTime() / 1e3);
			this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'scheduled', ${timestamp})
      `;
			await this.scheduleNextAlarm();
			return {
				taskId: id,
				callback,
				payload,
				time: timestamp,
				type: "scheduled"
			};
		}
		if (typeof when === "number") {
			const time = Math.floor(Date.now() / 1e3 + when);
			this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, delayInSeconds, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'delayed', ${when}, ${time})
      `;
			await this.scheduleNextAlarm();
			return {
				taskId: id,
				callback,
				payload,
				delayInSeconds: when,
				time,
				type: "delayed"
			};
		}
		throw new Error("Invalid schedule type. 'when' must be a Date or number of seconds");
	}
	/**
	* Send a request to the container (HTTP or WebSocket) using standard fetch API signature
	*
	* This method handles HTTP requests to the container.
	*
	* WebSocket requests done outside the DO won't work until https://github.com/cloudflare/workerd/issues/2319 is addressed.
	* Until then, please use `switchPort` + `fetch()`.
	*
	* Method supports multiple signatures to match standard fetch API:
	* - containerFetch(request: Request, port?: number)
	* - containerFetch(url: string | URL, init?: RequestInit, port?: number)
	*
	* Starts the container if not already running, and waits for the target port to be ready.
	*
	* @returns A Response from the container
	*/
	async containerFetch(requestOrUrl, portOrInit, portParam) {
		const { request, port } = this.requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam);
		const state = await this.state.getState();
		if (!this.container.running || state.status !== "healthy") try {
			await this.startAndWaitForPorts(port, { abort: request.signal });
		} catch (e) {
			if (isNoInstanceError(e)) return new Response("There is no Container instance available at this time.\nThis is likely because you have reached your max concurrent instance count (set in wrangler config) or are you currently provisioning the Container.\nIf you are deploying your Container for the first time, check your dashboard to see provisioning status, this may take a few minutes.", { status: 503 });
			if (isRateLimitedError(e)) return new Response(e instanceof Error ? e.message : String(e), { status: 429 });
			return new Response(`Failed to start container: ${e instanceof Error ? e.message : String(e)}`, { status: 500 });
		}
		const tcpPort = this.container.getTcpPort(port);
		const containerUrl = request.url.replace("https:", "http:");
		this.inflightRequests++;
		try {
			this.renewActivityTimeout();
			const res = await tcpPort.fetch(containerUrl, request);
			if (res.webSocket !== null) {
				const containerWs = res.webSocket;
				const [client, server] = Object.values(new WebSocketPair());
				let settled = false;
				const settleInflight = () => {
					if (!settled) {
						settled = true;
						this.decrementInflight();
					}
				};
				containerWs.accept();
				server.accept();
				server.addEventListener("message", async (event) => {
					this.renewActivityTimeout();
					try {
						const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
						containerWs.send(data);
					} catch {
						server.close(1011, "Failed to forward message to container");
					}
				});
				containerWs.addEventListener("message", async (event) => {
					this.renewActivityTimeout();
					try {
						const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
						server.send(data);
					} catch {
						containerWs.close(1011, "Failed to forward message to client");
					}
				});
				server.addEventListener("close", (event) => {
					settleInflight();
					const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
					containerWs.close(code, event.reason);
				});
				containerWs.addEventListener("close", (event) => {
					settleInflight();
					const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
					server.close(code, event.reason);
				});
				server.addEventListener("error", () => {
					settleInflight();
					containerWs.close(1011, "Client WebSocket error");
				});
				containerWs.addEventListener("error", () => {
					settleInflight();
					server.close(1011, "Container WebSocket error");
				});
				return new Response(null, {
					status: res.status,
					webSocket: client,
					headers: res.headers
				});
			}
			if (res.body !== null) {
				const { readable, writable } = new IdentityTransformStream();
				res.body?.pipeTo(writable).finally(() => {
					this.decrementInflight();
				});
				return new Response(readable, res);
			}
			this.decrementInflight();
			return res;
		} catch (e) {
			this.decrementInflight();
			if (!(e instanceof Error)) throw e;
			if (e.message.includes("Network connection lost.")) return new Response("Container suddenly disconnected, try again", { status: 500 });
			console.error(`Error proxying request to container ${this.ctx.id}:`, e);
			return new Response(`Error proxying request to container: ${e instanceof Error ? e.message : String(e)}`, { status: 500 });
		}
	}
	/**
	*
	* Fetch handler on the Container class.
	* By default this forwards all requests to the container by calling `containerFetch`.
	* Use `switchPort` to specify which port on the container to target, or this will use `defaultPort`.
	* @param request The request to handle
	*/
	async fetch(request) {
		if (this.defaultPort === void 0 && !request.headers.has("cf-container-target-port")) throw new Error("No port configured for this container. Set the `defaultPort` in your Container subclass, or specify a port with `container.fetch(switchPort(request, port))`.");
		let portValue = this.defaultPort;
		if (request.headers.has("cf-container-target-port")) {
			const portFromHeaders = parseInt(request.headers.get("cf-container-target-port") ?? "");
			if (isNaN(portFromHeaders)) throw new Error("port value from switchPort is not a number");
			else portValue = portFromHeaders;
		}
		return await this.containerFetch(request, portValue);
	}
	container;
	onStopCalled = false;
	state;
	monitor;
	startInFlight;
	monitoredPromise;
	sleepAfterMs = 0;
	inflightRequests = 0;
	outboundByHostOverrides = {};
	outboundHandlerOverride;
	allowedHostsOverride;
	deniedHostsOverride;
	hasInterceptAllRegistration = false;
	/**
	* Validates that a method name exists in the outboundHandlers registry for this class.
	* @throws Error if the method name is not found
	*/
	validateOutboundHandlerMethodName(methodName) {
		const handlers = outboundHandlersRegistry.get(this.constructor.name);
		if (!handlers || !(methodName in handlers)) throw new Error(`Outbound handler method '${methodName}' not found in outboundHandlers for ${this.constructor.name}`);
	}
	get effectiveAllowedHosts() {
		return this.allowedHostsOverride ?? this.allowedHosts;
	}
	get effectiveDeniedHosts() {
		return this.deniedHostsOverride ?? this.deniedHosts;
	}
	getOutboundConfiguration() {
		return {
			outboundByHostOverrides: Object.keys(this.outboundByHostOverrides).length > 0 ? this.outboundByHostOverrides : void 0,
			outboundHandlerOverride: this.outboundHandlerOverride,
			allowedHosts: this.effectiveAllowedHosts,
			deniedHosts: this.effectiveDeniedHosts,
			hasInterceptAllRegistration: this.hasInterceptAllRegistration || void 0
		};
	}
	persistOutboundConfiguration(configuration) {
		this.ctx.storage.kv.put(OUTBOUND_CONFIGURATION_KEY, {
			...configuration,
			allowedHosts: this.allowedHostsOverride,
			deniedHosts: this.deniedHostsOverride
		});
	}
	restoreOutboundConfiguration() {
		const configuration = this.ctx.storage.kv.get(OUTBOUND_CONFIGURATION_KEY);
		if (!configuration) return;
		this.outboundHandlerOverride = void 0;
		if (configuration.outboundHandlerOverride !== void 0) try {
			this.validateOutboundHandlerMethodName(configuration.outboundHandlerOverride.method);
			this.outboundHandlerOverride = configuration.outboundHandlerOverride;
		} catch (error) {
			console.warn("Ignoring invalid persisted outbound handler override:", error);
		}
		this.outboundByHostOverrides = {};
		for (const [hostname, override] of Object.entries(configuration.outboundByHostOverrides ?? {})) try {
			this.validateOutboundHandlerMethodName(override.method);
			this.outboundByHostOverrides[hostname] = override;
		} catch (error) {
			console.warn(`Ignoring invalid persisted outbound override for ${hostname}:`, error);
		}
		this.hasInterceptAllRegistration = configuration.hasInterceptAllRegistration === true;
		if (configuration.allowedHosts) this.allowedHostsOverride = configuration.allowedHosts;
		if (configuration.deniedHosts) this.deniedHostsOverride = configuration.deniedHosts;
		return this.getOutboundConfiguration();
	}
	/**
	* Returns true if a catch-all outbound HTTP interception is needed.
	* This is the case when a static `outbound` handler or a runtime
	* `outboundHandlerOverride` (catch-all) is configured.
	* When false, we only intercept specific hosts to avoid overhead.
	*/
	needsCatchAllInterception() {
		return this.constructor.outbound !== void 0 || this.outboundHandlerOverride !== void 0;
	}
	hasMutableOutboundConfiguration() {
		return Object.keys(this.outboundByHostOverrides).length > 0 || this.allowedHostsOverride !== void 0 || this.deniedHostsOverride !== void 0;
	}
	shouldInterceptAllOutbound() {
		return this.hasInterceptAllRegistration || this.needsCatchAllInterception() || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0 || this.hasMutableOutboundConfiguration();
	}
	getStaticOutboundByHostKeys() {
		const ctor = this.constructor;
		return ctor.outboundByHost ? Object.keys(ctor.outboundByHost) : [];
	}
	/**
	* Collects all hostnames that need per-host outbound interception.
	* This path is only used for the narrow optimized case where outbound
	* handling is static and host-specific.
	*/
	getHostsToIntercept() {
		const hosts = /* @__PURE__ */ new Set();
		const ctor = this.constructor;
		if (ctor.outboundByHost) for (const hostname of Object.keys(ctor.outboundByHost)) hosts.add(hostname);
		for (const hostname of Object.keys(this.outboundByHostOverrides)) hosts.add(hostname);
		return [...hosts];
	}
	async refreshOutboundInterception() {
		if (!this.usingInterception) return;
		this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
		await this.applyOutboundInterceptionPromise;
	}
	/**
	* Applies (or re-applies) outbound HTTP interception with the current
	* default registries + runtime overrides passed through ContainerProxy props.
	*
	* Uses per-host interception only for static host-specific outbound handlers.
	* As soon as the config needs to evaluate all hosts (catch-all outbound,
	* allow/deny lists, or runtime-mutated outbound config), we promote the
	* container to intercept-all and keep it there until the instance restarts.
	*
	* When `interceptHttps` is enabled, also applies HTTPS interception:
	* - Intercept-all mode: `interceptOutboundHttps('*', ...)` for all HTTPS traffic
	* - Per-host mode: `interceptOutboundHttps(host, ...)` for each known host
	*/
	async applyOutboundInterception() {
		const ctx = this.ctx;
		if (ctx.exports === void 0) throw new Error("ctx.exports is undefined, please try to update your compatibility date or export ContainerProxy from the containers package in your worker entrypoint");
		if (ctx.exports.ContainerProxy === void 0) throw new Error("ctx.exports.ContainerProxy is undefined, export ContainerProxy from the containers package in your worker entrypoint");
		const interceptAll = this.shouldInterceptAllOutbound();
		if (interceptAll) this.hasInterceptAllRegistration = interceptAll;
		const outboundConfiguration = this.getOutboundConfiguration();
		this.persistOutboundConfiguration(outboundConfiguration);
		const hosts = this.getHostsToIntercept();
		const props = {
			enableInternet: this.enableInternet,
			containerId: this.ctx.id.toString(),
			className: this.constructor.name,
			outboundByHostOverrides: outboundConfiguration.outboundByHostOverrides,
			outboundHandlerOverride: outboundConfiguration.outboundHandlerOverride,
			allowedHosts: outboundConfiguration.allowedHosts,
			deniedHosts: outboundConfiguration.deniedHosts,
			interceptAll
		};
		const fetcher = ctx.exports.ContainerProxy({ props });
		if (interceptAll) {
			for (const host of this.getStaticOutboundByHostKeys()) {
				await this.container.interceptOutboundHttp(host, fetcher);
				if (this.interceptHttps) await this.container.interceptOutboundHttps(host, fetcher);
			}
			if (this.interceptHttps) await this.container.interceptOutboundHttps("*", fetcher);
			await this.container.interceptAllOutboundHttp(fetcher);
		} else for (const host of hosts) {
			await this.container.interceptOutboundHttp(host, fetcher);
			if (this.interceptHttps) await this.container.interceptOutboundHttps(host, fetcher);
		}
	}
	/**
	* Execute SQL queries against the Container's database
	*/
	sql(strings, ...values) {
		const query = strings.reduce((acc, str, i) => acc + str + (i < values.length ? "?" : ""), "");
		return [...this.ctx.storage.sql.exec(query, ...values)];
	}
	requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam) {
		let request;
		let port;
		if (requestOrUrl instanceof Request) {
			request = requestOrUrl;
			port = typeof portOrInit === "number" ? portOrInit : void 0;
		} else {
			const url = typeof requestOrUrl === "string" ? requestOrUrl : requestOrUrl.toString();
			const init = typeof portOrInit === "number" ? {} : portOrInit || {};
			port = typeof portOrInit === "number" ? portOrInit : typeof portParam === "number" ? portParam : void 0;
			request = new Request(url, init);
		}
		port ??= this.defaultPort;
		if (port === void 0) throw new Error("No port specified for container fetch. Set defaultPort or specify a port parameter.");
		return {
			request,
			port
		};
	}
	/**
	*
	* The method prioritizes port sources in this order:
	* 1. Ports specified directly in the method call
	* 2. `requiredPorts` class property (if set)
	* 3. `defaultPort` (if neither of the above is specified)
	* 4. Falls back to port 33 if none of the above are set
	*/
	async getPortsToCheck(overridePorts) {
		if (overridePorts !== void 0) return Array.isArray(overridePorts) ? overridePorts : [overridePorts];
		if (this.requiredPorts && this.requiredPorts.length > 0) return [...this.requiredPorts];
		return [this.defaultPort ?? FALLBACK_PORT_TO_CHECK];
	}
	/**
	* Tries to start a container if it's not already running
	* Returns the number of tries used
	*/
	async startContainerIfNotRunning(waitOptions, options) {
		if (this.startInFlight) return this.startInFlight;
		if (this.container.running) {
			if (!this.monitor) this.monitor = this.container.monitor();
			return 0;
		}
		const startPromise = this.doStartContainer(waitOptions, options);
		this.startInFlight = startPromise;
		try {
			return await startPromise;
		} finally {
			if (this.startInFlight === startPromise) this.startInFlight = void 0;
		}
	}
	async doStartContainer(waitOptions, options) {
		const abortedSignal = new Promise((res) => {
			waitOptions.signal?.addEventListener("abort", () => {
				res(true);
			});
		});
		const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
		const totalTries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval);
		for (let tries = 0; tries < totalTries; tries++) {
			const envVars = options?.envVars ?? this.envVars;
			const entrypoint = options?.entrypoint ?? this.entrypoint;
			const enableInternet = options?.enableInternet ?? this.enableInternet;
			const labels = options?.labels ?? this.labels;
			const startConfig = { enableInternet };
			if (envVars && Object.keys(envVars).length > 0) startConfig.env = envVars;
			if (entrypoint) startConfig.entrypoint = entrypoint;
			if (labels && Object.keys(labels).length > 0) startConfig.labels = labels;
			this.renewActivityTimeout();
			const handleError = async () => {
				const err = await this.monitor?.catch((err) => err);
				if (typeof err === "number") {
					const toThrow = /* @__PURE__ */ new Error(`Container exited before we could determine the container health, exit code: ${err}`);
					await this.state.setStoppedWithCode(err);
					this.monitor = void 0;
					try {
						await this.onError(toThrow);
					} catch {}
					throw toThrow;
				} else if (!isNoInstanceError(err)) {
					await this.state.setStopped();
					this.monitor = void 0;
					try {
						await this.onError(err);
					} catch {}
					throw err;
				}
			};
			if (tries > 0 && !this.container.running) await handleError();
			await this.scheduleNextAlarm();
			if (!this.container.running) {
				await this.refreshOutboundInterception();
				this.container.start(startConfig);
				this.monitor = this.container.monitor();
				await this.state.setRunning();
			} else await this.scheduleNextAlarm();
			this.renewActivityTimeout();
			const port = this.container.getTcpPort(waitOptions.portToCheck);
			try {
				const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
				await port.fetch("http://containerstarthealthcheck", { signal: combinedSignal });
				return tries;
			} catch (error) {
				if (isNotListeningError(error) && this.container.running) return tries;
				if (!this.container.running && isNotListeningError(error)) await handleError();
				await Promise.any([new Promise((res) => setTimeout(res, waitOptions.waitInterval)), abortedSignal]);
				if (waitOptions.signal?.aborted) throw new Error("Aborted waiting for container to start as we received a cancellation signal", { cause: error });
				if (totalTries === tries + 1) {
					if (error instanceof Error && error.message.includes("Network connection lost")) this.ctx.abort();
					await handleError();
					await this.state.setStopped();
					this.monitor = void 0;
					throw new Error(NO_CONTAINER_INSTANCE_ERROR, { cause: error });
				}
				continue;
			}
		}
		throw new Error(`Container did not start after ${totalTries * pollInterval}ms`);
	}
	setupMonitorCallbacks() {
		const monitor = this.monitor;
		if (!monitor || this.monitoredPromise === monitor) return;
		this.monitoredPromise = monitor;
		monitor.then(async () => {
			await this.ctx.blockConcurrencyWhile(async () => {
				if (this.monitor === monitor) await this.state.setStoppedWithCode(0);
			});
		}).catch(async (error) => {
			if (this.monitor !== monitor) return;
			if (isNoInstanceError(error)) {
				await this.ctx.blockConcurrencyWhile(async () => {
					if (this.monitor === monitor) await this.state.setStopped();
				});
				return;
			}
			const exitCode = getExitCodeFromError(error);
			if (exitCode !== null) {
				await this.ctx.blockConcurrencyWhile(async () => {
					if (this.monitor === monitor) await this.state.setStoppedWithCode(exitCode);
				});
				return;
			}
			await this.ctx.blockConcurrencyWhile(async () => {
				if (this.monitor === monitor) await this.state.setStopped();
			});
			if (this.monitor !== monitor) return;
			try {
				await this.onError(error);
			} catch {}
		}).finally(() => {
			if (this.monitor !== monitor) return;
			this.monitoredPromise = void 0;
			this.monitor = void 0;
			if (this.timeout) {
				if (this.resolve) this.resolve();
				clearTimeout(this.timeout);
			}
		});
	}
	deleteSchedules(name) {
		this.sql`DELETE FROM container_schedules WHERE callback = ${name}`;
	}
	/**
	* Method called when an alarm fires
	* Executes any scheduled tasks that are due
	*/
	async alarm(alarmProps) {
		if (alarmProps !== void 0 && alarmProps.isRetry && alarmProps.retryCount > MAX_ALARM_RETRIES) {
			if ((Number(this.sql`SELECT COUNT(*) as count FROM container_schedules`[0]?.count) || 0) > 0 || this.container.running) await this.scheduleNextAlarm();
			return;
		}
		const prevAlarm = Date.now();
		await this.ctx.storage.setAlarm(prevAlarm);
		await this.ctx.storage.sync();
		const result = this.sql`
         SELECT * FROM container_schedules;
       `;
		let minTime = Date.now() + 18e4;
		const now = Date.now() / 1e3;
		for (const row of result) {
			if (row.time > now) continue;
			const callback = this[row.callback];
			if (!callback || typeof callback !== "function") {
				console.error(`Callback ${row.callback} not found or is not a function`);
				continue;
			}
			const schedule = this.getSchedule(row.id);
			try {
				const payload = row.payload ? JSON.parse(row.payload) : void 0;
				await callback.call(this, payload, await schedule);
			} catch (e) {
				console.error(`Error executing scheduled callback "${row.callback}":`, e);
			}
			this.sql`DELETE FROM container_schedules WHERE id = ${row.id}`;
		}
		const resultForMinTime = this.sql`
         SELECT * FROM container_schedules;
       `;
		const minTimeFromSchedules = Math.min(...resultForMinTime.map((r) => r.time * 1e3));
		if (!this.container.running) {
			await this.syncPendingStoppedEvents();
			if (resultForMinTime.length == 0) await this.ctx.storage.deleteAlarm();
			else await this.ctx.storage.setAlarm(minTimeFromSchedules);
			return;
		}
		if (this.isActivityExpired()) {
			await this.onActivityExpired();
			this.renewActivityTimeout();
			return;
		}
		minTime = Math.min(minTimeFromSchedules, minTime, this.sleepAfterMs);
		const timeout = Math.max(0, minTime - Date.now());
		await new Promise((resolve) => {
			this.resolve = resolve;
			if (!this.container.running) {
				resolve();
				return;
			}
			this.timeout = setTimeout(() => {
				resolve();
			}, timeout);
		});
		await this.ctx.storage.setAlarm(Date.now());
	}
	timeout;
	resolve;
	async syncPendingStoppedEvents() {
		const state = await this.state.getState();
		if (!this.container.running && (state.status === "healthy" || state.status === "running")) {
			await this.callOnStop({
				exitCode: 0,
				reason: "exit"
			}, state);
			return;
		}
		if (!this.container.running && state.status === "stopped_with_code") {
			await this.callOnStop({
				exitCode: state.exitCode ?? 0,
				reason: "exit"
			}, state);
			return;
		}
	}
	async callOnStop(onStopParams, stateBeforeOnStop) {
		if (this.onStopCalled) return;
		this.onStopCalled = true;
		const promise = this.onStop(onStopParams);
		if (promise instanceof Promise) await promise.finally(() => {
			this.onStopCalled = false;
		});
		else this.onStopCalled = false;
		await this.state.setStoppedIfUnchanged(stateBeforeOnStop);
	}
	/**
	* Schedule the next alarm based on upcoming tasks
	*/
	async scheduleNextAlarm(ms = 1e3) {
		const nextTime = ms + Date.now();
		if (this.timeout) {
			if (this.resolve) this.resolve();
			clearTimeout(this.timeout);
		}
		await this.ctx.storage.setAlarm(nextTime);
		await this.ctx.storage.sync();
	}
	async listSchedules(name) {
		const result = this.sql`
      SELECT * FROM container_schedules WHERE callback = ${name} LIMIT 1
    `;
		if (!result || result.length === 0) return [];
		return result.map(this.toSchedule);
	}
	toSchedule(schedule) {
		let payload;
		try {
			payload = JSON.parse(schedule.payload);
		} catch (e) {
			console.error(`Error parsing payload for schedule ${schedule.id}:`, e);
			payload = void 0;
		}
		if (schedule.type === "delayed") return {
			taskId: schedule.id,
			callback: schedule.callback,
			payload,
			type: "delayed",
			time: schedule.time,
			delayInSeconds: schedule.delayInSeconds
		};
		return {
			taskId: schedule.id,
			callback: schedule.callback,
			payload,
			type: "scheduled",
			time: schedule.time
		};
	}
	/**
	* Get a scheduled task by ID
	* @template T Type of the payload data
	* @param id ID of the scheduled task
	* @returns The Schedule object or undefined if not found
	*/
	async getSchedule(id) {
		const result = this.sql`
      SELECT * FROM container_schedules WHERE id = ${id} LIMIT 1
    `;
		if (!result || result.length === 0) return;
		const schedule = result[0];
		return this.toSchedule(schedule);
	}
	isActivityExpired() {
		if (this.inflightRequests > 0) {
			this.renewActivityTimeout();
			return false;
		}
		return this.sleepAfterMs <= Date.now();
	}
};
// node_modules/@cloudflare/containers/dist/lib/utils.js
var singletonContainerId = "cf-singleton-container";
/**
* Get a container stub
* @param binding The Container's Durable Object binding
* @param name The name of the instance to get, uses 'cf-singleton-container' by default
* @returns A container stub ready to handle requests
*/
function getContainer(binding, name = singletonContainerId) {
	const objectId = binding.idFromName(name);
	return binding.get(objectId);
}
/**
* Return a request with the port target set correctly
* You can use this method when you have to use `fetch` and not `containerFetch` with as it's a JSRPC method and it
* comes with some consequences like not being able to pass WebSockets.
*
* @example container.fetch(switchPort(request, 8090));
*/
function switchPort(request, port) {
	const headers = new Headers(request.headers);
	headers.set("cf-container-target-port", port.toString());
	return new Request(request, { headers });
}
// node_modules/aws4fetch/dist/aws4fetch.esm.mjs
/**
* @license MIT <https://opensource.org/licenses/MIT>
* @copyright Michael Hart 2024
*/
var encoder = new TextEncoder();
var HOST_SERVICES = {
	appstream2: "appstream",
	cloudhsmv2: "cloudhsm",
	email: "ses",
	marketplace: "aws-marketplace",
	mobile: "AWSMobileHubService",
	pinpoint: "mobiletargeting",
	queue: "sqs",
	"git-codecommit": "codecommit",
	"mturk-requester-sandbox": "mturk-requester",
	"personalize-runtime": "personalize"
};
var UNSIGNABLE_HEADERS = /* @__PURE__ */ new Set([
	"authorization",
	"content-type",
	"content-length",
	"user-agent",
	"presigned-expires",
	"expect",
	"x-amzn-trace-id",
	"range",
	"connection"
]);
var AwsClient = class {
	constructor({ accessKeyId, secretAccessKey, sessionToken, service, region, cache, retries, initRetryMs }) {
		if (accessKeyId == null) throw new TypeError("accessKeyId is a required option");
		if (secretAccessKey == null) throw new TypeError("secretAccessKey is a required option");
		this.accessKeyId = accessKeyId;
		this.secretAccessKey = secretAccessKey;
		this.sessionToken = sessionToken;
		this.service = service;
		this.region = region;
		this.cache = cache || /* @__PURE__ */ new Map();
		this.retries = retries != null ? retries : 10;
		this.initRetryMs = initRetryMs || 50;
	}
	async sign(input, init) {
		if (input instanceof Request) {
			const { method, url, headers, body } = input;
			init = Object.assign({
				method,
				url,
				headers
			}, init);
			if (init.body == null && headers.has("Content-Type")) init.body = body != null && headers.has("X-Amz-Content-Sha256") ? body : await input.clone().arrayBuffer();
			input = url;
		}
		const signer = new AwsV4Signer(Object.assign({ url: input.toString() }, init, this, init && init.aws));
		const signed = Object.assign({}, init, await signer.sign());
		delete signed.aws;
		try {
			return new Request(signed.url.toString(), signed);
		} catch (e) {
			if (e instanceof TypeError) return new Request(signed.url.toString(), Object.assign({ duplex: "half" }, signed));
			throw e;
		}
	}
	async fetch(input, init) {
		for (let i = 0; i <= this.retries; i++) {
			const fetched = fetch(await this.sign(input, init));
			if (i === this.retries) return fetched;
			const res = await fetched;
			if (res.status < 500 && res.status !== 429) return res;
			await new Promise((resolve) => setTimeout(resolve, Math.random() * this.initRetryMs * Math.pow(2, i)));
		}
		throw new Error("An unknown error occurred, ensure retries is not negative");
	}
};
var AwsV4Signer = class {
	constructor({ method, url, headers, body, accessKeyId, secretAccessKey, sessionToken, service, region, cache, datetime, signQuery, appendSessionToken, allHeaders, singleEncode }) {
		if (url == null) throw new TypeError("url is a required option");
		if (accessKeyId == null) throw new TypeError("accessKeyId is a required option");
		if (secretAccessKey == null) throw new TypeError("secretAccessKey is a required option");
		this.method = method || (body ? "POST" : "GET");
		this.url = new URL(url);
		this.headers = new Headers(headers || {});
		this.body = body;
		this.accessKeyId = accessKeyId;
		this.secretAccessKey = secretAccessKey;
		this.sessionToken = sessionToken;
		let guessedService, guessedRegion;
		if (!service || !region) [guessedService, guessedRegion] = guessServiceRegion(this.url, this.headers);
		this.service = service || guessedService || "";
		this.region = region || guessedRegion || "us-east-1";
		this.cache = cache || /* @__PURE__ */ new Map();
		this.datetime = datetime || (/* @__PURE__ */ new Date()).toISOString().replace(/[:-]|\.\d{3}/g, "");
		this.signQuery = signQuery;
		this.appendSessionToken = appendSessionToken || this.service === "iotdevicegateway";
		this.headers.delete("Host");
		if (this.service === "s3" && !this.signQuery && !this.headers.has("X-Amz-Content-Sha256")) this.headers.set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD");
		const params = this.signQuery ? this.url.searchParams : this.headers;
		params.set("X-Amz-Date", this.datetime);
		if (this.sessionToken && !this.appendSessionToken) params.set("X-Amz-Security-Token", this.sessionToken);
		this.signableHeaders = ["host", ...this.headers.keys()].filter((header) => allHeaders || !UNSIGNABLE_HEADERS.has(header)).sort();
		this.signedHeaders = this.signableHeaders.join(";");
		this.canonicalHeaders = this.signableHeaders.map((header) => header + ":" + (header === "host" ? this.url.host : (this.headers.get(header) || "").replace(/\s+/g, " "))).join("\n");
		this.credentialString = [
			this.datetime.slice(0, 8),
			this.region,
			this.service,
			"aws4_request"
		].join("/");
		if (this.signQuery) {
			if (this.service === "s3" && !params.has("X-Amz-Expires")) params.set("X-Amz-Expires", "86400");
			params.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
			params.set("X-Amz-Credential", this.accessKeyId + "/" + this.credentialString);
			params.set("X-Amz-SignedHeaders", this.signedHeaders);
		}
		if (this.service === "s3") try {
			this.encodedPath = decodeURIComponent(this.url.pathname.replace(/\+/g, " "));
		} catch (e) {
			this.encodedPath = this.url.pathname;
		}
		else this.encodedPath = this.url.pathname.replace(/\/+/g, "/");
		if (!singleEncode) this.encodedPath = encodeURIComponent(this.encodedPath).replace(/%2F/g, "/");
		this.encodedPath = encodeRfc3986(this.encodedPath);
		const seenKeys = /* @__PURE__ */ new Set();
		this.encodedSearch = [...this.url.searchParams].filter(([k]) => {
			if (!k) return false;
			if (this.service === "s3") {
				if (seenKeys.has(k)) return false;
				seenKeys.add(k);
			}
			return true;
		}).map((pair) => pair.map((p) => encodeRfc3986(encodeURIComponent(p)))).sort(([k1, v1], [k2, v2]) => k1 < k2 ? -1 : k1 > k2 ? 1 : v1 < v2 ? -1 : v1 > v2 ? 1 : 0).map((pair) => pair.join("=")).join("&");
	}
	async sign() {
		if (this.signQuery) {
			this.url.searchParams.set("X-Amz-Signature", await this.signature());
			if (this.sessionToken && this.appendSessionToken) this.url.searchParams.set("X-Amz-Security-Token", this.sessionToken);
		} else this.headers.set("Authorization", await this.authHeader());
		return {
			method: this.method,
			url: this.url,
			headers: this.headers,
			body: this.body
		};
	}
	async authHeader() {
		return [
			"AWS4-HMAC-SHA256 Credential=" + this.accessKeyId + "/" + this.credentialString,
			"SignedHeaders=" + this.signedHeaders,
			"Signature=" + await this.signature()
		].join(", ");
	}
	async signature() {
		const date = this.datetime.slice(0, 8);
		const cacheKey = [
			this.secretAccessKey,
			date,
			this.region,
			this.service
		].join();
		let kCredentials = this.cache.get(cacheKey);
		if (!kCredentials) {
			kCredentials = await hmac(await hmac(await hmac(await hmac("AWS4" + this.secretAccessKey, date), this.region), this.service), "aws4_request");
			this.cache.set(cacheKey, kCredentials);
		}
		return buf2hex(await hmac(kCredentials, await this.stringToSign()));
	}
	async stringToSign() {
		return [
			"AWS4-HMAC-SHA256",
			this.datetime,
			this.credentialString,
			buf2hex(await hash(await this.canonicalString()))
		].join("\n");
	}
	async canonicalString() {
		return [
			this.method.toUpperCase(),
			this.encodedPath,
			this.encodedSearch,
			this.canonicalHeaders + "\n",
			this.signedHeaders,
			await this.hexBodyHash()
		].join("\n");
	}
	async hexBodyHash() {
		let hashHeader = this.headers.get("X-Amz-Content-Sha256") || (this.service === "s3" && this.signQuery ? "UNSIGNED-PAYLOAD" : null);
		if (hashHeader == null) {
			if (this.body && typeof this.body !== "string" && !("byteLength" in this.body)) throw new Error("body must be a string, ArrayBuffer or ArrayBufferView, unless you include the X-Amz-Content-Sha256 header");
			hashHeader = buf2hex(await hash(this.body || ""));
		}
		return hashHeader;
	}
};
async function hmac(key, string) {
	const cryptoKey = await crypto.subtle.importKey("raw", typeof key === "string" ? encoder.encode(key) : key, {
		name: "HMAC",
		hash: { name: "SHA-256" }
	}, false, ["sign"]);
	return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(string));
}
async function hash(content) {
	return crypto.subtle.digest("SHA-256", typeof content === "string" ? encoder.encode(content) : content);
}
var HEX_CHARS = [
	"0",
	"1",
	"2",
	"3",
	"4",
	"5",
	"6",
	"7",
	"8",
	"9",
	"a",
	"b",
	"c",
	"d",
	"e",
	"f"
];
function buf2hex(arrayBuffer) {
	const buffer = new Uint8Array(arrayBuffer);
	let out = "";
	for (let idx = 0; idx < buffer.length; idx++) {
		const n = buffer[idx];
		out += HEX_CHARS[n >>> 4 & 15];
		out += HEX_CHARS[n & 15];
	}
	return out;
}
function encodeRfc3986(urlEncodedStr) {
	return urlEncodedStr.replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}
function guessServiceRegion(url, headers) {
	const { hostname, pathname } = url;
	if (hostname.endsWith(".on.aws")) {
		const match = hostname.match(/^[^.]{1,63}\.lambda-url\.([^.]{1,63})\.on\.aws$/);
		return match != null ? ["lambda", match[1] || ""] : ["", ""];
	}
	if (hostname.endsWith(".r2.cloudflarestorage.com")) return ["s3", "auto"];
	if (hostname.endsWith(".backblazeb2.com")) {
		const match = hostname.match(/^(?:[^.]{1,63}\.)?s3\.([^.]{1,63})\.backblazeb2\.com$/);
		return match != null ? ["s3", match[1] || ""] : ["", ""];
	}
	const match = hostname.replace("dualstack.", "").match(/([^.]{1,63})\.(?:([^.]{0,63})\.)?amazonaws\.com(?:\.cn)?$/);
	let service = match && match[1] || "";
	let region = match && match[2];
	if (region === "us-gov") region = "us-gov-west-1";
	else if (region === "s3" || region === "s3-accelerate") {
		region = "us-east-1";
		service = "s3";
	} else if (service === "iot") {
		if (hostname.startsWith("iot.")) service = "execute-api";
		else if (hostname.startsWith("data.jobs.iot.")) service = "iot-jobs-data";
		else service = pathname === "/mqtt" ? "iotdevicegateway" : "iotdata";
	} else if (service === "autoscaling") {
		const targetPrefix = (headers.get("X-Amz-Target") || "").split(".")[0];
		if (targetPrefix === "AnyScaleFrontendService") service = "application-autoscaling";
		else if (targetPrefix === "AnyScaleScalingPlannerFrontendService") service = "autoscaling-plans";
	} else if (region == null && service.startsWith("s3-")) {
		region = service.slice(3).replace(/^fips-|^external-1/, "");
		service = "s3";
	} else if (service.endsWith("-fips")) service = service.slice(0, -5);
	else if (region && /-\d$/.test(service) && !/-\d$/.test(region)) [service, region] = [region, service];
	return [HOST_SERVICES[service] || service, region || ""];
}
// node_modules/capnweb/dist/index-workers.js
var WORKERS_MODULE_SYMBOL = /* @__PURE__ */ Symbol("workers-module");
globalThis[WORKERS_MODULE_SYMBOL] = cfw;
if (!Symbol.dispose) Symbol.dispose = /* @__PURE__ */ Symbol.for("dispose");
if (!Symbol.asyncDispose) Symbol.asyncDispose = /* @__PURE__ */ Symbol.for("asyncDispose");
if (!Promise.withResolvers) Promise.withResolvers = function() {
	let resolve;
	let reject;
	return {
		promise: new Promise((res, rej) => {
			resolve = res;
			reject = rej;
		}),
		resolve,
		reject
	};
};
var workersModule = globalThis[WORKERS_MODULE_SYMBOL];
var RpcTarget$1 = workersModule ? workersModule.RpcTarget : class {};
var AsyncFunction = (async function() {}).constructor;
var BUFFER_PROTOTYPE = typeof Buffer !== "undefined" ? Buffer.prototype : void 0;
function typeForRpc(value) {
	switch (typeof value) {
		case "boolean":
		case "number":
		case "string": return "primitive";
		case "undefined": return "undefined";
		case "object":
		case "function": break;
		case "bigint": return "bigint";
		default: return "unsupported";
	}
	if (value === null) return "primitive";
	let prototype = Object.getPrototypeOf(value);
	switch (prototype) {
		case Object.prototype: return "object";
		case Function.prototype:
		case AsyncFunction.prototype: return "function";
		case Array.prototype: return "array";
		case Date.prototype: return "date";
		case Uint8Array.prototype:
		case BUFFER_PROTOTYPE: return "bytes";
		case WritableStream.prototype: return "writable";
		case ReadableStream.prototype: return "readable";
		case Headers.prototype: return "headers";
		case Request.prototype: return "request";
		case Response.prototype: return "response";
		case Blob.prototype: return "blob";
		case RpcStub.prototype: return "stub";
		case RpcPromise.prototype: return "rpc-promise";
		default:
			if (workersModule) {
				if (prototype == workersModule.RpcStub.prototype || value instanceof workersModule.ServiceStub) return "rpc-target";
				else if (prototype == workersModule.RpcPromise.prototype || prototype == workersModule.RpcProperty.prototype) return "rpc-thenable";
			}
			if (value instanceof RpcTarget$1) return "rpc-target";
			if (value instanceof Error) return "error";
			return "unsupported";
	}
}
function mapNotLoaded() {
	throw new Error("RPC map() implementation was not loaded.");
}
var mapImpl = {
	applyMap: mapNotLoaded,
	sendMap: mapNotLoaded
};
function streamNotLoaded() {
	throw new Error("Stream implementation was not loaded.");
}
var streamImpl = {
	createWritableStreamHook: streamNotLoaded,
	createWritableStreamFromHook: streamNotLoaded,
	createReadableStreamHook: streamNotLoaded
};
var StubHook = class {
	stream(path, args) {
		let pulled = this.call(path, args).pull();
		let promise;
		if (pulled instanceof Promise) promise = pulled.then((p) => {
			p.dispose();
		});
		else {
			pulled.dispose();
			promise = Promise.resolve();
		}
		return { promise };
	}
};
var ErrorStubHook = class extends StubHook {
	constructor(error) {
		super();
		this.error = error;
	}
	call(path, args) {
		return this;
	}
	map(path, captures, instructions) {
		return this;
	}
	get(path) {
		return this;
	}
	dup() {
		return this;
	}
	pull() {
		return Promise.reject(this.error);
	}
	ignoreUnhandledRejections() {}
	dispose() {}
	onBroken(callback) {
		try {
			callback(this.error);
		} catch (err) {
			Promise.resolve(err);
		}
	}
};
var DISPOSED_HOOK = new ErrorStubHook(/* @__PURE__ */ new Error("Attempted to use RPC stub after it has been disposed."));
var doCall = (hook, path, params) => {
	return hook.call(path, params);
};
function withCallInterceptor(interceptor, callback) {
	let oldValue = doCall;
	doCall = interceptor;
	try {
		return callback();
	} finally {
		doCall = oldValue;
	}
}
var RAW_STUB = /* @__PURE__ */ Symbol("realStub");
var PROXY_HANDLERS = {
	apply(target, thisArg, argumentsList) {
		let stub = target.raw;
		return new RpcPromise(doCall(stub.hook, stub.pathIfPromise || [], RpcPayload.fromAppParams(argumentsList)), []);
	},
	get(target, prop, receiver) {
		let stub = target.raw;
		if (prop === RAW_STUB) return stub;
		else if (prop in RpcPromise.prototype) return stub[prop];
		else if (typeof prop === "string") return new RpcPromise(stub.hook, stub.pathIfPromise ? [...stub.pathIfPromise, prop] : [prop]);
		else if (prop === Symbol.dispose && (!stub.pathIfPromise || stub.pathIfPromise.length == 0)) return () => {
			stub.hook.dispose();
			stub.hook = DISPOSED_HOOK;
		};
		else return;
	},
	has(target, prop) {
		let stub = target.raw;
		if (prop === RAW_STUB) return true;
		else if (prop in RpcPromise.prototype) return prop in stub;
		else if (typeof prop === "string") return true;
		else if (prop === Symbol.dispose && (!stub.pathIfPromise || stub.pathIfPromise.length == 0)) return true;
		else return false;
	},
	construct(target, args) {
		throw new Error("An RPC stub cannot be used as a constructor.");
	},
	defineProperty(target, property, attributes) {
		throw new Error("Can't define properties on RPC stubs.");
	},
	deleteProperty(target, p) {
		throw new Error("Can't delete properties on RPC stubs.");
	},
	getOwnPropertyDescriptor(target, p) {},
	getPrototypeOf(target) {
		return Object.getPrototypeOf(target.raw);
	},
	isExtensible(target) {
		return false;
	},
	ownKeys(target) {
		return [];
	},
	preventExtensions(target) {
		return true;
	},
	set(target, p, newValue, receiver) {
		throw new Error("Can't assign properties on RPC stubs.");
	},
	setPrototypeOf(target, v) {
		throw new Error("Can't override prototype of RPC stubs.");
	}
};
var RpcStub = class _RpcStub extends RpcTarget$1 {
	constructor(hook, pathIfPromise) {
		super();
		if (!(hook instanceof StubHook)) {
			let value = hook;
			if (value instanceof RpcTarget$1 || value instanceof Function) hook = TargetStubHook.create(value, void 0);
			else hook = new PayloadStubHook(RpcPayload.fromAppReturn(value));
			if (pathIfPromise) throw new TypeError("RpcStub constructor expected one argument, received two.");
		}
		this.hook = hook;
		this.pathIfPromise = pathIfPromise;
		let func = () => {};
		func.raw = this;
		return new Proxy(func, PROXY_HANDLERS);
	}
	hook;
	pathIfPromise;
	dup() {
		let target = this[RAW_STUB];
		if (target.pathIfPromise) return new _RpcStub(target.hook.get(target.pathIfPromise));
		else return new _RpcStub(target.hook.dup());
	}
	onRpcBroken(callback) {
		this[RAW_STUB].hook.onBroken(callback);
	}
	map(func) {
		let { hook, pathIfPromise } = this[RAW_STUB];
		return mapImpl.sendMap(hook, pathIfPromise || [], func);
	}
	toString() {
		return "[object RpcStub]";
	}
};
var RpcPromise = class extends RpcStub {
	constructor(hook, pathIfPromise) {
		super(hook, pathIfPromise);
	}
	then(onfulfilled, onrejected) {
		return pullPromise(this).then(...arguments);
	}
	catch(onrejected) {
		return pullPromise(this).catch(...arguments);
	}
	finally(onfinally) {
		return pullPromise(this).finally(...arguments);
	}
	toString() {
		return "[object RpcPromise]";
	}
};
function unwrapStubTakingOwnership(stub) {
	let { hook, pathIfPromise } = stub[RAW_STUB];
	if (pathIfPromise && pathIfPromise.length > 0) return hook.get(pathIfPromise);
	else return hook;
}
function unwrapStubAndDup(stub) {
	let { hook, pathIfPromise } = stub[RAW_STUB];
	if (pathIfPromise) return hook.get(pathIfPromise);
	else return hook.dup();
}
function unwrapStubNoProperties(stub) {
	let { hook, pathIfPromise } = stub[RAW_STUB];
	if (pathIfPromise && pathIfPromise.length > 0) return;
	return hook;
}
function unwrapStubOrParent(stub) {
	return stub[RAW_STUB].hook;
}
function unwrapStubAndPath(stub) {
	return stub[RAW_STUB];
}
async function pullPromise(promise) {
	let { hook, pathIfPromise } = promise[RAW_STUB];
	if (pathIfPromise.length > 0) hook = hook.get(pathIfPromise);
	return (await hook.pull()).deliverResolve();
}
var RpcPayload = class _RpcPayload {
	constructor(value, source, hooks, promises) {
		this.value = value;
		this.source = source;
		this.hooks = hooks;
		this.promises = promises;
	}
	static fromAppParams(value) {
		return new _RpcPayload(value, "params");
	}
	static fromAppReturn(value) {
		return new _RpcPayload(value, "return");
	}
	static fromArray(array) {
		let hooks = [];
		let promises = [];
		let resultArray = [];
		for (let payload of array) {
			payload.ensureDeepCopied();
			for (let hook of payload.hooks) hooks.push(hook);
			for (let promise of payload.promises) {
				if (promise.parent === payload) promise = {
					parent: resultArray,
					property: resultArray.length,
					promise: promise.promise
				};
				promises.push(promise);
			}
			resultArray.push(payload.value);
		}
		return new _RpcPayload(resultArray, "owned", hooks, promises);
	}
	static forEvaluate(hooks, promises) {
		return new _RpcPayload(null, "owned", hooks, promises);
	}
	static deepCopyFrom(value, oldParent, owner) {
		let result = new _RpcPayload(null, "owned", [], []);
		result.value = result.deepCopy(value, oldParent, "value", result, true, owner);
		return result;
	}
	rpcTargets;
	getHookForRpcTarget(target, parent, dupStubs = true) {
		if (this.source === "params") {
			if (dupStubs) {
				let dupable = target;
				if (typeof dupable.dup === "function") target = dupable.dup();
			}
			return TargetStubHook.create(target, parent);
		} else if (this.source === "return") {
			let hook = this.rpcTargets?.get(target);
			if (hook) {
				if (dupStubs) return hook.dup();
				else {
					this.rpcTargets?.delete(target);
					return hook;
				}
			} else {
				hook = TargetStubHook.create(target, parent);
				if (dupStubs) {
					if (!this.rpcTargets) this.rpcTargets = /* @__PURE__ */ new Map();
					this.rpcTargets.set(target, hook);
					return hook.dup();
				} else return hook;
			}
		} else throw new Error("owned payload shouldn't contain raw RpcTargets");
	}
	getHookForWritableStream(stream, parent, dupStubs = true) {
		if (this.source === "params") return streamImpl.createWritableStreamHook(stream);
		else if (this.source === "return") {
			let hook = this.rpcTargets?.get(stream);
			if (hook) {
				if (dupStubs) return hook.dup();
				else {
					this.rpcTargets?.delete(stream);
					return hook;
				}
			} else {
				hook = streamImpl.createWritableStreamHook(stream);
				if (dupStubs) {
					if (!this.rpcTargets) this.rpcTargets = /* @__PURE__ */ new Map();
					this.rpcTargets.set(stream, hook);
					return hook.dup();
				} else return hook;
			}
		} else throw new Error("owned payload shouldn't contain raw WritableStreams");
	}
	getHookForReadableStream(stream, parent, dupStubs = true) {
		if (this.source === "params") return streamImpl.createReadableStreamHook(stream);
		else if (this.source === "return") {
			let hook = this.rpcTargets?.get(stream);
			if (hook) {
				if (dupStubs) return hook.dup();
				else {
					this.rpcTargets?.delete(stream);
					return hook;
				}
			} else {
				hook = streamImpl.createReadableStreamHook(stream);
				if (dupStubs) {
					if (!this.rpcTargets) this.rpcTargets = /* @__PURE__ */ new Map();
					this.rpcTargets.set(stream, hook);
					return hook.dup();
				} else return hook;
			}
		} else throw new Error("owned payload shouldn't contain raw ReadableStreams");
	}
	deepCopy(value, oldParent, property, parent, dupStubs, owner) {
		switch (typeForRpc(value)) {
			case "unsupported": return value;
			case "primitive":
			case "bigint":
			case "date":
			case "bytes":
			case "blob":
			case "error":
			case "undefined": return value;
			case "array": {
				let array = value;
				let len = array.length;
				let result = new Array(len);
				for (let i = 0; i < len; i++) result[i] = this.deepCopy(array[i], array, i, result, dupStubs, owner);
				return result;
			}
			case "object": {
				let result = {};
				let object = value;
				for (let i in object) result[i] = this.deepCopy(object[i], object, i, result, dupStubs, owner);
				return result;
			}
			case "stub":
			case "rpc-promise": {
				let stub = value;
				let hook;
				if (dupStubs) hook = unwrapStubAndDup(stub);
				else hook = unwrapStubTakingOwnership(stub);
				if (stub instanceof RpcPromise) {
					let promise = new RpcPromise(hook, []);
					this.promises.push({
						parent,
						property,
						promise
					});
					return promise;
				} else {
					this.hooks.push(hook);
					return new RpcStub(hook);
				}
			}
			case "function":
			case "rpc-target": {
				let target = value;
				let hook;
				if (owner) hook = owner.getHookForRpcTarget(target, oldParent, dupStubs);
				else hook = TargetStubHook.create(target, oldParent);
				this.hooks.push(hook);
				return new RpcStub(hook);
			}
			case "rpc-thenable": {
				let target = value;
				let promise;
				if (owner) promise = new RpcPromise(owner.getHookForRpcTarget(target, oldParent, dupStubs), []);
				else promise = new RpcPromise(TargetStubHook.create(target, oldParent), []);
				this.promises.push({
					parent,
					property,
					promise
				});
				return promise;
			}
			case "writable": {
				let stream = value;
				let hook;
				if (owner) hook = owner.getHookForWritableStream(stream, oldParent, dupStubs);
				else hook = streamImpl.createWritableStreamHook(stream);
				this.hooks.push(hook);
				return stream;
			}
			case "readable": {
				let stream = value;
				let hook;
				if (owner) hook = owner.getHookForReadableStream(stream, oldParent, dupStubs);
				else hook = streamImpl.createReadableStreamHook(stream);
				this.hooks.push(hook);
				return stream;
			}
			case "headers": return new Headers(value);
			case "request": {
				let req = value;
				if (req.body) this.deepCopy(req.body, req, "body", req, dupStubs, owner);
				return new Request(req);
			}
			case "response": {
				let resp = value;
				if (resp.body) this.deepCopy(resp.body, resp, "body", resp, dupStubs, owner);
				return new Response(resp.body, resp);
			}
			default: throw new Error("unreachable");
		}
	}
	ensureDeepCopied() {
		if (this.source !== "owned") {
			let dupStubs = this.source === "params";
			this.hooks = [];
			this.promises = [];
			try {
				this.value = this.deepCopy(this.value, void 0, "value", this, dupStubs, this);
			} catch (err) {
				this.hooks = void 0;
				this.promises = void 0;
				throw err;
			}
			this.source = "owned";
			if (this.rpcTargets && this.rpcTargets.size > 0) throw new Error("Not all rpcTargets were accounted for in deep-copy?");
			this.rpcTargets = void 0;
		}
	}
	deliverTo(parent, property, promises) {
		this.ensureDeepCopied();
		if (this.value instanceof RpcPromise) _RpcPayload.deliverRpcPromiseTo(this.value, parent, property, promises);
		else {
			parent[property] = this.value;
			for (let record of this.promises) _RpcPayload.deliverRpcPromiseTo(record.promise, record.parent, record.property, promises);
		}
	}
	static deliverRpcPromiseTo(promise, parent, property, promises) {
		let hook = unwrapStubNoProperties(promise);
		if (!hook) throw new Error("property promises should have been resolved earlier");
		let inner = hook.pull();
		if (inner instanceof _RpcPayload) inner.deliverTo(parent, property, promises);
		else promises.push(inner.then((payload) => {
			let subPromises = [];
			payload.deliverTo(parent, property, subPromises);
			if (subPromises.length > 0) return Promise.all(subPromises);
		}));
	}
	async deliverCall(func, thisArg) {
		try {
			let promises = [];
			this.deliverTo(this, "value", promises);
			if (promises.length > 0) await Promise.all(promises);
			let result = Function.prototype.apply.call(func, thisArg, this.value);
			if (result instanceof RpcPromise) return _RpcPayload.fromAppReturn(result);
			else return _RpcPayload.fromAppReturn(await result);
		} finally {
			this.dispose();
		}
	}
	async deliverResolve() {
		try {
			let promises = [];
			this.deliverTo(this, "value", promises);
			if (promises.length > 0) await Promise.all(promises);
			let result = this.value;
			if (result instanceof Object) {
				if (!(Symbol.dispose in result)) Object.defineProperty(result, Symbol.dispose, {
					value: () => this.dispose(),
					writable: true,
					enumerable: false,
					configurable: true
				});
			}
			return result;
		} catch (err) {
			this.dispose();
			throw err;
		}
	}
	dispose() {
		if (this.source === "owned") {
			this.hooks.forEach((hook) => hook.dispose());
			this.promises.forEach((promise) => promise.promise[Symbol.dispose]());
		} else if (this.source === "return") {
			this.disposeImpl(this.value, void 0);
			if (this.rpcTargets && this.rpcTargets.size > 0) throw new Error("Not all rpcTargets were accounted for in disposeImpl()?");
		}
		this.source = "owned";
		this.hooks = [];
		this.promises = [];
	}
	disposeImpl(value, parent) {
		switch (typeForRpc(value)) {
			case "unsupported":
			case "primitive":
			case "bigint":
			case "bytes":
			case "blob":
			case "date":
			case "error":
			case "undefined": return;
			case "array": {
				let array = value;
				let len = array.length;
				for (let i = 0; i < len; i++) this.disposeImpl(array[i], array);
				return;
			}
			case "object": {
				let object = value;
				for (let i in object) this.disposeImpl(object[i], object);
				return;
			}
			case "stub":
			case "rpc-promise": {
				let hook = unwrapStubNoProperties(value);
				if (hook) hook.dispose();
				return;
			}
			case "function":
			case "rpc-target": {
				let target = value;
				let hook = this.rpcTargets?.get(target);
				if (hook) {
					hook.dispose();
					this.rpcTargets.delete(target);
				} else disposeRpcTarget(target);
				return;
			}
			case "rpc-thenable": return;
			case "headers": return;
			case "request": {
				let req = value;
				if (req.body) this.disposeImpl(req.body, req);
				return;
			}
			case "response": {
				let resp = value;
				if (resp.body) this.disposeImpl(resp.body, resp);
				return;
			}
			case "writable": {
				let stream = value;
				let hook = this.rpcTargets?.get(stream);
				if (hook) this.rpcTargets.delete(stream);
				else hook = streamImpl.createWritableStreamHook(stream);
				hook.dispose();
				return;
			}
			case "readable": {
				let stream = value;
				let hook = this.rpcTargets?.get(stream);
				if (hook) this.rpcTargets.delete(stream);
				else hook = streamImpl.createReadableStreamHook(stream);
				hook.dispose();
				return;
			}
			default: return;
		}
	}
	ignoreUnhandledRejections() {
		if (this.hooks) {
			this.hooks.forEach((hook) => {
				hook.ignoreUnhandledRejections();
			});
			this.promises.forEach((promise) => unwrapStubOrParent(promise.promise).ignoreUnhandledRejections());
		} else this.ignoreUnhandledRejectionsImpl(this.value);
	}
	ignoreUnhandledRejectionsImpl(value) {
		switch (typeForRpc(value)) {
			case "unsupported":
			case "primitive":
			case "bigint":
			case "bytes":
			case "blob":
			case "date":
			case "error":
			case "undefined":
			case "function":
			case "rpc-target":
			case "writable":
			case "readable":
			case "headers":
			case "request":
			case "response": return;
			case "array": {
				let array = value;
				let len = array.length;
				for (let i = 0; i < len; i++) this.ignoreUnhandledRejectionsImpl(array[i]);
				return;
			}
			case "object": {
				let object = value;
				for (let i in object) this.ignoreUnhandledRejectionsImpl(object[i]);
				return;
			}
			case "stub":
			case "rpc-promise":
				unwrapStubOrParent(value).ignoreUnhandledRejections();
				return;
			case "rpc-thenable":
				value.then((_) => {}, (_) => {});
				return;
			default: return;
		}
	}
};
function followPath(value, parent, path, owner) {
	for (let i = 0; i < path.length; i++) {
		parent = value;
		let part = path[i];
		if (part in Object.prototype) {
			value = void 0;
			continue;
		}
		switch (typeForRpc(value)) {
			case "object":
			case "function":
				if (Object.hasOwn(value, part)) value = value[part];
				else value = void 0;
				break;
			case "array":
				if (Number.isInteger(part) && part >= 0) value = value[part];
				else value = void 0;
				break;
			case "rpc-target":
			case "rpc-thenable":
				if (Object.hasOwn(value, part)) throw new TypeError(`Attempted to access property '${part}', which is an instance property of the RpcTarget. To avoid leaking private internals, instance properties cannot be accessed over RPC. If you want to make this property available over RPC, define it as a method or getter on the class, instead of an instance property.`);
				else value = value[part];
				owner = null;
				break;
			case "stub":
			case "rpc-promise": {
				let { hook, pathIfPromise } = unwrapStubAndPath(value);
				return {
					hook,
					remainingPath: pathIfPromise ? pathIfPromise.concat(path.slice(i)) : path.slice(i)
				};
			}
			case "writable":
				value = void 0;
				break;
			case "readable":
				value = void 0;
				break;
			case "primitive":
			case "bigint":
			case "bytes":
			case "blob":
			case "date":
			case "error":
			case "headers":
			case "request":
			case "response":
				value = void 0;
				break;
			case "undefined":
				value = value[part];
				break;
			case "unsupported": if (i === 0) throw new TypeError(`RPC stub points at a non-serializable type.`);
			else {
				let prefix = path.slice(0, i).join(".");
				let remainder = path.slice(0, i).join(".");
				throw new TypeError(`'${prefix}' is not a serializable type, so property ${remainder} cannot be accessed.`);
			}
			default: throw new TypeError("unreachable");
		}
	}
	if (value instanceof RpcPromise) {
		let { hook, pathIfPromise } = unwrapStubAndPath(value);
		return {
			hook,
			remainingPath: pathIfPromise || []
		};
	}
	return {
		value,
		parent,
		owner
	};
}
var ValueStubHook = class extends StubHook {
	call(path, args) {
		try {
			let { value, owner } = this.getValue();
			let followResult = followPath(value, void 0, path, owner);
			if (followResult.hook) return followResult.hook.call(followResult.remainingPath, args);
			if (typeof followResult.value != "function") throw new TypeError(`'${path.join(".")}' is not a function.`);
			return new PromiseStubHook(args.deliverCall(followResult.value, followResult.parent).then((payload) => {
				return new PayloadStubHook(payload);
			}));
		} catch (err) {
			return new ErrorStubHook(err);
		}
	}
	map(path, captures, instructions) {
		try {
			let followResult;
			try {
				let { value, owner } = this.getValue();
				followResult = followPath(value, void 0, path, owner);
			} catch (err) {
				for (let cap of captures) cap.dispose();
				throw err;
			}
			if (followResult.hook) return followResult.hook.map(followResult.remainingPath, captures, instructions);
			return mapImpl.applyMap(followResult.value, followResult.parent, followResult.owner, captures, instructions);
		} catch (err) {
			return new ErrorStubHook(err);
		}
	}
	get(path) {
		try {
			let { value, owner } = this.getValue();
			if (path.length === 0 && owner === null) throw new Error("Can't dup an RpcTarget stub as a promise.");
			let followResult = followPath(value, void 0, path, owner);
			if (followResult.hook) return followResult.hook.get(followResult.remainingPath);
			return new PayloadStubHook(RpcPayload.deepCopyFrom(followResult.value, followResult.parent, followResult.owner));
		} catch (err) {
			return new ErrorStubHook(err);
		}
	}
};
var PayloadStubHook = class _PayloadStubHook extends ValueStubHook {
	constructor(payload) {
		super();
		this.payload = payload;
	}
	payload;
	getPayload() {
		if (this.payload) return this.payload;
		else throw new Error("Attempted to use an RPC StubHook after it was disposed.");
	}
	getValue() {
		let payload = this.getPayload();
		return {
			value: payload.value,
			owner: payload
		};
	}
	dup() {
		let thisPayload = this.getPayload();
		return new _PayloadStubHook(RpcPayload.deepCopyFrom(thisPayload.value, void 0, thisPayload));
	}
	pull() {
		return this.getPayload();
	}
	ignoreUnhandledRejections() {
		if (this.payload) this.payload.ignoreUnhandledRejections();
	}
	dispose() {
		if (this.payload) {
			this.payload.dispose();
			this.payload = void 0;
		}
	}
	onBroken(callback) {
		if (this.payload) {
			if (this.payload.value instanceof RpcStub) this.payload.value.onRpcBroken(callback);
		}
	}
};
function disposeRpcTarget(target) {
	if (Symbol.dispose in target) try {
		target[Symbol.dispose]();
	} catch (err) {
		Promise.reject(err);
	}
}
var TargetStubHook = class _TargetStubHook extends ValueStubHook {
	static create(value, parent) {
		if (typeof value !== "function") parent = void 0;
		return new _TargetStubHook(value, parent);
	}
	constructor(target, parent, dupFrom) {
		super();
		this.target = target;
		this.parent = parent;
		if (dupFrom) {
			if (dupFrom.refcount) {
				this.refcount = dupFrom.refcount;
				++this.refcount.count;
			}
		} else if (Symbol.dispose in target) this.refcount = { count: 1 };
	}
	target;
	parent;
	refcount;
	getTarget() {
		if (this.target) return this.target;
		else throw new Error("Attempted to use an RPC StubHook after it was disposed.");
	}
	getValue() {
		return {
			value: this.getTarget(),
			owner: null
		};
	}
	dup() {
		return new _TargetStubHook(this.getTarget(), this.parent, this);
	}
	pull() {
		let target = this.getTarget();
		if ("then" in target) return Promise.resolve(target).then((resolution) => {
			return RpcPayload.fromAppReturn(resolution);
		});
		else return Promise.reject(/* @__PURE__ */ new Error("Tried to resolve a non-promise stub."));
	}
	ignoreUnhandledRejections() {}
	dispose() {
		if (this.target) {
			if (this.refcount) {
				if (--this.refcount.count == 0) disposeRpcTarget(this.target);
			}
			this.target = void 0;
		}
	}
	onBroken(callback) {}
};
var PromiseStubHook = class _PromiseStubHook extends StubHook {
	promise;
	resolution;
	constructor(promise) {
		super();
		this.promise = promise.then((res) => {
			this.resolution = res;
			return res;
		});
	}
	call(path, args) {
		args.ensureDeepCopied();
		return new _PromiseStubHook(this.promise.then((hook) => hook.call(path, args)));
	}
	stream(path, args) {
		args.ensureDeepCopied();
		return { promise: this.promise.then((hook) => {
			return hook.stream(path, args).promise;
		}) };
	}
	map(path, captures, instructions) {
		return new _PromiseStubHook(this.promise.then((hook) => hook.map(path, captures, instructions), (err) => {
			for (let cap of captures) cap.dispose();
			throw err;
		}));
	}
	get(path) {
		return new _PromiseStubHook(this.promise.then((hook) => hook.get(path)));
	}
	dup() {
		if (this.resolution) return this.resolution.dup();
		else return new _PromiseStubHook(this.promise.then((hook) => hook.dup()));
	}
	pull() {
		if (this.resolution) return this.resolution.pull();
		else return this.promise.then((hook) => hook.pull());
	}
	ignoreUnhandledRejections() {
		if (this.resolution) this.resolution.ignoreUnhandledRejections();
		else this.promise.then((res) => {
			res.ignoreUnhandledRejections();
		}, (err) => {});
	}
	dispose() {
		if (this.resolution) this.resolution.dispose();
		else this.promise.then((hook) => {
			hook.dispose();
		}, (err) => {});
	}
	onBroken(callback) {
		if (this.resolution) this.resolution.onBroken(callback);
		else this.promise.then((hook) => {
			hook.onBroken(callback);
		}, callback);
	}
};
var NullExporter = class {
	exportStub(stub) {
		throw new Error("Cannot serialize RPC stubs without an RPC session.");
	}
	exportPromise(stub) {
		throw new Error("Cannot serialize RPC stubs without an RPC session.");
	}
	getImport(hook) {}
	unexport(ids) {}
	createPipe(readable) {
		throw new Error("Cannot create pipes without an RPC session.");
	}
	onSendError(error) {}
};
var NULL_EXPORTER = new NullExporter();
async function streamToBlob(stream, type) {
	let b = await new Response(stream).blob();
	return b.type === type ? b : b.slice(0, b.size, type);
}
var ERROR_TYPES = {
	Error,
	EvalError,
	RangeError,
	ReferenceError,
	SyntaxError,
	TypeError,
	URIError,
	AggregateError
};
var Devaluator = class _Devaluator {
	constructor(exporter, source) {
		this.exporter = exporter;
		this.source = source;
	}
	static devaluate(value, parent, exporter = NULL_EXPORTER, source) {
		let devaluator = new _Devaluator(exporter, source);
		try {
			return devaluator.devaluateImpl(value, parent, 0);
		} catch (err) {
			if (devaluator.exports) try {
				exporter.unexport(devaluator.exports);
			} catch (err2) {}
			throw err;
		}
	}
	exports;
	devaluateImpl(value, parent, depth) {
		if (depth >= 64) throw new Error("Serialization exceeded maximum allowed depth. (Does the message contain cycles?)");
		switch (typeForRpc(value)) {
			case "unsupported": {
				let msg;
				try {
					msg = `Cannot serialize value: ${value}`;
				} catch (err) {
					msg = "Cannot serialize value: (couldn't stringify value)";
				}
				throw new TypeError(msg);
			}
			case "primitive": if (typeof value === "number" && !isFinite(value)) {
				if (value === Infinity) return ["inf"];
				else if (value === -Infinity) return ["-inf"];
				else return ["nan"];
			} else return value;
			case "object": {
				let object = value;
				let result = {};
				for (let key in object) result[key] = this.devaluateImpl(object[key], object, depth + 1);
				return result;
			}
			case "array": {
				let array = value;
				let len = array.length;
				let result = new Array(len);
				for (let i = 0; i < len; i++) result[i] = this.devaluateImpl(array[i], array, depth + 1);
				return [result];
			}
			case "bigint": return ["bigint", value.toString()];
			case "date": {
				const time = value.getTime();
				return ["date", Number.isNaN(time) ? null : time];
			}
			case "bytes": {
				let bytes = value;
				if (bytes.toBase64) return ["bytes", bytes.toBase64({ omitPadding: true })];
				let b64;
				if (typeof Buffer !== "undefined") b64 = (bytes instanceof Buffer ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)).toString("base64");
				else {
					let binary = "";
					for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
					b64 = btoa(binary);
				}
				return ["bytes", b64.replace(/=+$/, "")];
			}
			case "headers": return ["headers", [...value]];
			case "request": {
				let req = value;
				let init = {};
				if (req.method !== "GET") init.method = req.method;
				let headers = [...req.headers];
				if (headers.length > 0) init.headers = headers;
				if (req.body) {
					init.body = this.devaluateImpl(req.body, req, depth + 1);
					init.duplex = req.duplex || "half";
				} else if (req.body === void 0 && ![
					"GET",
					"HEAD",
					"OPTIONS",
					"TRACE",
					"DELETE"
				].includes(req.method)) {
					let bodyPromise = req.arrayBuffer();
					let readable = new ReadableStream({ async start(controller) {
						try {
							controller.enqueue(new Uint8Array(await bodyPromise));
							controller.close();
						} catch (err) {
							controller.error(err);
						}
					} });
					let hook = streamImpl.createReadableStreamHook(readable);
					init.body = ["readable", this.exporter.createPipe(readable, hook)];
					init.duplex = req.duplex || "half";
				}
				if (req.cache && req.cache !== "default") init.cache = req.cache;
				if (req.redirect !== "follow") init.redirect = req.redirect;
				if (req.integrity) init.integrity = req.integrity;
				if (req.mode && req.mode !== "cors") init.mode = req.mode;
				if (req.credentials && req.credentials !== "same-origin") init.credentials = req.credentials;
				if (req.referrer && req.referrer !== "about:client") init.referrer = req.referrer;
				if (req.referrerPolicy) init.referrerPolicy = req.referrerPolicy;
				if (req.keepalive) init.keepalive = req.keepalive;
				let cfReq = req;
				if (cfReq.cf) init.cf = cfReq.cf;
				if (cfReq.encodeResponseBody && cfReq.encodeResponseBody !== "automatic") init.encodeResponseBody = cfReq.encodeResponseBody;
				return [
					"request",
					req.url,
					init
				];
			}
			case "response": {
				let resp = value;
				let body = this.devaluateImpl(resp.body, resp, depth + 1);
				let init = {};
				if (resp.status !== 200) init.status = resp.status;
				if (resp.statusText) init.statusText = resp.statusText;
				let headers = [...resp.headers];
				if (headers.length > 0) init.headers = headers;
				let cfResp = resp;
				if (cfResp.cf) init.cf = cfResp.cf;
				if (cfResp.encodeBody && cfResp.encodeBody !== "automatic") init.encodeBody = cfResp.encodeBody;
				if (cfResp.webSocket) throw new TypeError("Can't serialize a Response containing a webSocket.");
				return [
					"response",
					body,
					init
				];
			}
			case "blob": {
				let blob = value;
				let readable = blob.stream();
				let hook = streamImpl.createReadableStreamHook(readable);
				let importId = this.exporter.createPipe(readable, hook);
				return [
					"blob",
					blob.type,
					["readable", importId]
				];
			}
			case "error": {
				let e = value;
				let rewritten = this.exporter.onSendError(e);
				if (rewritten) e = rewritten;
				let anyE = e;
				let props;
				let captureProp = (key, val) => {
					let exportsBefore = this.exports?.length ?? 0;
					try {
						let encoded = this.devaluateImpl(val, e, depth + 1);
						if (!props) props = {};
						props[key] = encoded;
					} catch (err) {
						if (this.exports && this.exports.length > exportsBefore) {
							let tail = this.exports.splice(exportsBefore);
							try {
								this.exporter.unexport(tail);
							} catch (err2) {}
						}
					}
				};
				for (let key of Object.keys(e)) {
					if (key === "name" || key === "message" || key === "stack") continue;
					captureProp(key, anyE[key]);
				}
				if ("cause" in e) captureProp("cause", anyE.cause);
				if (e instanceof AggregateError) captureProp("errors", e.errors);
				let result = [
					"error",
					e.name,
					e.message
				];
				if (props) {
					result.push(rewritten && rewritten.stack ? rewritten.stack : null);
					result.push(props);
				} else if (rewritten && rewritten.stack) result.push(rewritten.stack);
				return result;
			}
			case "undefined": return ["undefined"];
			case "stub":
			case "rpc-promise": {
				if (!this.source) throw new Error("Can't serialize RPC stubs in this context.");
				let { hook, pathIfPromise } = unwrapStubAndPath(value);
				let importId = this.exporter.getImport(hook);
				if (importId !== void 0) {
					if (pathIfPromise) {
						if (pathIfPromise.length > 0) return [
							"pipeline",
							importId,
							pathIfPromise
						];
						else return ["pipeline", importId];
					} else return ["import", importId];
				}
				if (pathIfPromise) hook = hook.get(pathIfPromise);
				else hook = hook.dup();
				return this.devaluateHook(pathIfPromise ? "promise" : "export", hook);
			}
			case "function":
			case "rpc-target": {
				if (!this.source) throw new Error("Can't serialize RPC stubs in this context.");
				let hook = this.source.getHookForRpcTarget(value, parent);
				return this.devaluateHook("export", hook);
			}
			case "rpc-thenable": {
				if (!this.source) throw new Error("Can't serialize RPC stubs in this context.");
				let hook = this.source.getHookForRpcTarget(value, parent);
				return this.devaluateHook("promise", hook);
			}
			case "writable": {
				if (!this.source) throw new Error("Can't serialize WritableStream in this context.");
				let hook = this.source.getHookForWritableStream(value, parent);
				return this.devaluateHook("writable", hook);
			}
			case "readable": {
				if (!this.source) throw new Error("Can't serialize ReadableStream in this context.");
				let ws = value;
				let hook = this.source.getHookForReadableStream(ws, parent);
				return ["readable", this.exporter.createPipe(ws, hook)];
			}
			default: throw new Error("unreachable");
		}
	}
	devaluateHook(type, hook) {
		if (!this.exports) this.exports = [];
		let exportId = type === "promise" ? this.exporter.exportPromise(hook) : this.exporter.exportStub(hook);
		this.exports.push(exportId);
		return [type, exportId];
	}
};
var NullImporter = class {
	importStub(idx) {
		throw new Error("Cannot deserialize RPC stubs without an RPC session.");
	}
	importPromise(idx) {
		throw new Error("Cannot deserialize RPC stubs without an RPC session.");
	}
	getExport(idx) {}
	getPipeReadable(exportId) {
		throw new Error("Cannot retrieve pipe readable without an RPC session.");
	}
};
new NullImporter();
function fixBrokenRequestBody(request, body) {
	return new RpcPromise(new PromiseStubHook(new Response(body).arrayBuffer().then((arrayBuffer) => {
		let bytes = new Uint8Array(arrayBuffer);
		let result = new Request(request, { body: bytes });
		return new PayloadStubHook(RpcPayload.fromAppReturn(result));
	})), []);
}
function streamToBlobPromise(stream, type) {
	return new RpcPromise(new PromiseStubHook(streamToBlob(stream, type).then((blob) => {
		return new PayloadStubHook(RpcPayload.fromAppReturn(blob));
	})), []);
}
var Evaluator = class _Evaluator {
	constructor(importer) {
		this.importer = importer;
	}
	hooks = [];
	promises = [];
	evaluate(value) {
		let payload = RpcPayload.forEvaluate(this.hooks, this.promises);
		try {
			payload.value = this.evaluateImpl(value, payload, "value");
			return payload;
		} catch (err) {
			payload.dispose();
			throw err;
		}
	}
	evaluateCopy(value) {
		return this.evaluate(structuredClone(value));
	}
	evaluateImpl(value, parent, property) {
		if (value instanceof Array) {
			if (value.length == 1 && value[0] instanceof Array) {
				let result = value[0];
				for (let i = 0; i < result.length; i++) result[i] = this.evaluateImpl(result[i], result, i);
				return result;
			} else switch (value[0]) {
				case "bigint":
					if (typeof value[1] == "string") return BigInt(value[1]);
					break;
				case "date":
					if (value[1] === null) return /* @__PURE__ */ new Date(NaN);
					if (typeof value[1] == "number") return new Date(value[1]);
					break;
				case "bytes":
					if (typeof value[1] == "string") {
						if (typeof Buffer !== "undefined") return Buffer.from(value[1], "base64");
						else if (Uint8Array.fromBase64) return Uint8Array.fromBase64(value[1]);
						else {
							let bs = atob(value[1]);
							let len = bs.length;
							let bytes = new Uint8Array(len);
							for (let i = 0; i < len; i++) bytes[i] = bs.charCodeAt(i);
							return bytes;
						}
					}
					break;
				case "error":
					if (value.length >= 3 && typeof value[1] === "string" && typeof value[2] === "string") {
						let cls = ERROR_TYPES[value[1]] || Error;
						let result = cls === AggregateError ? new cls([], value[2]) : new cls(value[2]);
						if (typeof value[3] === "string") result.stack = value[3];
						if (value.length >= 5) {
							let props = value[4];
							if (!props || typeof props !== "object" || Array.isArray(props)) break;
							let anyResult = result;
							let propsObj = props;
							for (let key of Object.keys(propsObj)) {
								if (key === "name" || key === "message" || key === "stack") continue;
								anyResult[key] = this.evaluateImpl(propsObj[key], result, key);
							}
						}
						return result;
					}
					break;
				case "undefined":
					if (value.length === 1) return;
					break;
				case "inf": return Infinity;
				case "-inf": return -Infinity;
				case "nan": return NaN;
				case "headers":
					if (value.length === 2 && value[1] instanceof Array) return new Headers(value[1]);
					break;
				case "request": {
					if (value.length !== 3 || typeof value[1] !== "string") break;
					let url = value[1];
					let init = value[2];
					if (typeof init !== "object" || init === null) break;
					if (init.body) {
						init.body = this.evaluateImpl(init.body, init, "body");
						if (init.body === null || typeof init.body === "string" || init.body instanceof Uint8Array || init.body instanceof ReadableStream);
						else throw new TypeError("Request body must be of type ReadableStream.");
					}
					if (init.signal) {
						init.signal = this.evaluateImpl(init.signal, init, "signal");
						if (!(init.signal instanceof AbortSignal)) throw new TypeError("Request siganl must be of type AbortSignal.");
					}
					if (init.headers && !(init.headers instanceof Array)) throw new TypeError("Request headers must be serialized as an array of pairs.");
					let result = new Request(url, init);
					if (init.body instanceof ReadableStream && result.body === void 0) {
						let promise = fixBrokenRequestBody(result, init.body);
						this.promises.push({
							promise,
							parent,
							property
						});
						return promise;
					} else return result;
				}
				case "response": {
					if (value.length !== 3) break;
					let body = this.evaluateImpl(value[1], parent, property);
					if (body === null || typeof body === "string" || body instanceof Uint8Array || body instanceof ReadableStream);
					else throw new TypeError("Response body must be of type ReadableStream.");
					let init = value[2];
					if (typeof init !== "object" || init === null) break;
					if (init.webSocket) throw new TypeError("Can't deserialize a Response containing a webSocket.");
					if (init.headers && !(init.headers instanceof Array)) throw new TypeError("Request headers must be serialized as an array of pairs.");
					return new Response(body, init);
				}
				case "blob": {
					if (value.length !== 3 || typeof value[1] !== "string") break;
					let contentType = value[1];
					let content = this.evaluateImpl(value[2], parent, property);
					if (!(content instanceof ReadableStream)) throw new TypeError("Blob content must be serialized as a ReadableStream.");
					let promise = streamToBlobPromise(content, contentType);
					this.promises.push({
						promise,
						parent,
						property
					});
					return promise;
				}
				case "import":
				case "pipeline": {
					if (value.length < 2 || value.length > 4) break;
					if (typeof value[1] != "number") break;
					let hook = this.importer.getExport(value[1]);
					if (!hook) throw new Error(`no such entry on exports table: ${value[1]}`);
					let isPromise = value[0] == "pipeline";
					let addStub = (hook2) => {
						if (isPromise) {
							let promise = new RpcPromise(hook2, []);
							this.promises.push({
								promise,
								parent,
								property
							});
							return promise;
						} else {
							this.hooks.push(hook2);
							return new RpcPromise(hook2, []);
						}
					};
					if (value.length == 2) {
						if (isPromise) return addStub(hook.get([]));
						else return addStub(hook.dup());
					}
					let path = value[2];
					if (!(path instanceof Array)) break;
					if (!path.every((part) => {
						return typeof part == "string" || typeof part == "number";
					})) break;
					if (value.length == 3) return addStub(hook.get(path));
					let args = value[3];
					if (!(args instanceof Array)) break;
					args = new _Evaluator(this.importer).evaluate([args]);
					return addStub(hook.call(path, args));
				}
				case "remap": {
					if (value.length !== 5 || typeof value[1] !== "number" || !(value[2] instanceof Array) || !(value[3] instanceof Array) || !(value[4] instanceof Array)) break;
					let hook = this.importer.getExport(value[1]);
					if (!hook) throw new Error(`no such entry on exports table: ${value[1]}`);
					let path = value[2];
					if (!path.every((part) => {
						return typeof part == "string" || typeof part == "number";
					})) break;
					let captures = value[3].map((cap) => {
						if (!(cap instanceof Array) || cap.length !== 2 || cap[0] !== "import" && cap[0] !== "export" || typeof cap[1] !== "number") throw new TypeError(`unknown map capture: ${JSON.stringify(cap)}`);
						if (cap[0] === "export") return this.importer.importStub(cap[1]);
						else {
							let exp = this.importer.getExport(cap[1]);
							if (!exp) throw new Error(`no such entry on exports table: ${cap[1]}`);
							return exp.dup();
						}
					});
					let instructions = value[4];
					let promise = new RpcPromise(hook.map(path, captures, instructions), []);
					this.promises.push({
						promise,
						parent,
						property
					});
					return promise;
				}
				case "export":
				case "promise":
					if (typeof value[1] == "number") {
						if (value[0] == "promise") {
							let promise = new RpcPromise(this.importer.importPromise(value[1]), []);
							this.promises.push({
								parent,
								property,
								promise
							});
							return promise;
						} else {
							let hook = this.importer.importStub(value[1]);
							this.hooks.push(hook);
							return new RpcStub(hook);
						}
					}
					break;
				case "writable":
					if (typeof value[1] == "number") {
						let hook = this.importer.importStub(value[1]);
						let stream = streamImpl.createWritableStreamFromHook(hook);
						this.hooks.push(hook);
						return stream;
					}
					break;
				case "readable": if (typeof value[1] == "number") {
					let stream = this.importer.getPipeReadable(value[1]);
					let hook = streamImpl.createReadableStreamHook(stream);
					this.hooks.push(hook);
					return stream;
				}
			}
			throw new TypeError(`unknown special value: ${JSON.stringify(value)}`);
		} else if (value instanceof Object) {
			let result = value;
			for (let key in result) if (key in Object.prototype || key === "toJSON") {
				this.evaluateImpl(result[key], result, key);
				delete result[key];
			} else result[key] = this.evaluateImpl(result[key], result, key);
			return result;
		} else return value;
	}
};
var ImportTableEntry = class {
	constructor(session, importId, pulling) {
		this.session = session;
		this.importId = importId;
		if (pulling) this.activePull = Promise.withResolvers();
	}
	localRefcount = 0;
	remoteRefcount = 1;
	activePull;
	resolution;
	onBrokenRegistrations;
	resolve(resolution) {
		if (this.localRefcount == 0) {
			resolution.dispose();
			return;
		}
		this.resolution = resolution;
		this.sendRelease();
		if (this.onBrokenRegistrations) {
			for (let i of this.onBrokenRegistrations) {
				let callback = this.session.onBrokenCallbacks[i];
				let endIndex = this.session.onBrokenCallbacks.length;
				resolution.onBroken(callback);
				if (this.session.onBrokenCallbacks[endIndex] === callback) delete this.session.onBrokenCallbacks[endIndex];
				else delete this.session.onBrokenCallbacks[i];
			}
			this.onBrokenRegistrations = void 0;
		}
		if (this.activePull) {
			this.activePull.resolve();
			this.activePull = void 0;
		}
	}
	async awaitResolution() {
		if (!this.activePull) {
			this.session.sendPull(this.importId);
			this.activePull = Promise.withResolvers();
		}
		await this.activePull.promise;
		return this.resolution.pull();
	}
	dispose() {
		if (this.resolution) this.resolution.dispose();
		else {
			this.abort(/* @__PURE__ */ new Error("RPC was canceled because the RpcPromise was disposed."));
			this.sendRelease();
		}
	}
	abort(error) {
		if (!this.resolution) {
			this.resolution = new ErrorStubHook(error);
			if (this.activePull) {
				this.activePull.reject(error);
				this.activePull = void 0;
			}
			this.onBrokenRegistrations = void 0;
		}
	}
	onBroken(callback) {
		if (this.resolution) this.resolution.onBroken(callback);
		else {
			let index = this.session.onBrokenCallbacks.length;
			this.session.onBrokenCallbacks.push(callback);
			if (!this.onBrokenRegistrations) this.onBrokenRegistrations = [];
			this.onBrokenRegistrations.push(index);
		}
	}
	sendRelease() {
		if (this.remoteRefcount > 0) {
			this.session.sendRelease(this.importId, this.remoteRefcount);
			this.remoteRefcount = 0;
		}
	}
};
var RpcImportHook = class _RpcImportHook extends StubHook {
	constructor(isPromise, entry) {
		super();
		this.isPromise = isPromise;
		++entry.localRefcount;
		this.entry = entry;
	}
	entry;
	collectPath(path) {
		return this;
	}
	getEntry() {
		if (this.entry) return this.entry;
		else throw new Error("This RpcImportHook was already disposed.");
	}
	call(path, args) {
		let entry = this.getEntry();
		if (entry.resolution) return entry.resolution.call(path, args);
		else return entry.session.sendCall(entry.importId, path, args);
	}
	stream(path, args) {
		let entry = this.getEntry();
		if (entry.resolution) return entry.resolution.stream(path, args);
		else return entry.session.sendStream(entry.importId, path, args);
	}
	map(path, captures, instructions) {
		let entry;
		try {
			entry = this.getEntry();
		} catch (err) {
			for (let cap of captures) cap.dispose();
			throw err;
		}
		if (entry.resolution) return entry.resolution.map(path, captures, instructions);
		else return entry.session.sendMap(entry.importId, path, captures, instructions);
	}
	get(path) {
		let entry = this.getEntry();
		if (entry.resolution) return entry.resolution.get(path);
		else return entry.session.sendCall(entry.importId, path);
	}
	dup() {
		return new _RpcImportHook(false, this.getEntry());
	}
	pull() {
		let entry = this.getEntry();
		if (!this.isPromise) throw new Error("Can't pull this hook because it's not a promise hook.");
		if (entry.resolution) return entry.resolution.pull();
		return entry.awaitResolution();
	}
	ignoreUnhandledRejections() {}
	dispose() {
		let entry = this.entry;
		this.entry = void 0;
		if (entry) {
			if (--entry.localRefcount === 0) entry.dispose();
		}
	}
	onBroken(callback) {
		if (this.entry) this.entry.onBroken(callback);
	}
};
var RpcMainHook = class extends RpcImportHook {
	session;
	constructor(entry) {
		super(false, entry);
		this.session = entry.session;
	}
	dispose() {
		if (this.session) {
			let session = this.session;
			this.session = void 0;
			session.shutdown();
		}
	}
};
var RpcSessionImpl = class {
	constructor(transport, mainHook, options) {
		this.transport = transport;
		this.options = options;
		this.exports.push({
			hook: mainHook,
			refcount: 1
		});
		this.imports.push(new ImportTableEntry(this, 0, false));
		this.readLoop().catch((err) => this.abort(err));
	}
	exports = [];
	reverseExports = /* @__PURE__ */ new Map();
	imports = [];
	abortReason;
	cancelReadLoop;
	nextExportId = -1;
	onBatchDone;
	pullCount = 0;
	onBrokenCallbacks = [];
	getMainImport() {
		return new RpcMainHook(this.imports[0]);
	}
	shutdown() {
		this.abort(/* @__PURE__ */ new Error("RPC session was shut down by disposing the main stub"), false);
	}
	exportStub(hook) {
		if (this.abortReason) throw this.abortReason;
		let existingExportId = this.reverseExports.get(hook);
		if (existingExportId !== void 0) {
			++this.exports[existingExportId].refcount;
			return existingExportId;
		} else {
			let exportId = this.nextExportId--;
			this.exports[exportId] = {
				hook,
				refcount: 1
			};
			this.reverseExports.set(hook, exportId);
			return exportId;
		}
	}
	exportPromise(hook) {
		if (this.abortReason) throw this.abortReason;
		let exportId = this.nextExportId--;
		this.exports[exportId] = {
			hook,
			refcount: 1
		};
		this.reverseExports.set(hook, exportId);
		this.ensureResolvingExport(exportId);
		return exportId;
	}
	unexport(ids) {
		for (let id of ids) this.releaseExport(id, 1);
	}
	releaseExport(exportId, refcount) {
		let entry = this.exports[exportId];
		if (!entry) throw new Error(`no such export ID: ${exportId}`);
		if (entry.refcount < refcount) throw new Error(`refcount would go negative: ${entry.refcount} < ${refcount}`);
		entry.refcount -= refcount;
		if (entry.refcount === 0) {
			delete this.exports[exportId];
			this.reverseExports.delete(entry.hook);
			entry.hook.dispose();
		}
	}
	onSendError(error) {
		if (this.options.onSendError) return this.options.onSendError(error);
	}
	ensureResolvingExport(exportId) {
		let exp = this.exports[exportId];
		if (!exp) throw new Error(`no such export ID: ${exportId}`);
		if (!exp.pull) {
			let resolve = async () => {
				let hook = exp.hook;
				for (;;) {
					let payload = await hook.pull();
					if (payload.value instanceof RpcStub) {
						let { hook: inner, pathIfPromise } = unwrapStubAndPath(payload.value);
						if (pathIfPromise && pathIfPromise.length == 0) {
							if (this.getImport(hook) === void 0) {
								hook = inner;
								continue;
							}
						}
					}
					return payload;
				}
			};
			let autoRelease = exp.autoRelease;
			++this.pullCount;
			exp.pull = resolve().then((payload) => {
				let value = Devaluator.devaluate(payload.value, void 0, this, payload);
				this.send([
					"resolve",
					exportId,
					value
				]);
				if (autoRelease) this.releaseExport(exportId, 1);
			}, (error) => {
				this.send([
					"reject",
					exportId,
					Devaluator.devaluate(error, void 0, this)
				]);
				if (autoRelease) this.releaseExport(exportId, 1);
			}).catch((error) => {
				try {
					this.send([
						"reject",
						exportId,
						Devaluator.devaluate(error, void 0, this)
					]);
					if (autoRelease) this.releaseExport(exportId, 1);
				} catch (error2) {
					this.abort(error2);
				}
			}).finally(() => {
				if (--this.pullCount === 0) {
					if (this.onBatchDone) this.onBatchDone.resolve();
				}
			});
		}
	}
	getImport(hook) {
		if (hook instanceof RpcImportHook && hook.entry && hook.entry.session === this) return hook.entry.importId;
		else return;
	}
	importStub(idx) {
		if (this.abortReason) throw this.abortReason;
		let entry = this.imports[idx];
		if (!entry) {
			entry = new ImportTableEntry(this, idx, false);
			this.imports[idx] = entry;
		}
		return new RpcImportHook(false, entry);
	}
	importPromise(idx) {
		if (this.abortReason) throw this.abortReason;
		if (this.imports[idx]) return new ErrorStubHook(/* @__PURE__ */ new Error("Bug in RPC system: The peer sent a promise reusing an existing export ID."));
		let entry = new ImportTableEntry(this, idx, true);
		this.imports[idx] = entry;
		return new RpcImportHook(true, entry);
	}
	getExport(idx) {
		return this.exports[idx]?.hook;
	}
	getPipeReadable(exportId) {
		let entry = this.exports[exportId];
		if (!entry || !entry.pipeReadable) throw new Error(`Export ${exportId} is not a pipe or its readable end was already consumed.`);
		let readable = entry.pipeReadable;
		entry.pipeReadable = void 0;
		return readable;
	}
	createPipe(readable, readableHook) {
		if (this.abortReason) throw this.abortReason;
		this.send(["pipe"]);
		let importId = this.imports.length;
		let entry = new ImportTableEntry(this, importId, false);
		this.imports.push(entry);
		let hook = new RpcImportHook(false, entry);
		let writable = streamImpl.createWritableStreamFromHook(hook);
		readable.pipeTo(writable).catch(() => {}).finally(() => readableHook.dispose());
		return importId;
	}
	send(msg) {
		if (this.abortReason !== void 0) return 0;
		let msgText;
		try {
			msgText = JSON.stringify(msg);
		} catch (err) {
			try {
				this.abort(err);
			} catch (err2) {}
			throw err;
		}
		this.transport.send(msgText).catch((err) => this.abort(err, false));
		return msgText.length;
	}
	sendCall(id, path, args) {
		if (this.abortReason) throw this.abortReason;
		let value = [
			"pipeline",
			id,
			path
		];
		if (args) {
			let devalue = Devaluator.devaluate(args.value, void 0, this, args);
			value.push(devalue[0]);
		}
		this.send(["push", value]);
		let entry = new ImportTableEntry(this, this.imports.length, false);
		this.imports.push(entry);
		return new RpcImportHook(true, entry);
	}
	sendStream(id, path, args) {
		if (this.abortReason) throw this.abortReason;
		let value = [
			"pipeline",
			id,
			path
		];
		let devalue = Devaluator.devaluate(args.value, void 0, this, args);
		value.push(devalue[0]);
		let size = this.send(["stream", value]);
		let importId = this.imports.length;
		let entry = new ImportTableEntry(this, importId, true);
		entry.remoteRefcount = 0;
		entry.localRefcount = 1;
		this.imports.push(entry);
		return {
			promise: entry.awaitResolution().then((p) => {
				p.dispose();
				delete this.imports[importId];
			}, (err) => {
				delete this.imports[importId];
				throw err;
			}),
			size
		};
	}
	sendMap(id, path, captures, instructions) {
		if (this.abortReason) {
			for (let cap of captures) cap.dispose();
			throw this.abortReason;
		}
		let value = [
			"remap",
			id,
			path,
			captures.map((hook) => {
				let importId = this.getImport(hook);
				if (importId !== void 0) return ["import", importId];
				else return ["export", this.exportStub(hook)];
			}),
			instructions
		];
		this.send(["push", value]);
		let entry = new ImportTableEntry(this, this.imports.length, false);
		this.imports.push(entry);
		return new RpcImportHook(true, entry);
	}
	sendPull(id) {
		if (this.abortReason) throw this.abortReason;
		this.send(["pull", id]);
	}
	sendRelease(id, remoteRefcount) {
		if (this.abortReason) return;
		this.send([
			"release",
			id,
			remoteRefcount
		]);
		delete this.imports[id];
	}
	abort(error, trySendAbortMessage = true) {
		if (this.abortReason !== void 0) return;
		this.cancelReadLoop?.(error);
		this.cancelReadLoop = void 0;
		if (trySendAbortMessage) try {
			this.transport.send(JSON.stringify(["abort", Devaluator.devaluate(error, void 0, this)])).catch((err) => {});
		} catch (err) {}
		if (error === void 0) error = "undefined";
		this.abortReason = error;
		if (this.onBatchDone) this.onBatchDone.reject(error);
		if (this.transport.abort) try {
			this.transport.abort(error);
		} catch (err) {
			Promise.resolve(err);
		}
		for (let i in this.onBrokenCallbacks) try {
			this.onBrokenCallbacks[i](error);
		} catch (err) {
			Promise.resolve(err);
		}
		for (let i in this.imports) this.imports[i].abort(error);
		for (let i in this.exports) this.exports[i].hook.dispose();
	}
	async readLoop() {
		while (!this.abortReason) {
			let readCanceled = Promise.withResolvers();
			this.cancelReadLoop = readCanceled.reject;
			let msgText;
			try {
				msgText = await Promise.race([this.transport.receive(), readCanceled.promise]);
			} finally {
				if (this.cancelReadLoop === readCanceled.reject) this.cancelReadLoop = void 0;
			}
			let msg = JSON.parse(msgText);
			if (this.abortReason) break;
			if (msg instanceof Array) switch (msg[0]) {
				case "push":
					if (msg.length > 1) {
						let hook = new PayloadStubHook(new Evaluator(this).evaluate(msg[1]));
						hook.ignoreUnhandledRejections();
						this.exports.push({
							hook,
							refcount: 1
						});
						continue;
					}
					break;
				case "stream":
					if (msg.length > 1) {
						let hook = new PayloadStubHook(new Evaluator(this).evaluate(msg[1]));
						hook.ignoreUnhandledRejections();
						let exportId = this.exports.length;
						this.exports.push({
							hook,
							refcount: 1,
							autoRelease: true
						});
						this.ensureResolvingExport(exportId);
						continue;
					}
					break;
				case "pipe": {
					let { readable, writable } = new TransformStream();
					let hook = streamImpl.createWritableStreamHook(writable);
					this.exports.push({
						hook,
						refcount: 1,
						pipeReadable: readable
					});
					continue;
				}
				case "pull": {
					let exportId = msg[1];
					if (typeof exportId == "number") {
						this.ensureResolvingExport(exportId);
						continue;
					}
					break;
				}
				case "resolve":
				case "reject": {
					let importId = msg[1];
					if (typeof importId == "number" && msg.length > 2) {
						let imp = this.imports[importId];
						if (imp) {
							if (msg[0] == "resolve") imp.resolve(new PayloadStubHook(new Evaluator(this).evaluate(msg[2])));
							else {
								let payload = new Evaluator(this).evaluate(msg[2]);
								payload.dispose();
								imp.resolve(new ErrorStubHook(payload.value));
							}
						} else if (msg[0] == "resolve") new Evaluator(this).evaluate(msg[2]).dispose();
						continue;
					}
					break;
				}
				case "release": {
					let exportId = msg[1];
					let refcount = msg[2];
					if (typeof exportId == "number" && typeof refcount == "number") {
						this.releaseExport(exportId, refcount);
						continue;
					}
					break;
				}
				case "abort": {
					let payload = new Evaluator(this).evaluate(msg[1]);
					payload.dispose();
					this.abort(payload, false);
					break;
				}
			}
			throw new Error(`bad RPC message: ${JSON.stringify(msg)}`);
		}
	}
	async drain() {
		if (this.abortReason) throw this.abortReason;
		if (this.pullCount > 0) {
			let { promise, resolve, reject } = Promise.withResolvers();
			this.onBatchDone = {
				resolve,
				reject
			};
			await promise;
		}
	}
	getStats() {
		let result = {
			imports: 0,
			exports: 0
		};
		for (let i in this.imports) ++result.imports;
		for (let i in this.exports) ++result.exports;
		return result;
	}
};
var RpcSession = class {
	#session;
	#mainStub;
	constructor(transport, localMain, options = {}) {
		let mainHook;
		if (localMain) mainHook = new PayloadStubHook(RpcPayload.fromAppReturn(localMain));
		else mainHook = new ErrorStubHook(/* @__PURE__ */ new Error("This connection has no main object."));
		this.#session = new RpcSessionImpl(transport, mainHook, options);
		this.#mainStub = new RpcStub(this.#session.getMainImport());
	}
	getRemoteMain() {
		return this.#mainStub;
	}
	getStats() {
		return this.#session.getStats();
	}
	drain() {
		return this.#session.drain();
	}
};
var currentMapBuilder;
var MapBuilder = class {
	context;
	captureMap = /* @__PURE__ */ new Map();
	instructions = [];
	constructor(subject, path) {
		if (currentMapBuilder) this.context = {
			parent: currentMapBuilder,
			captures: [],
			subject: currentMapBuilder.capture(subject),
			path
		};
		else this.context = {
			parent: void 0,
			captures: [],
			subject,
			path
		};
		currentMapBuilder = this;
	}
	unregister() {
		currentMapBuilder = this.context.parent;
	}
	makeInput() {
		return new MapVariableHook(this, 0);
	}
	makeOutput(result) {
		let devalued;
		try {
			devalued = Devaluator.devaluate(result.value, void 0, this, result);
		} finally {
			result.dispose();
		}
		this.instructions.push(devalued);
		if (this.context.parent) {
			this.context.parent.instructions.push([
				"remap",
				this.context.subject,
				this.context.path,
				this.context.captures.map((cap) => ["import", cap]),
				this.instructions
			]);
			return new MapVariableHook(this.context.parent, this.context.parent.instructions.length);
		} else return this.context.subject.map(this.context.path, this.context.captures, this.instructions);
	}
	pushCall(hook, path, params) {
		let devalued = Devaluator.devaluate(params.value, void 0, this, params);
		devalued = devalued[0];
		let subject = this.capture(hook.dup());
		this.instructions.push([
			"pipeline",
			subject,
			path,
			devalued
		]);
		return new MapVariableHook(this, this.instructions.length);
	}
	pushGet(hook, path) {
		let subject = this.capture(hook.dup());
		this.instructions.push([
			"pipeline",
			subject,
			path
		]);
		return new MapVariableHook(this, this.instructions.length);
	}
	capture(hook) {
		if (hook instanceof MapVariableHook && hook.mapper === this) return hook.idx;
		let result = this.captureMap.get(hook);
		if (result === void 0) {
			if (this.context.parent) {
				let parentIdx = this.context.parent.capture(hook);
				this.context.captures.push(parentIdx);
			} else this.context.captures.push(hook);
			result = -this.context.captures.length;
			this.captureMap.set(hook, result);
		}
		return result;
	}
	exportStub(hook) {
		throw new Error("Can't construct an RpcTarget or RPC callback inside a mapper function. Try creating a new RpcStub outside the callback first, then using it inside the callback.");
	}
	exportPromise(hook) {
		return this.exportStub(hook);
	}
	getImport(hook) {
		return this.capture(hook);
	}
	unexport(ids) {}
	createPipe(readable) {
		throw new Error("Cannot send ReadableStream inside a mapper function.");
	}
	onSendError(error) {}
};
mapImpl.sendMap = (hook, path, func) => {
	let builder = new MapBuilder(hook, path);
	let result;
	try {
		result = RpcPayload.fromAppReturn(withCallInterceptor(builder.pushCall.bind(builder), () => {
			return func(new RpcPromise(builder.makeInput(), []));
		}));
	} finally {
		builder.unregister();
	}
	if (result instanceof Promise) {
		result.catch((err) => {});
		throw new Error("RPC map() callbacks cannot be async.");
	}
	return new RpcPromise(builder.makeOutput(result), []);
};
function throwMapperBuilderUseError() {
	throw new Error("Attempted to use an abstract placeholder from a mapper function. Please make sure your map function has no side effects.");
}
var MapVariableHook = class extends StubHook {
	constructor(mapper, idx) {
		super();
		this.mapper = mapper;
		this.idx = idx;
	}
	dup() {
		return this;
	}
	dispose() {}
	get(path) {
		if (path.length == 0) return this;
		else if (currentMapBuilder) return currentMapBuilder.pushGet(this, path);
		else throwMapperBuilderUseError();
	}
	call(path, args) {
		throwMapperBuilderUseError();
	}
	map(path, captures, instructions) {
		throwMapperBuilderUseError();
	}
	pull() {
		throwMapperBuilderUseError();
	}
	ignoreUnhandledRejections() {}
	onBroken(callback) {
		throwMapperBuilderUseError();
	}
};
var MapApplicator = class {
	constructor(captures, input) {
		this.captures = captures;
		this.variables = [input];
	}
	variables;
	dispose() {
		for (let variable of this.variables) variable.dispose();
	}
	apply(instructions) {
		try {
			if (instructions.length < 1) throw new Error("Invalid empty mapper function.");
			for (let instruction of instructions.slice(0, -1)) {
				let payload = new Evaluator(this).evaluateCopy(instruction);
				if (payload.value instanceof RpcStub) {
					let hook = unwrapStubNoProperties(payload.value);
					if (hook) {
						this.variables.push(hook);
						continue;
					}
				}
				this.variables.push(new PayloadStubHook(payload));
			}
			return new Evaluator(this).evaluateCopy(instructions[instructions.length - 1]);
		} finally {
			for (let variable of this.variables) variable.dispose();
		}
	}
	importStub(idx) {
		throw new Error("A mapper function cannot refer to exports.");
	}
	importPromise(idx) {
		return this.importStub(idx);
	}
	getExport(idx) {
		if (idx < 0) return this.captures[-idx - 1];
		else return this.variables[idx];
	}
	getPipeReadable(exportId) {
		throw new Error("A mapper function cannot use pipe readables.");
	}
};
function applyMapToElement(input, parent, owner, captures, instructions) {
	let mapper = new MapApplicator(captures, new PayloadStubHook(RpcPayload.deepCopyFrom(input, parent, owner)));
	try {
		return mapper.apply(instructions);
	} finally {
		mapper.dispose();
	}
}
mapImpl.applyMap = (input, parent, owner, captures, instructions) => {
	try {
		let result;
		if (input instanceof RpcPromise) throw new Error("applyMap() can't be called on RpcPromise");
		else if (input instanceof Array) {
			let payloads = [];
			try {
				for (let elem of input) payloads.push(applyMapToElement(elem, input, owner, captures, instructions));
			} catch (err) {
				for (let payload of payloads) payload.dispose();
				throw err;
			}
			result = RpcPayload.fromArray(payloads);
		} else if (input === null || input === void 0) result = RpcPayload.fromAppReturn(input);
		else result = applyMapToElement(input, parent, owner, captures, instructions);
		return new PayloadStubHook(result);
	} finally {
		for (let cap of captures) cap.dispose();
	}
};
var WritableStreamStubHook = class _WritableStreamStubHook extends StubHook {
	state;
	static create(stream) {
		let writer = stream.getWriter();
		return new _WritableStreamStubHook({
			refcount: 1,
			writer,
			closed: false
		});
	}
	constructor(state, dupFrom) {
		super();
		this.state = state;
		if (dupFrom) ++state.refcount;
	}
	getState() {
		if (this.state) return this.state;
		else throw new Error("Attempted to use a WritableStreamStubHook after it was disposed.");
	}
	call(path, args) {
		try {
			let state = this.getState();
			if (path.length !== 1 || typeof path[0] !== "string") throw new Error("WritableStream stub only supports direct method calls");
			const method = path[0];
			if (method !== "write" && method !== "close" && method !== "abort") {
				args.dispose();
				throw new Error(`Unknown WritableStream method: ${method}`);
			}
			if (method === "close" || method === "abort") state.closed = true;
			let func = state.writer[method];
			return new PromiseStubHook(args.deliverCall(func, state.writer).then((payload) => new PayloadStubHook(payload)));
		} catch (err) {
			return new ErrorStubHook(err);
		}
	}
	map(path, captures, instructions) {
		for (let cap of captures) cap.dispose();
		return new ErrorStubHook(/* @__PURE__ */ new Error("Cannot use map() on a WritableStream"));
	}
	get(path) {
		return new ErrorStubHook(/* @__PURE__ */ new Error("Cannot access properties on a WritableStream stub"));
	}
	dup() {
		let state = this.getState();
		return new _WritableStreamStubHook(state, this);
	}
	pull() {
		return Promise.reject(/* @__PURE__ */ new Error("Cannot pull a WritableStream stub"));
	}
	ignoreUnhandledRejections() {}
	dispose() {
		let state = this.state;
		this.state = void 0;
		if (state) {
			if (--state.refcount === 0) {
				if (!state.closed) state.writer.abort(/* @__PURE__ */ new Error("WritableStream RPC stub was disposed without calling close()")).catch(() => {});
				state.writer.releaseLock();
			}
		}
	}
	onBroken(callback) {}
};
var INITIAL_WINDOW = 262144;
var MAX_WINDOW = 1073741824;
var MIN_WINDOW = 65536;
var STARTUP_GROWTH_FACTOR = 2;
var STEADY_GROWTH_FACTOR = 1.25;
var DECAY_FACTOR = .9;
var STARTUP_EXIT_ROUNDS = 3;
var FlowController = class {
	constructor(now) {
		this.now = now;
	}
	window = INITIAL_WINDOW;
	bytesInFlight = 0;
	inStartupPhase = true;
	delivered = 0;
	deliveredTime = 0;
	firstAckTime = 0;
	firstAckDelivered = 0;
	minRtt = Infinity;
	roundsWithoutIncrease = 0;
	lastRoundWindow = 0;
	roundStartTime = 0;
	onSend(size) {
		this.bytesInFlight += size;
		let token = {
			sentTime: this.now(),
			size,
			deliveredAtSend: this.delivered,
			deliveredTimeAtSend: this.deliveredTime,
			windowAtSend: this.window,
			windowFullAtSend: this.bytesInFlight >= this.window
		};
		return {
			token,
			shouldBlock: token.windowFullAtSend
		};
	}
	onError(token) {
		this.bytesInFlight -= token.size;
	}
	onAck(token) {
		let ackTime = this.now();
		this.delivered += token.size;
		this.deliveredTime = ackTime;
		this.bytesInFlight -= token.size;
		let rtt = ackTime - token.sentTime;
		this.minRtt = Math.min(this.minRtt, rtt);
		if (this.firstAckTime === 0) {
			this.firstAckTime = ackTime;
			this.firstAckDelivered = this.delivered;
		} else {
			let baseTime;
			let baseDelivered;
			if (token.deliveredTimeAtSend === 0) {
				baseTime = this.firstAckTime;
				baseDelivered = this.firstAckDelivered;
			} else {
				baseTime = token.deliveredTimeAtSend;
				baseDelivered = token.deliveredAtSend;
			}
			let interval = ackTime - baseTime;
			let bandwidth = (this.delivered - baseDelivered) / interval;
			let growthFactor = this.inStartupPhase ? STARTUP_GROWTH_FACTOR : STEADY_GROWTH_FACTOR;
			let newWindow = bandwidth * this.minRtt * growthFactor;
			newWindow = Math.min(newWindow, token.windowAtSend * growthFactor);
			if (token.windowFullAtSend) newWindow = Math.max(newWindow, token.windowAtSend * DECAY_FACTOR);
			else newWindow = Math.max(newWindow, this.window);
			this.window = Math.max(Math.min(newWindow, MAX_WINDOW), MIN_WINDOW);
			if (this.inStartupPhase && token.sentTime >= this.roundStartTime) {
				if (this.window > this.lastRoundWindow * STEADY_GROWTH_FACTOR) this.roundsWithoutIncrease = 0;
				else if (++this.roundsWithoutIncrease >= STARTUP_EXIT_ROUNDS) this.inStartupPhase = false;
				this.roundStartTime = ackTime;
				this.lastRoundWindow = this.window;
			}
		}
		return this.bytesInFlight < this.window;
	}
};
function createWritableStreamFromHook(hook) {
	let pendingError = void 0;
	let hookDisposed = false;
	let fc = new FlowController(() => performance.now());
	let windowResolve;
	let windowReject;
	const disposeHook = () => {
		if (!hookDisposed) {
			hookDisposed = true;
			hook.dispose();
		}
	};
	return new WritableStream({
		write(chunk, controller) {
			if (pendingError !== void 0) throw pendingError;
			const payload = RpcPayload.fromAppParams([chunk]);
			const { promise, size } = hook.stream(["write"], payload);
			if (size === void 0) return promise.catch((err) => {
				if (pendingError === void 0) pendingError = err;
				throw err;
			});
			else {
				let { token, shouldBlock } = fc.onSend(size);
				promise.then(() => {
					if (fc.onAck(token) && windowResolve) {
						windowResolve();
						windowResolve = void 0;
						windowReject = void 0;
					}
				}, (err) => {
					fc.onError(token);
					if (pendingError === void 0) {
						pendingError = err;
						controller.error(err);
						disposeHook();
					}
					if (windowReject) {
						windowReject(err);
						windowResolve = void 0;
						windowReject = void 0;
					}
				});
				if (shouldBlock) return new Promise((resolve, reject) => {
					windowResolve = resolve;
					windowReject = reject;
				});
			}
		},
		async close() {
			if (pendingError !== void 0) {
				disposeHook();
				throw pendingError;
			}
			const { promise } = hook.stream(["close"], RpcPayload.fromAppParams([]));
			try {
				await promise;
			} catch (err) {
				throw pendingError ?? err;
			} finally {
				disposeHook();
			}
		},
		abort(reason) {
			if (pendingError !== void 0) return;
			pendingError = reason ?? /* @__PURE__ */ new Error("WritableStream was aborted");
			if (windowReject) {
				windowReject(pendingError);
				windowResolve = void 0;
				windowReject = void 0;
			}
			const { promise } = hook.stream(["abort"], RpcPayload.fromAppParams([reason]));
			promise.then(() => disposeHook(), () => disposeHook());
		}
	});
}
var ReadableStreamStubHook = class _ReadableStreamStubHook extends StubHook {
	state;
	static create(stream) {
		return new _ReadableStreamStubHook({
			refcount: 1,
			stream,
			canceled: false
		});
	}
	constructor(state, dupFrom) {
		super();
		this.state = state;
		if (dupFrom) ++state.refcount;
	}
	call(path, args) {
		args.dispose();
		return new ErrorStubHook(/* @__PURE__ */ new Error("Cannot call methods on a ReadableStream stub"));
	}
	map(path, captures, instructions) {
		for (let cap of captures) cap.dispose();
		return new ErrorStubHook(/* @__PURE__ */ new Error("Cannot use map() on a ReadableStream"));
	}
	get(path) {
		return new ErrorStubHook(/* @__PURE__ */ new Error("Cannot access properties on a ReadableStream stub"));
	}
	dup() {
		let state = this.state;
		if (!state) throw new Error("Attempted to dup a ReadableStreamStubHook after it was disposed.");
		return new _ReadableStreamStubHook(state, this);
	}
	pull() {
		return Promise.reject(/* @__PURE__ */ new Error("Cannot pull a ReadableStream stub"));
	}
	ignoreUnhandledRejections() {}
	dispose() {
		let state = this.state;
		this.state = void 0;
		if (state) {
			if (--state.refcount === 0) {
				if (!state.canceled) {
					state.canceled = true;
					if (!state.stream.locked) state.stream.cancel(/* @__PURE__ */ new Error("ReadableStream RPC stub was disposed without being consumed")).catch(() => {});
				}
			}
		}
	}
	onBroken(callback) {}
};
streamImpl.createWritableStreamHook = WritableStreamStubHook.create;
streamImpl.createWritableStreamFromHook = createWritableStreamFromHook;
streamImpl.createReadableStreamHook = ReadableStreamStubHook.create;
var RpcSession2 = RpcSession;
var RpcTarget4 = RpcTarget$1;
// node_modules/@cloudflare/sandbox/dist/sandbox-DlkunMi0.js
/**
* Base SDK error that wraps ErrorResponse
* Preserves all error information from container
*/
var SandboxError = class extends Error {
	constructor(errorResponse, options) {
		super(errorResponse.message, options);
		this.errorResponse = errorResponse;
		this.name = "SandboxError";
	}
	get code() {
		return this.errorResponse.code;
	}
	get context() {
		return this.errorResponse.context;
	}
	get httpStatus() {
		return this.errorResponse.httpStatus;
	}
	get operation() {
		return this.errorResponse.operation;
	}
	get suggestion() {
		return this.errorResponse.suggestion;
	}
	get timestamp() {
		return this.errorResponse.timestamp;
	}
	get documentation() {
		return this.errorResponse.documentation;
	}
	toJSON() {
		return {
			name: this.name,
			message: this.message,
			code: this.code,
			context: this.context,
			httpStatus: this.httpStatus,
			operation: this.operation,
			suggestion: this.suggestion,
			timestamp: this.timestamp,
			documentation: this.documentation,
			stack: this.stack
		};
	}
};
/**
* Error thrown when a file or directory is not found
*/
var FileNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "FileNotFoundError";
	}
	get path() {
		return this.context.path;
	}
};
/**
* Error thrown when a file already exists
*/
var FileExistsError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "FileExistsError";
	}
	get path() {
		return this.context.path;
	}
};
/**
* Error thrown when a file is too large
*/
var FileTooLargeError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "FileTooLargeError";
	}
	get path() {
		return this.context.path;
	}
};
/**
* Generic file system error (permissions, disk full, etc.)
*/
var FileSystemError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "FileSystemError";
	}
	get path() {
		return this.context.path;
	}
	get stderr() {
		return this.context.stderr;
	}
	get exitCode() {
		return this.context.exitCode;
	}
};
/**
* Error thrown when permission is denied
*/
var PermissionDeniedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "PermissionDeniedError";
	}
	get path() {
		return this.context.path;
	}
};
/**
* Error thrown when a command is not found
*/
var CommandNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "CommandNotFoundError";
	}
	get command() {
		return this.context.command;
	}
};
/**
* Generic command execution error
*/
var CommandError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "CommandError";
	}
	get command() {
		return this.context.command;
	}
	get exitCode() {
		return this.context.exitCode;
	}
	get stdout() {
		return this.context.stdout;
	}
	get stderr() {
		return this.context.stderr;
	}
};
/**
* Error thrown when a process is not found
*/
var ProcessNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ProcessNotFoundError";
	}
	get processId() {
		return this.context.processId;
	}
};
/**
* Generic process error
*/
var ProcessError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ProcessError";
	}
	get processId() {
		return this.context.processId;
	}
	get pid() {
		return this.context.pid;
	}
	get exitCode() {
		return this.context.exitCode;
	}
	get stderr() {
		return this.context.stderr;
	}
};
/**
* Error thrown when a session already exists
*/
var SessionAlreadyExistsError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "SessionAlreadyExistsError";
	}
	get sessionId() {
		return this.context.sessionId;
	}
	get containerPlacementId() {
		return this.context.containerPlacementId;
	}
};
/**
* Error thrown when a session was destroyed while a command was executing
*/
var SessionDestroyedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "SessionDestroyedError";
	}
	get sessionId() {
		return this.context.sessionId;
	}
};
/**
* Error thrown when a session's underlying shell exited without an explicit
* `destroy()` call (user ran `exit`, the shell crashed, or a child process
* took the shell down). The session-local state is gone, but the next call
* with the same sessionId will transparently start a fresh session.
*/
var SessionTerminatedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "SessionTerminatedError";
	}
	get sessionId() {
		return this.context.sessionId;
	}
	get exitCode() {
		return this.context.exitCode;
	}
};
/**
* Compatibility error for legacy port exposure registry responses.
*/
var PortAlreadyExposedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "PortAlreadyExposedError";
	}
	get port() {
		return this.context.port;
	}
	get portName() {
		return this.context.portName;
	}
};
/**
* Compatibility error for legacy port exposure registry responses.
*/
var PortNotExposedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "PortNotExposedError";
	}
	get port() {
		return this.context.port;
	}
};
/**
* Error thrown when a port number is invalid
*/
var InvalidPortError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "InvalidPortError";
	}
	get port() {
		return this.context.port;
	}
	get reason() {
		return this.context.reason;
	}
};
/**
* Error thrown when a service on a port is not responding
*/
var ServiceNotRespondingError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ServiceNotRespondingError";
	}
	get port() {
		return this.context.port;
	}
	get portName() {
		return this.context.portName;
	}
};
/**
* Error thrown when a port is already in use
*/
var PortInUseError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "PortInUseError";
	}
	get port() {
		return this.context.port;
	}
};
/**
* Generic port operation error
*/
var PortError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "PortError";
	}
	get port() {
		return this.context.port;
	}
	get portName() {
		return this.context.portName;
	}
	get stderr() {
		return this.context.stderr;
	}
};
/**
* Error thrown when port exposure requires a custom domain
*/
var CustomDomainRequiredError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "CustomDomainRequiredError";
	}
};
/**
* Error thrown when a git repository is not found
*/
var GitRepositoryNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitRepositoryNotFoundError";
	}
	get repository() {
		return this.context.repository;
	}
};
/**
* Error thrown when git authentication fails
*/
var GitAuthenticationError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitAuthenticationError";
	}
	get repository() {
		return this.context.repository;
	}
};
/**
* Error thrown when a git branch is not found
*/
var GitBranchNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitBranchNotFoundError";
	}
	get branch() {
		return this.context.branch;
	}
	get repository() {
		return this.context.repository;
	}
};
/**
* Error thrown when a git network operation fails
*/
var GitNetworkError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitNetworkError";
	}
	get repository() {
		return this.context.repository;
	}
	get branch() {
		return this.context.branch;
	}
	get targetDir() {
		return this.context.targetDir;
	}
};
/**
* Error thrown when git clone fails
*/
var GitCloneError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitCloneError";
	}
	get repository() {
		return this.context.repository;
	}
	get targetDir() {
		return this.context.targetDir;
	}
	get stderr() {
		return this.context.stderr;
	}
	get exitCode() {
		return this.context.exitCode;
	}
};
/**
* Error thrown when git checkout fails
*/
var GitCheckoutError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitCheckoutError";
	}
	get branch() {
		return this.context.branch;
	}
	get repository() {
		return this.context.repository;
	}
	get stderr() {
		return this.context.stderr;
	}
};
/**
* Error thrown when a git URL is invalid
*/
var InvalidGitUrlError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "InvalidGitUrlError";
	}
	get validationErrors() {
		return this.context.validationErrors;
	}
};
/**
* Generic git operation error
*/
var GitError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "GitError";
	}
	get repository() {
		return this.context.repository;
	}
	get branch() {
		return this.context.branch;
	}
	get targetDir() {
		return this.context.targetDir;
	}
	get stderr() {
		return this.context.stderr;
	}
	get exitCode() {
		return this.context.exitCode;
	}
};
/**
* Error thrown when interpreter is not ready
*/
var InterpreterNotReadyError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "InterpreterNotReadyError";
	}
	get retryAfter() {
		return this.context.retryAfter;
	}
	get progress() {
		return this.context.progress;
	}
};
/**
* Error thrown when a context is not found
*/
var ContextNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ContextNotFoundError";
	}
	get contextId() {
		return this.context.contextId;
	}
};
/**
* Error thrown when code execution fails
*/
var CodeExecutionError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "CodeExecutionError";
	}
	get contextId() {
		return this.context.contextId;
	}
	get ename() {
		return this.context.ename;
	}
	get evalue() {
		return this.context.evalue;
	}
	get traceback() {
		return this.context.traceback;
	}
};
/**
* Error thrown when validation fails
*/
var ValidationFailedError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ValidationFailedError";
	}
	get validationErrors() {
		return this.context.validationErrors;
	}
};
/**
* Error thrown when a process does not become ready within the timeout period
*/
var ProcessReadyTimeoutError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ProcessReadyTimeoutError";
	}
	get processId() {
		return this.context.processId;
	}
	get command() {
		return this.context.command;
	}
	get condition() {
		return this.context.condition;
	}
	get timeout() {
		return this.context.timeout;
	}
};
/**
* Error thrown when a process exits before becoming ready
*/
var ProcessExitedBeforeReadyError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ProcessExitedBeforeReadyError";
	}
	get processId() {
		return this.context.processId;
	}
	get command() {
		return this.context.command;
	}
	get condition() {
		return this.context.condition;
	}
	get exitCode() {
		return this.context.exitCode;
	}
};
/**
* Error thrown when a backup is not found in R2
*/
var BackupNotFoundError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "BackupNotFoundError";
	}
	get backupId() {
		return this.context.backupId;
	}
};
/**
* Error thrown when a backup has expired (past its TTL)
*/
var BackupExpiredError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "BackupExpiredError";
	}
	get backupId() {
		return this.context.backupId;
	}
	get expiredAt() {
		return this.context.expiredAt;
	}
};
/**
* Error thrown when backup configuration or inputs are invalid
*/
var InvalidBackupConfigError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "InvalidBackupConfigError";
	}
	get reason() {
		return this.context.reason;
	}
};
/**
* Error thrown when backup creation fails
*/
var BackupCreateError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "BackupCreateError";
	}
	get dir() {
		return this.context.dir;
	}
	get backupId() {
		return this.context.backupId;
	}
};
/**
* Error thrown when backup restoration fails
*/
var BackupRestoreError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "BackupRestoreError";
	}
	get dir() {
		return this.context.dir;
	}
	get backupId() {
		return this.context.backupId;
	}
};
/**
* Raised when the sandbox container cannot accept an incoming RPC connection.
* The container may be starting up, temporarily unhealthy, or was replaced
* while the connection attempt was in progress.
*
* Always retryable: the operation that triggered the connection attempt can
* be retried once the container is ready.
*/
var ContainerUnavailableError = class extends SandboxError {
	constructor(errorResponse) {
		super(errorResponse);
		this.name = "ContainerUnavailableError";
	}
	get reason() {
		return this.context.reason;
	}
	get retryAfterMs() {
		return this.context.retryAfterMs;
	}
};
/**
* Raised when the capnweb WebSocket session itself fails on the SDK side.
* Unlike the rest of the SandboxError tree, the container never produces
* this error — it is synthesised by `translateRPCError` from the plain
* Errors capnweb / DeferredTransport raise when the connection dies.
*
* `kind` distinguishes the failure mode (peer close, upgrade failed, etc.)
* so callers can branch on a structured code instead of substring-matching
* on the message.
*
* Always retryable: the SDK opens a fresh connection on the next call.
*/
var RPCTransportError = class extends SandboxError {
	constructor(errorResponse, options) {
		super(errorResponse, options);
		this.name = "RPCTransportError";
	}
	get kind() {
		return this.errorResponse.context.kind;
	}
	get originalMessage() {
		return this.errorResponse.context.originalMessage;
	}
};
/**
* Raised when a sandbox-owned operation was interrupted by a runtime
* replacement or sandbox lifetime change after the operation was admitted.
* The caller can retry the full operation when `context.retryable` is true.
*/
var OperationInterruptedError = class extends SandboxError {
	constructor(errorResponse, options) {
		super(errorResponse, options);
		this.name = "OperationInterruptedError";
	}
	get reason() {
		return this.context.reason;
	}
};
/**
* Convert ErrorResponse to appropriate Error class
* Simple switch statement - we trust the container sends correct context
*/
function createErrorFromResponse(errorResponse, options) {
	switch (errorResponse.code) {
		case ErrorCode.FILE_NOT_FOUND: return new FileNotFoundError(errorResponse);
		case ErrorCode.FILE_EXISTS: return new FileExistsError(errorResponse);
		case ErrorCode.FILE_TOO_LARGE: return new FileTooLargeError(errorResponse);
		case ErrorCode.PERMISSION_DENIED: return new PermissionDeniedError(errorResponse);
		case ErrorCode.IS_DIRECTORY:
		case ErrorCode.NOT_DIRECTORY:
		case ErrorCode.NO_SPACE:
		case ErrorCode.TOO_MANY_FILES:
		case ErrorCode.RESOURCE_BUSY:
		case ErrorCode.READ_ONLY:
		case ErrorCode.NAME_TOO_LONG:
		case ErrorCode.TOO_MANY_LINKS:
		case ErrorCode.FILESYSTEM_ERROR: return new FileSystemError(errorResponse);
		case ErrorCode.COMMAND_NOT_FOUND: return new CommandNotFoundError(errorResponse);
		case ErrorCode.COMMAND_PERMISSION_DENIED:
		case ErrorCode.COMMAND_EXECUTION_ERROR:
		case ErrorCode.INVALID_COMMAND:
		case ErrorCode.STREAM_START_ERROR: return new CommandError(errorResponse);
		case ErrorCode.PROCESS_NOT_FOUND: return new ProcessNotFoundError(errorResponse);
		case ErrorCode.PROCESS_PERMISSION_DENIED:
		case ErrorCode.PROCESS_ERROR: return new ProcessError(errorResponse);
		case ErrorCode.SESSION_ALREADY_EXISTS: return new SessionAlreadyExistsError(errorResponse);
		case ErrorCode.SESSION_DESTROYED: return new SessionDestroyedError(errorResponse);
		case ErrorCode.SESSION_TERMINATED: return new SessionTerminatedError(errorResponse);
		case ErrorCode.PORT_ALREADY_EXPOSED: return new PortAlreadyExposedError(errorResponse);
		case ErrorCode.PORT_NOT_EXPOSED: return new PortNotExposedError(errorResponse);
		case ErrorCode.INVALID_PORT_NUMBER:
		case ErrorCode.INVALID_PORT: return new InvalidPortError(errorResponse);
		case ErrorCode.SERVICE_NOT_RESPONDING: return new ServiceNotRespondingError(errorResponse);
		case ErrorCode.PORT_IN_USE: return new PortInUseError(errorResponse);
		case ErrorCode.PORT_OPERATION_ERROR: return new PortError(errorResponse);
		case ErrorCode.CUSTOM_DOMAIN_REQUIRED: return new CustomDomainRequiredError(errorResponse);
		case ErrorCode.GIT_REPOSITORY_NOT_FOUND: return new GitRepositoryNotFoundError(errorResponse);
		case ErrorCode.GIT_AUTH_FAILED: return new GitAuthenticationError(errorResponse);
		case ErrorCode.GIT_BRANCH_NOT_FOUND: return new GitBranchNotFoundError(errorResponse);
		case ErrorCode.GIT_NETWORK_ERROR: return new GitNetworkError(errorResponse);
		case ErrorCode.GIT_CLONE_FAILED: return new GitCloneError(errorResponse);
		case ErrorCode.GIT_CHECKOUT_FAILED: return new GitCheckoutError(errorResponse);
		case ErrorCode.INVALID_GIT_URL: return new InvalidGitUrlError(errorResponse);
		case ErrorCode.GIT_OPERATION_FAILED: return new GitError(errorResponse);
		case ErrorCode.BACKUP_NOT_FOUND: return new BackupNotFoundError(errorResponse);
		case ErrorCode.BACKUP_EXPIRED: return new BackupExpiredError(errorResponse);
		case ErrorCode.INVALID_BACKUP_CONFIG: return new InvalidBackupConfigError(errorResponse);
		case ErrorCode.BACKUP_CREATE_FAILED: return new BackupCreateError(errorResponse);
		case ErrorCode.BACKUP_RESTORE_FAILED: return new BackupRestoreError(errorResponse);
		case ErrorCode.INTERPRETER_NOT_READY: return new InterpreterNotReadyError(errorResponse);
		case ErrorCode.CONTEXT_NOT_FOUND: return new ContextNotFoundError(errorResponse);
		case ErrorCode.CODE_EXECUTION_ERROR: return new CodeExecutionError(errorResponse);
		case ErrorCode.OPERATION_INTERRUPTED: return new OperationInterruptedError(errorResponse, options);
		case ErrorCode.CONTAINER_UNAVAILABLE: return new ContainerUnavailableError(errorResponse);
		case ErrorCode.RPC_TRANSPORT_ERROR: return new RPCTransportError(errorResponse, options);
		case ErrorCode.VALIDATION_FAILED: return new ValidationFailedError(errorResponse);
		case ErrorCode.INVALID_JSON_RESPONSE:
		case ErrorCode.UNKNOWN_ERROR:
		case ErrorCode.INTERNAL_ERROR: return new SandboxError(errorResponse);
		default: return new SandboxError(errorResponse);
	}
}
var DEFAULT_INITIAL_RETRY_DELAY_MS = 3e3;
var DEFAULT_MAX_RETRY_DELAY_MS = 3e4;
var RETRYABLE_WEBSOCKET_UPGRADE_STATUSES = /* @__PURE__ */ new Set([
	500,
	502,
	503,
	504
]);
function isRetryableWebSocketUpgradeResponse(response) {
	return RETRYABLE_WEBSOCKET_UPGRADE_STATUSES.has(response.status);
}
/**
* Compute the next backoff delay from the remaining retry budget. Returns null
* when another attempt should not begin.
*
* Delay is limited to the budget left after reserving `minTimeForRetryMs` for
* the subsequent attempt. An attempt already in progress owns its own
* per-request timeouts via the caller-provided `fetchResponse` function.
*/
function nextRetryDelayMs(attempt, remainingMs, minTimeForRetryMs) {
	const availableForDelay = remainingMs - minTimeForRetryMs;
	if (availableForDelay <= 0) return null;
	const computedDelay = Math.min(DEFAULT_INITIAL_RETRY_DELAY_MS * 2 ** attempt, DEFAULT_MAX_RETRY_DELAY_MS);
	return Math.min(computedDelay, availableForDelay);
}
/**
* Retry Response-returning operations while their response remains retryable.
*
* The retry budget decides whether another attempt may begin after a retryable
* response or thrown error. Each attempt owns any per-request timeout inside
* the caller-provided `fetchResponse` function. Backoff is limited to the
* remaining budget after reserving `minTimeForRetryMs` for that next attempt.
*/
async function fetchWithResponseRetry(fetchResponse, options) {
	const startTime = Date.now();
	let attempt = 0;
	while (true) {
		let response;
		try {
			response = await fetchResponse();
		} catch (error) {
			if (!options.shouldRetryError?.(error)) throw error;
			const elapsed$1 = Date.now() - startTime;
			const remaining$1 = options.retryTimeoutMs - elapsed$1;
			const delay$1 = nextRetryDelayMs(attempt, remaining$1, options.minTimeForRetryMs);
			if (delay$1 === null) throw error;
			options.logger.info(options.retryLogMessage, {
				attempt: attempt + 1,
				delayMs: delay$1,
				remainingSec: Math.floor(remaining$1 / 1e3),
				error: error instanceof Error ? error.message : String(error)
			});
			await new Promise((resolve) => setTimeout(resolve, delay$1));
			attempt++;
			continue;
		}
		if (!options.shouldRetry(response)) return response;
		const elapsed = Date.now() - startTime;
		const remaining = options.retryTimeoutMs - elapsed;
		const delay = nextRetryDelayMs(attempt, remaining, options.minTimeForRetryMs);
		if (delay === null) {
			options.onRetryExhausted?.({
				attempts: attempt + 1,
				elapsedMs: elapsed,
				response
			});
			return response;
		}
		options.logger.info(options.retryLogMessage, {
			status: response.status,
			attempt: attempt + 1,
			delayMs: delay,
			remainingSec: Math.floor(remaining / 1e3),
			...options.getRetryLogContext?.(response)
		});
		await new Promise((resolve) => setTimeout(resolve, delay));
		attempt++;
	}
}
/**
* Container startup retry configuration
*/
var DEFAULT_RETRY_TIMEOUT_MS$1 = 12e4;
var MIN_TIME_FOR_RETRY_MS$1 = 15e3;
/**
* Abstract base transport with shared retry logic
*
* Handles 503 retry for container startup - shared by all transports.
* Subclasses implement the transport-specific fetch and stream logic.
*/
var BaseTransport = class {
	config;
	logger;
	retryTimeoutMs;
	constructor(config) {
		this.config = config;
		this.logger = config.logger ?? createNoOpLogger();
		this.retryTimeoutMs = config.retryTimeoutMs ?? DEFAULT_RETRY_TIMEOUT_MS$1;
	}
	setRetryTimeoutMs(ms) {
		this.retryTimeoutMs = ms;
	}
	getRetryTimeoutMs() {
		return this.retryTimeoutMs;
	}
	/**
	* Fetch with automatic retry for 503 (container starting)
	*
	* This is the primary entry point for making requests. It wraps the
	* transport-specific doFetch() with retry logic for container startup.
	*/
	async fetch(path$1, options) {
		return fetchWithResponseRetry(() => this.doFetch(path$1, options), {
			retryTimeoutMs: this.retryTimeoutMs,
			minTimeForRetryMs: MIN_TIME_FOR_RETRY_MS$1,
			logger: this.logger,
			retryLogMessage: "Container not ready, retrying",
			shouldRetry: (response) => response.status === 503,
			getRetryLogContext: () => ({ mode: this.getMode() }),
			onRetryExhausted: ({ attempts, elapsedMs }) => {
				this.logger.error("Container failed to become ready", /* @__PURE__ */ new Error(`Failed after ${attempts} attempts over ${Math.floor(elapsedMs / 1e3)}s`));
			}
		});
	}
	/**
	* Build a URL targeting the container's HTTP server.
	*/
	buildContainerUrl(path$1) {
		if (this.config.stub) return `http://localhost:${this.config.port || 3e3}${path$1}`;
		return `${this.config.baseUrl ?? `http://localhost:${this.config.port || 3e3}`}${path$1}`;
	}
	/**
	* Single HTTP request to the container — no WebSocket, no 503 retry.
	*/
	httpFetch(path$1, options) {
		const url = this.buildContainerUrl(path$1);
		if (this.config.stub) return this.config.stub.containerFetch(url, options || {}, this.config.port);
		return globalThis.fetch(url, options);
	}
	/**
	* Streaming HTTP request to the container — no WebSocket, no 503 retry.
	*/
	async httpFetchStream(path$1, body, method = "POST", headers) {
		const url = this.buildContainerUrl(path$1);
		const init = {
			method,
			headers: body && method === "POST" ? {
				...headers,
				"Content-Type": "application/json"
			} : headers,
			body: body && method === "POST" ? JSON.stringify(body) : void 0
		};
		let response;
		if (this.config.stub) response = await this.config.stub.containerFetch(url, init, this.config.port);
		else response = await globalThis.fetch(url, init);
		if (!response.ok) {
			const errorBody = await response.text();
			throw new Error(`HTTP error! status: ${response.status} - ${errorBody}`);
		}
		if (!response.body) throw new Error("No response body for streaming");
		return response.body;
	}
};
/**
* HTTP transport implementation
*
* Uses standard fetch API for communication with the container.
* HTTP is stateless, so connect/disconnect are no-ops.
*
* All HTTP request logic lives in {@link BaseTransport.httpFetch} and
* {@link BaseTransport.httpFetchStream}; this subclass simply wires
* the abstract `doFetch` / `fetchStream` hooks to those shared helpers.
*/
var HttpTransport = class extends BaseTransport {
	getMode() {
		return "http";
	}
	async connect() {}
	disconnect() {}
	isConnected() {
		return true;
	}
	async doFetch(path$1, options) {
		return this.httpFetch(path$1, options);
	}
	async fetchStream(path$1, body, method = "POST", headers) {
		return this.httpFetchStream(path$1, body, method, headers);
	}
};
/**
* Default timeout values (all in milliseconds)
*/
var DEFAULT_REQUEST_TIMEOUT_MS = 12e4;
var DEFAULT_STREAM_IDLE_TIMEOUT_MS = 3e5;
var DEFAULT_CONNECT_TIMEOUT_MS$1 = 3e4;
var DEFAULT_IDLE_DISCONNECT_MS$1 = 1e3;
var MIN_TIME_FOR_CONNECT_RETRY_MS = 15e3;
/**
* WebSocket transport implementation
*
* Multiplexes HTTP-like requests over a single WebSocket connection.
* Useful when running inside Workers/DO where sub-request limits apply.
*/
var WebSocketTransport = class extends BaseTransport {
	ws = null;
	state = "disconnected";
	pendingRequests = /* @__PURE__ */ new Map();
	connectPromise = null;
	idleDisconnectTimer = null;
	boundHandleMessage;
	boundHandleClose;
	constructor(config) {
		super(config);
		if (!config.wsUrl) throw new Error("wsUrl is required for WebSocket transport");
		this.boundHandleMessage = this.handleMessage.bind(this);
		this.boundHandleClose = this.handleClose.bind(this);
	}
	getMode() {
		return "websocket";
	}
	/**
	* Check if WebSocket is connected
	*/
	isConnected() {
		return this.state === "connected" && this.ws?.readyState === WebSocket.OPEN;
	}
	/**
	* Connect to the WebSocket server
	*
	* The connection promise is assigned synchronously so concurrent
	* callers share the same connection attempt.
	*/
	async connect() {
		this.clearIdleDisconnectTimer();
		if (this.isConnected()) return;
		if (this.connectPromise) return this.connectPromise;
		this.connectPromise = this.doConnect();
		try {
			await this.connectPromise;
		} finally {
			this.connectPromise = null;
		}
	}
	/**
	* Disconnect from the WebSocket server
	*/
	disconnect() {
		this.cleanup();
	}
	/**
	* Whether a WebSocket connection is currently being established.
	*
	* When true, awaiting `connectPromise` from a nested call would deadlock:
	* the outer `connectViaFetch → stub.fetch → containerFetch →
	* startAndWaitForPorts → blockConcurrencyWhile(onStart)` chain may call
	* back into the SDK (e.g. `exec()`), which would await the same
	* `connectPromise` that cannot resolve until `onStart` returns.
	*
	* Callers use this to fall back to a direct HTTP request, which is safe
	* because `startAndWaitForPorts()` calls `setHealthy()` before invoking
	* `onStart()`, so `containerFetch()` routes directly to the container.
	*/
	isWebSocketConnecting() {
		return this.state === "connecting";
	}
	/**
	* Transport-specific fetch implementation.
	* Converts WebSocket response to standard Response object.
	*
	* Falls back to HTTP while a WebSocket connection is being established
	* to avoid the re-entrant deadlock described in `isWebSocketConnecting()`.
	*/
	async doFetch(path$1, options) {
		if (this.isWebSocketConnecting()) return this.httpFetch(path$1, options);
		await this.connect();
		const method = options?.method || "GET";
		const body = this.parseBody(options?.body);
		const headers = this.normalizeHeaders(options?.headers);
		const result = await this.request(method, path$1, body, headers, options?.requestTimeoutMs);
		return new Response(JSON.stringify(result.body), {
			status: result.status,
			headers: { "Content-Type": "application/json" }
		});
	}
	/**
	* Streaming fetch implementation.
	*
	* Delegates to `requestStream()`, which applies the re-entrancy guard.
	*/
	async fetchStream(path$1, body, method = "POST", headers) {
		return this.requestStream(method, path$1, body, headers);
	}
	/**
	* Parse request body from RequestInit
	*/
	parseBody(body) {
		if (!body) return;
		if (typeof body === "string") try {
			return JSON.parse(body);
		} catch (error) {
			throw new Error(`Request body must be valid JSON: ${error instanceof Error ? error.message : String(error)}`);
		}
		throw new Error(`WebSocket transport only supports string bodies. Got: ${typeof body}`);
	}
	/**
	* Normalize RequestInit headers into a plain object for WSRequest.
	*/
	normalizeHeaders(headers) {
		if (!headers) return;
		const normalized = {};
		new Headers(headers).forEach((value, key) => {
			normalized[key] = value;
		});
		return Object.keys(normalized).length > 0 ? normalized : void 0;
	}
	/**
	* Internal connection logic
	*/
	async doConnect() {
		this.state = "connecting";
		if (this.config.stub) await this.connectViaFetch();
		else await this.connectViaWebSocket();
	}
	async fetchUpgradeWithRetry(attemptUpgrade) {
		return fetchWithResponseRetry(attemptUpgrade, {
			retryTimeoutMs: this.getRetryTimeoutMs(),
			minTimeForRetryMs: MIN_TIME_FOR_CONNECT_RETRY_MS,
			logger: this.logger,
			retryLogMessage: "WebSocket upgrade returned retryable status, retrying",
			shouldRetry: isRetryableWebSocketUpgradeResponse
		});
	}
	/**
	* Connect using fetch-based WebSocket (Cloudflare Workers style)
	* This is required when running inside a Durable Object.
	*
	* Uses stub.fetch() which routes WebSocket upgrade requests through the
	* parent Container class that supports the WebSocket protocol.
	*/
	async connectViaFetch() {
		const timeoutMs = this.config.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS$1;
		try {
			const wsPath = new URL(this.config.wsUrl).pathname;
			const httpUrl = `http://localhost:${this.config.port || 3e3}${wsPath}`;
			const response = await this.fetchUpgradeWithRetry(() => this.fetchUpgradeAttempt(httpUrl, timeoutMs));
			if (response.status !== 101) throw new Error(`WebSocket upgrade failed: ${response.status} ${response.statusText}`);
			const ws = response.webSocket;
			if (!ws) throw new Error("No WebSocket in upgrade response");
			ws.accept();
			this.ws = ws;
			this.state = "connected";
			this.ws.addEventListener("close", this.boundHandleClose);
			this.ws.addEventListener("message", this.boundHandleMessage);
			this.logger.debug("WebSocket connected via fetch", { url: this.config.wsUrl });
		} catch (error) {
			this.state = "error";
			this.logger.error("WebSocket fetch connection failed", error instanceof Error ? error : new Error(String(error)));
			throw error;
		}
	}
	async fetchUpgradeAttempt(httpUrl, timeoutMs) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const request = new Request(httpUrl, {
				headers: {
					Upgrade: "websocket",
					Connection: "Upgrade"
				},
				signal: controller.signal
			});
			return await this.config.stub.fetch(request);
		} finally {
			clearTimeout(timeout);
		}
	}
	/**
	* Connect using standard WebSocket API (browser/Node style)
	*/
	connectViaWebSocket() {
		return new Promise((resolve, reject) => {
			const timeoutMs = this.config.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS$1;
			const timeout = setTimeout(() => {
				this.cleanup();
				reject(/* @__PURE__ */ new Error(`WebSocket connection timeout after ${timeoutMs}ms`));
			}, timeoutMs);
			try {
				this.ws = new WebSocket(this.config.wsUrl);
				const onOpen = () => {
					clearTimeout(timeout);
					this.ws?.removeEventListener("open", onOpen);
					this.ws?.removeEventListener("error", onConnectError);
					this.state = "connected";
					this.logger.debug("WebSocket connected", { url: this.config.wsUrl });
					resolve();
				};
				const onConnectError = () => {
					clearTimeout(timeout);
					this.ws?.removeEventListener("open", onOpen);
					this.ws?.removeEventListener("error", onConnectError);
					this.state = "error";
					this.logger.error("WebSocket error", /* @__PURE__ */ new Error("WebSocket connection failed"));
					reject(/* @__PURE__ */ new Error("WebSocket connection failed"));
				};
				this.ws.addEventListener("open", onOpen);
				this.ws.addEventListener("error", onConnectError);
				this.ws.addEventListener("close", this.boundHandleClose);
				this.ws.addEventListener("message", this.boundHandleMessage);
			} catch (error) {
				clearTimeout(timeout);
				this.state = "error";
				reject(error);
			}
		});
	}
	/**
	* Send a request and wait for response.
	*
	* Only reachable from `doFetch()`, which already applies the re-entrancy
	* guard via `isWebSocketConnecting()`. The `connect()` call here handles
	* the case where the WebSocket was closed between `doFetch` and `request`
	* (idle disconnect).
	*/
	async request(method, path$1, body, headers, requestTimeoutMs) {
		await this.connect();
		this.clearIdleDisconnectTimer();
		const id = generateRequestId();
		const request = {
			type: "request",
			id,
			method,
			path: path$1,
			body,
			headers
		};
		return new Promise((resolve, reject) => {
			const timeoutMs = requestTimeoutMs ?? this.config.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
			const timeoutId = setTimeout(() => {
				this.pendingRequests.delete(id);
				this.scheduleIdleDisconnect();
				reject(/* @__PURE__ */ new Error(`Request timeout after ${timeoutMs}ms: ${method} ${path$1}`));
			}, timeoutMs);
			this.pendingRequests.set(id, {
				resolve: (response) => {
					clearTimeout(timeoutId);
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
					resolve({
						status: response.status,
						body: response.body
					});
				},
				reject: (error) => {
					clearTimeout(timeoutId);
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
					reject(error);
				},
				isStreaming: false,
				timeoutId
			});
			try {
				this.send(request);
			} catch (error) {
				clearTimeout(timeoutId);
				this.pendingRequests.delete(id);
				this.scheduleIdleDisconnect();
				reject(error instanceof Error ? error : new Error(String(error)));
			}
		});
	}
	/**
	* Send a streaming request and return a ReadableStream.
	*
	* The stream will receive data chunks as they arrive over the WebSocket.
	* Format matches SSE for compatibility with existing streaming code.
	*
	* This method waits for the first message before returning. If the server
	* responds with an error (non-streaming response), it throws immediately
	* rather than returning a stream that will error later.
	*
	* Uses an inactivity timeout instead of a total-duration timeout so that
	* long-running streams (e.g. execStream from an agent) stay alive as long
	* as data is flowing. The timer resets on every chunk or response message.
	*
	* Falls back to HTTP while a WebSocket connection is being established
	* to avoid the re-entrant deadlock described in `isWebSocketConnecting()`.
	*/
	async requestStream(method, path$1, body, headers) {
		if (this.isWebSocketConnecting()) return this.httpFetchStream(path$1, body, method, headers);
		await this.connect();
		this.clearIdleDisconnectTimer();
		const id = generateRequestId();
		const request = {
			type: "request",
			id,
			method,
			path: path$1,
			body,
			headers
		};
		const idleTimeoutMs = this.config.streamIdleTimeoutMs ?? DEFAULT_STREAM_IDLE_TIMEOUT_MS;
		return new Promise((resolveStream, rejectStream) => {
			let streamController;
			let firstMessageReceived = false;
			const createIdleTimeout = () => {
				return setTimeout(() => {
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
					const error = /* @__PURE__ */ new Error(`Stream idle timeout after ${idleTimeoutMs}ms: ${method} ${path$1}`);
					if (firstMessageReceived) try {
						streamController?.error(error);
					} catch {}
					else rejectStream(error);
				}, idleTimeoutMs);
			};
			const timeoutId = createIdleTimeout();
			const stream = new ReadableStream({
				start: (controller) => {
					streamController = controller;
				},
				cancel: () => {
					const pending = this.pendingRequests.get(id);
					if (pending?.timeoutId) clearTimeout(pending.timeoutId);
					try {
						this.send({
							type: "cancel",
							id
						});
					} catch (error) {
						this.logger.debug("Failed to send stream cancel message", {
							id,
							error: error instanceof Error ? error.message : String(error)
						});
					}
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
				}
			});
			this.pendingRequests.set(id, {
				resolve: (response) => {
					const pending = this.pendingRequests.get(id);
					if (pending?.timeoutId) clearTimeout(pending.timeoutId);
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
					if (!firstMessageReceived) {
						firstMessageReceived = true;
						if (response.status >= 400) rejectStream(/* @__PURE__ */ new Error(`Stream error: ${response.status} - ${JSON.stringify(response.body)}`));
						else {
							streamController?.close();
							resolveStream(stream);
						}
					} else if (response.status >= 400) try {
						streamController?.error(/* @__PURE__ */ new Error(`Stream error: ${response.status} - ${JSON.stringify(response.body)}`));
					} catch {}
					else streamController?.close();
				},
				reject: (error) => {
					const pending = this.pendingRequests.get(id);
					if (pending?.timeoutId) clearTimeout(pending.timeoutId);
					this.pendingRequests.delete(id);
					this.scheduleIdleDisconnect();
					if (firstMessageReceived) try {
						streamController?.error(error);
					} catch {}
					else rejectStream(error);
				},
				streamController: void 0,
				isStreaming: true,
				timeoutId,
				onFirstChunk: () => {
					if (!firstMessageReceived) {
						firstMessageReceived = true;
						const pending = this.pendingRequests.get(id);
						if (pending) {
							pending.streamController = streamController;
							if (pending.bufferedChunks) {
								try {
									for (const buffered of pending.bufferedChunks) streamController.enqueue(buffered);
								} catch (error) {
									this.logger.debug("Failed to flush buffered chunks, cleaning up", {
										id,
										error: error instanceof Error ? error.message : String(error)
									});
									if (pending.timeoutId) clearTimeout(pending.timeoutId);
									this.pendingRequests.delete(id);
									this.scheduleIdleDisconnect();
								}
								pending.bufferedChunks = void 0;
							}
						}
						resolveStream(stream);
					}
				}
			});
			try {
				this.send(request);
			} catch (error) {
				clearTimeout(timeoutId);
				this.pendingRequests.delete(id);
				this.scheduleIdleDisconnect();
				rejectStream(error instanceof Error ? error : new Error(String(error)));
			}
		});
	}
	/**
	* Send a message over the WebSocket
	*/
	send(message) {
		if (!this.ws || this.ws.readyState !== WebSocket.OPEN) throw new Error("WebSocket not connected");
		this.ws.send(JSON.stringify(message));
		this.logger.debug("WebSocket sent", {
			id: message.id,
			type: message.type,
			method: message.type === "request" ? message.method : void 0,
			path: message.type === "request" ? message.path : void 0
		});
	}
	/**
	* Handle incoming WebSocket messages
	*/
	handleMessage(event) {
		try {
			const message = JSON.parse(event.data);
			if (isWSResponse(message)) this.handleResponse(message);
			else if (isWSStreamChunk(message)) this.handleStreamChunk(message);
			else if (isWSError(message)) this.handleError(message);
			else this.logger.warn("Unknown WebSocket message type", { message });
		} catch (error) {
			this.logger.error("Failed to parse WebSocket message", error instanceof Error ? error : new Error(String(error)));
		}
	}
	/**
	* Handle a response message
	*/
	handleResponse(response) {
		const pending = this.pendingRequests.get(response.id);
		if (!pending) {
			this.logger.warn("Received response for unknown request", { id: response.id });
			return;
		}
		this.logger.debug("WebSocket response", {
			id: response.id,
			status: response.status,
			done: response.done
		});
		if (response.done) pending.resolve(response);
	}
	/**
	* Handle a stream chunk message
	*
	* Resets the idle timeout on every chunk so that long-running streams
	* with continuous output are not killed by the inactivity timer.
	*/
	handleStreamChunk(chunk) {
		const pending = this.pendingRequests.get(chunk.id);
		if (!pending) {
			this.logger.warn("Received stream chunk for unknown request", { id: chunk.id });
			return;
		}
		if (pending.onFirstChunk) {
			pending.onFirstChunk();
			pending.onFirstChunk = void 0;
		}
		if (pending.isStreaming) this.resetStreamIdleTimeout(chunk.id, pending);
		if (chunk.event === "keepalive") return;
		if (!pending.streamController) {
			if (!pending.bufferedChunks) pending.bufferedChunks = [];
			const encoder$1 = new TextEncoder();
			let sseData$1;
			if (chunk.event) sseData$1 = `event: ${chunk.event}\ndata: ${chunk.data}\n\n`;
			else sseData$1 = `data: ${chunk.data}\n\n`;
			pending.bufferedChunks.push(encoder$1.encode(sseData$1));
			return;
		}
		const encoder = new TextEncoder();
		let sseData;
		if (chunk.event) sseData = `event: ${chunk.event}\ndata: ${chunk.data}\n\n`;
		else sseData = `data: ${chunk.data}\n\n`;
		try {
			pending.streamController.enqueue(encoder.encode(sseData));
		} catch (error) {
			this.logger.debug("Failed to enqueue stream chunk, cleaning up", {
				id: chunk.id,
				error: error instanceof Error ? error.message : String(error)
			});
			if (pending.timeoutId) clearTimeout(pending.timeoutId);
			this.pendingRequests.delete(chunk.id);
			this.scheduleIdleDisconnect();
		}
	}
	/**
	* Reset the idle timeout for a streaming request.
	* Called on every incoming chunk to keep the stream alive while data flows.
	*/
	resetStreamIdleTimeout(id, pending) {
		if (pending.timeoutId) clearTimeout(pending.timeoutId);
		const idleTimeoutMs = this.config.streamIdleTimeoutMs ?? DEFAULT_STREAM_IDLE_TIMEOUT_MS;
		pending.timeoutId = setTimeout(() => {
			this.pendingRequests.delete(id);
			this.scheduleIdleDisconnect();
			if (pending.streamController) try {
				pending.streamController.error(/* @__PURE__ */ new Error(`Stream idle timeout after ${idleTimeoutMs}ms`));
			} catch {}
		}, idleTimeoutMs);
	}
	/**
	* Handle an error message
	*/
	handleError(error) {
		if (error.id) {
			const pending = this.pendingRequests.get(error.id);
			if (pending) {
				pending.reject(/* @__PURE__ */ new Error(`${error.code}: ${error.message}`));
				return;
			}
		}
		this.logger.error("WebSocket error message", new Error(error.message), {
			code: error.code,
			status: error.status
		});
	}
	/**
	* Handle WebSocket close
	*/
	handleClose(event) {
		this.state = "disconnected";
		this.ws = null;
		this.connectPromise = null;
		const closeError = /* @__PURE__ */ new Error(`WebSocket closed: ${event.code} ${event.reason || "No reason"}`);
		for (const [, pending] of this.pendingRequests) {
			if (pending.timeoutId) clearTimeout(pending.timeoutId);
			if (pending.streamController) try {
				pending.streamController.error(closeError);
			} catch {}
			pending.reject(closeError);
		}
		this.pendingRequests.clear();
	}
	/**
	* Cleanup resources
	*/
	cleanup() {
		this.clearIdleDisconnectTimer();
		if (this.ws) {
			this.ws.removeEventListener("close", this.boundHandleClose);
			this.ws.removeEventListener("message", this.boundHandleMessage);
			this.ws.close();
			this.ws = null;
		}
		this.state = "disconnected";
		this.connectPromise = null;
		for (const pending of this.pendingRequests.values()) if (pending.timeoutId) clearTimeout(pending.timeoutId);
		this.pendingRequests.clear();
	}
	scheduleIdleDisconnect() {
		if (!this.isConnected() || this.pendingRequests.size > 0) return;
		this.clearIdleDisconnectTimer();
		this.idleDisconnectTimer = setTimeout(() => {
			this.idleDisconnectTimer = null;
			if (this.pendingRequests.size === 0 && this.isConnected()) {
				this.logger.debug("Disconnecting idle WebSocket transport");
				this.cleanup();
			}
		}, DEFAULT_IDLE_DISCONNECT_MS$1);
	}
	clearIdleDisconnectTimer() {
		if (this.idleDisconnectTimer) {
			clearTimeout(this.idleDisconnectTimer);
			this.idleDisconnectTimer = null;
		}
	}
};
/**
* Create a route-based compatibility transport instance based on mode.
*
* Selects the HTTP or custom WebSocket transport for the route-based client
* layer.
*
* @example
* ```typescript
* // HTTP transport (default)
* const http = createTransport({
*   mode: 'http',
*   baseUrl: 'http://localhost:3000'
* });
*
* // WebSocket transport
* const ws = createTransport({
*   mode: 'websocket',
*   wsUrl: 'ws://localhost:3000/ws'
* });
* ```
*/
function createTransport(options) {
	switch (options.mode) {
		case "http": return new HttpTransport(options);
		case "websocket": return new WebSocketTransport(options);
	}
}
/**
* Abstract base class for route-based HTTP/WebSocket compatibility clients.
*
* Requests go through the Transport abstraction layer, which handles:
* - HTTP and WebSocket route-based modes transparently
* - Automatic retry for 503 errors while the container is starting
* - Streaming responses for the existing route API
*
* DO-to-container control-channel capabilities live in `container-control/`.
* This layer supports the route-based compatibility API.
*/
var BaseHttpClient = class {
	options;
	logger;
	transport;
	constructor(options = {}) {
		this.options = options;
		this.logger = options.logger ?? createNoOpLogger();
		if (options.transport) this.transport = options.transport;
		else this.transport = createTransport({
			mode: options.transportMode ?? "http",
			baseUrl: options.baseUrl ?? "http://localhost:3000",
			wsUrl: options.wsUrl,
			logger: this.logger,
			stub: options.stub,
			port: options.port,
			retryTimeoutMs: options.retryTimeoutMs
		});
	}
	/**
	* Update the transport's 503 retry budget
	*/
	setRetryTimeoutMs(ms) {
		this.transport.setRetryTimeoutMs(ms);
	}
	/**
	* Check if using WebSocket transport
	*/
	isWebSocketMode() {
		return this.transport.getMode() === "websocket";
	}
	/**
	* Core fetch method - delegates to Transport which handles retry logic
	*/
	async doFetch(path$1, options) {
		const { defaultHeaders } = this.options;
		if (defaultHeaders) options = {
			...options,
			headers: {
				...defaultHeaders,
				...options?.headers
			}
		};
		return this.transport.fetch(path$1, options);
	}
	/**
	* Make a POST request with JSON body
	*/
	async post(endpoint, data, responseHandler, requestOptions) {
		const response = await this.doFetch(endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(data),
			...requestOptions
		});
		return await this.handleResponse(response, responseHandler);
	}
	/**
	* Make a GET request
	*/
	async get(endpoint, responseHandler) {
		const response = await this.doFetch(endpoint, { method: "GET" });
		return await this.handleResponse(response, responseHandler);
	}
	/**
	* Make a DELETE request
	*/
	async delete(endpoint, responseHandler) {
		const response = await this.doFetch(endpoint, { method: "DELETE" });
		return await this.handleResponse(response, responseHandler);
	}
	/**
	* Handle HTTP response with error checking and parsing
	*/
	async handleResponse(response, customHandler) {
		if (!response.ok) await this.handleErrorResponse(response);
		if (customHandler) return customHandler(response);
		try {
			return await response.json();
		} catch (error) {
			throw createErrorFromResponse({
				code: ErrorCode.INVALID_JSON_RESPONSE,
				message: `Invalid JSON response: ${error instanceof Error ? error.message : "Unknown parsing error"}`,
				context: {},
				httpStatus: response.status,
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
	}
	/**
	* Handle error responses with consistent error throwing
	*/
	async handleErrorResponse(response) {
		let errorData;
		try {
			errorData = await response.json();
		} catch {
			errorData = {
				code: ErrorCode.INTERNAL_ERROR,
				message: `HTTP error! status: ${response.status}`,
				context: { statusText: response.statusText },
				httpStatus: response.status,
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			};
		}
		const error = createErrorFromResponse(errorData);
		this.options.onError?.(errorData.message, void 0);
		throw error;
	}
	/**
	* Create a streaming response handler for Server-Sent Events
	*/
	async handleStreamResponse(response) {
		if (!response.ok) await this.handleErrorResponse(response);
		if (!response.body) throw new Error("No response body for streaming");
		return response.body;
	}
	/**
	* Stream request handler
	*
	* HTTP mode uses doFetch + handleStreamResponse for typed error handling.
	* For WebSocket mode, uses Transport's streaming support.
	*
	* @param path - The API path to call
	* @param body - Optional request body (for POST requests)
	* @param method - HTTP method (default: POST, use GET for process logs)
	*/
	async doStreamFetch(path$1, body, method = "POST") {
		const streamHeaders = method === "POST" ? {
			...this.options.defaultHeaders,
			"Content-Type": "application/json"
		} : this.options.defaultHeaders;
		if (this.transport.getMode() === "websocket") return this.transport.fetchStream(path$1, body, method, streamHeaders);
		const response = await this.doFetch(path$1, {
			method,
			headers: { "Content-Type": "application/json" },
			body: body && method === "POST" ? JSON.stringify(body) : void 0
		});
		return await this.handleStreamResponse(response);
	}
};
/**
* Client for backup operations.
*
* Handles communication with the container's backup endpoints.
* The container creates/extracts squashfs archives locally.
* R2 upload/download is handled by the Sandbox DO, not by this client.
*/
var BackupClient = class extends BaseHttpClient {
	/**
	* Tell the container to create a squashfs archive from a directory.
	* @param dir - Directory to back up
	* @param archivePath - Where the container should write the archive
	* @param sessionId - Session context
	*/
	async createArchive(dir, archivePath, sessionId, options) {
		const data = {
			dir,
			archivePath,
			gitignore: options?.gitignore ?? false,
			excludes: options?.excludes ?? [],
			compression: options?.compression,
			sessionId
		};
		return await this.post("/api/backup/create", data);
	}
	/**
	* Tell the container to restore a squashfs archive into a directory.
	* @param dir - Target directory
	* @param archivePath - Path to the archive file in the container
	* @param sessionId - Session context
	*/
	async restoreArchive(dir, archivePath, sessionId) {
		const data = {
			dir,
			archivePath,
			sessionId
		};
		return await this.post("/api/backup/restore", data);
	}
	async uploadParts(request, sessionId) {
		return this.post("/api/backup/upload-parts", {
			...request,
			sessionId: sessionId ?? request.sessionId
		});
	}
};
/**
* Client for command execution operations
*/
var CommandClient = class extends BaseHttpClient {
	/**
	* Execute a command and return the complete result
	* @param command - The command to execute
	* @param sessionId - The session ID for this command execution
	* @param timeoutMs - Optional timeout in milliseconds (unlimited by default)
	* @param env - Optional environment variables for this command
	* @param cwd - Optional working directory for this command
	*/
	async execute(command, sessionId, options) {
		try {
			const data = {
				command,
				sessionId,
				...options?.timeoutMs !== void 0 && { timeoutMs: options.timeoutMs },
				...options?.env !== void 0 && { env: options.env },
				...options?.cwd !== void 0 && { cwd: options.cwd },
				...options?.origin !== void 0 && { origin: options.origin }
			};
			const response = await this.post("/api/execute", data);
			this.options.onCommandComplete?.(response.success, response.exitCode, response.stdout, response.stderr, response.command);
			return response;
		} catch (error) {
			this.options.onError?.(error instanceof Error ? error.message : String(error), command);
			throw error;
		}
	}
	/**
	* Execute a command and return a stream of events
	* @param command - The command to execute
	* @param sessionId - The session ID for this command execution
	* @param options - Optional per-command execution settings
	*/
	async executeStream(command, sessionId, options) {
		try {
			const data = {
				command,
				sessionId,
				...options?.timeoutMs !== void 0 && { timeoutMs: options.timeoutMs },
				...options?.env !== void 0 && { env: options.env },
				...options?.cwd !== void 0 && { cwd: options.cwd },
				...options?.origin !== void 0 && { origin: options.origin }
			};
			return await this.doStreamFetch("/api/execute/stream", data);
		} catch (error) {
			this.options.onError?.(error instanceof Error ? error.message : String(error), command);
			throw error;
		}
	}
};
/**
* Client for file system operations
*/
var FileClient = class extends BaseHttpClient {
	/**
	* Create a directory
	* @param path - Directory path to create
	* @param sessionId - The session ID for this operation
	* @param options - Optional settings (recursive)
	*/
	async mkdir(path$1, sessionId, options) {
		const data = {
			path: path$1,
			sessionId,
			recursive: options?.recursive ?? false
		};
		return await this.post("/api/mkdir", data);
	}
	/**
	* Write content to a file
	* @param path - File path to write to
	* @param content - Content to write
	* @param sessionId - The session ID for this operation
	* @param options - Optional settings (encoding, ownerOnly)
	*/
	async writeFile(path$1, content, sessionId, options) {
		const data = {
			path: path$1,
			content,
			sessionId,
			encoding: options?.encoding,
			...options?.ownerOnly === true && { ownerOnly: true }
		};
		return await this.post("/api/write", data);
	}
	async readFile(path$1, sessionId, options) {
		if (options?.encoding === "none") throw new Error("readFile with encoding: 'none' requires the rpc transport. Set SANDBOX_TRANSPORT=rpc.");
		const data = {
			path: path$1,
			sessionId,
			encoding: options?.encoding
		};
		return await this.post("/api/read", data);
	}
	/**
	* Stream a file using Server-Sent Events
	* Returns a ReadableStream of SSE events containing metadata, chunks, and completion
	* @param path - File path to stream
	* @param sessionId - The session ID for this operation
	* @param options - Optional stream encoding; base64 preserves arbitrary bytes
	*/
	async readFileStream(path$1, sessionId, options) {
		const data = {
			path: path$1,
			sessionId,
			encoding: options?.encoding
		};
		return await this.doStreamFetch("/api/read/stream", data);
	}
	/**
	* Delete a file
	* @param path - File path to delete
	* @param sessionId - The session ID for this operation
	*/
	async deleteFile(path$1, sessionId) {
		const data = {
			path: path$1,
			sessionId
		};
		return await this.post("/api/delete", data);
	}
	/**
	* Rename a file
	* @param path - Current file path
	* @param newPath - New file path
	* @param sessionId - The session ID for this operation
	*/
	async renameFile(path$1, newPath, sessionId) {
		const data = {
			oldPath: path$1,
			newPath,
			sessionId
		};
		return await this.post("/api/rename", data);
	}
	/**
	* Move a file
	* @param path - Current file path
	* @param newPath - Destination file path
	* @param sessionId - The session ID for this operation
	*/
	async moveFile(path$1, newPath, sessionId) {
		const data = {
			sourcePath: path$1,
			destinationPath: newPath,
			sessionId
		};
		return await this.post("/api/move", data);
	}
	/**
	* List files in a directory
	* @param path - Directory path to list
	* @param sessionId - The session ID for this operation
	* @param options - Optional settings (recursive, includeHidden)
	*/
	async listFiles(path$1, sessionId, options) {
		const data = {
			path: path$1,
			sessionId,
			options: options || {}
		};
		return await this.post("/api/list-files", data);
	}
	/**
	* Check if a file or directory exists
	* @param path - Path to check
	* @param sessionId - The session ID for this operation
	*/
	async exists(path$1, sessionId) {
		const data = {
			path: path$1,
			sessionId
		};
		return await this.post("/api/exists", data);
	}
	/**
	* Write a file via a raw binary stream over the RPC transport.
	* Throws on HTTP and WebSocket transports — use writeFile() with a string instead.
	*/
	writeFileStream(_path, _content, _sessionId) {
		throw new Error("writeFileStream requires the rpc transport. Set SANDBOX_TRANSPORT=rpc.");
	}
};
/**
* Client for Git repository operations
*/
var GitClient = class GitClient extends BaseHttpClient {
	static REQUEST_TIMEOUT_BUFFER_MS = 3e4;
	constructor(options = {}) {
		super(options);
		this.logger = new GitLogger(this.logger);
	}
	/**
	* Clone a Git repository
	* @param repoUrl - URL of the Git repository to clone
	* @param sessionId - The session ID for this operation
	* @param options - Optional settings (branch, targetDir, depth, timeoutMs)
	*/
	async checkout(repoUrl, sessionId, options) {
		const timeoutMs = options?.timeoutMs ?? 6e5;
		let targetDir = options?.targetDir;
		if (!targetDir) targetDir = `/workspace/${extractRepoName(repoUrl)}`;
		const data = {
			repoUrl,
			sessionId,
			targetDir
		};
		if (options?.branch) data.branch = options.branch;
		if (options?.depth !== void 0) {
			if (!Number.isInteger(options.depth) || options.depth <= 0) throw new Error(`Invalid depth value: ${options.depth}. Must be a positive integer (e.g., 1, 5, 10).`);
			data.depth = options.depth;
		}
		if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new Error(`Invalid timeout value: ${timeoutMs}. Must be a positive integer number of milliseconds.`);
		data.timeoutMs = timeoutMs;
		return await this.post("/api/git/checkout", data, void 0, { requestTimeoutMs: timeoutMs + GitClient.REQUEST_TIMEOUT_BUFFER_MS });
	}
};
var InterpreterClient = class extends BaseHttpClient {
	maxRetries = 3;
	retryDelayMs = 1e3;
	async createCodeContext(options = {}) {
		return this.executeWithRetry(async () => {
			const response = await this.doFetch("/api/contexts", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					language: options.language || "python",
					cwd: options.cwd || "/workspace",
					env_vars: options.envVars
				})
			});
			if (!response.ok) throw await this.parseErrorResponse(response);
			const data = await response.json();
			if (!data.success) throw new Error(`Failed to create context: ${JSON.stringify(data)}`);
			return {
				id: data.contextId,
				language: data.language,
				cwd: data.cwd || "/workspace",
				createdAt: new Date(data.timestamp),
				lastUsed: new Date(data.timestamp)
			};
		});
	}
	async runCodeStream(contextId, code, language, callbacks, timeoutMs) {
		return this.executeWithRetry(async () => {
			const stream = await this.doStreamFetch("/api/execute/code", {
				context_id: contextId,
				code,
				language,
				...timeoutMs !== void 0 && { timeout_ms: timeoutMs }
			});
			for await (const chunk of this.readLines(stream)) await this.parseExecutionResult(chunk, callbacks);
		});
	}
	async listCodeContexts() {
		return this.executeWithRetry(async () => {
			const response = await this.doFetch("/api/contexts", {
				method: "GET",
				headers: { "Content-Type": "application/json" }
			});
			if (!response.ok) throw await this.parseErrorResponse(response);
			const data = await response.json();
			if (!data.success) throw new Error(`Failed to list contexts: ${JSON.stringify(data)}`);
			return data.contexts.map((ctx) => ({
				id: ctx.id,
				language: ctx.language,
				cwd: ctx.cwd || "/workspace",
				createdAt: new Date(data.timestamp),
				lastUsed: new Date(data.timestamp)
			}));
		});
	}
	async deleteCodeContext(contextId) {
		return this.executeWithRetry(async () => {
			const response = await this.doFetch(`/api/contexts/${contextId}`, {
				method: "DELETE",
				headers: { "Content-Type": "application/json" }
			});
			if (!response.ok) throw await this.parseErrorResponse(response);
		});
	}
	/**
	* Get a raw stream for code execution.
	* Used by CodeInterpreter.runCodeStreaming() for direct stream access.
	*/
	async streamCode(contextId, code, language) {
		return this.doStreamFetch("/api/execute/code", {
			context_id: contextId,
			code,
			language
		});
	}
	/**
	* Execute an operation with automatic retry for transient errors
	*/
	async executeWithRetry(operation) {
		let lastError;
		for (let attempt = 0; attempt < this.maxRetries; attempt++) try {
			return await operation();
		} catch (error) {
			lastError = error;
			if (this.isRetryableError(error)) {
				if (attempt < this.maxRetries - 1) {
					const delay = this.retryDelayMs * 2 ** attempt + Math.random() * 1e3;
					await new Promise((resolve) => setTimeout(resolve, delay));
					continue;
				}
			}
			throw error;
		}
		throw lastError || /* @__PURE__ */ new Error("Execution failed after retries");
	}
	isRetryableError(error) {
		if (error instanceof InterpreterNotReadyError) return true;
		if (error instanceof Error) return error.message.includes("not ready") || error.message.includes("initializing");
		return false;
	}
	async parseErrorResponse(response) {
		try {
			return createErrorFromResponse(await response.json());
		} catch {
			return createErrorFromResponse({
				code: ErrorCode.INTERNAL_ERROR,
				message: `HTTP ${response.status}: ${response.statusText}`,
				context: {},
				httpStatus: response.status,
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
	}
	async *readLines(stream) {
		const reader = stream.getReader();
		let buffer = "";
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (value) buffer += new TextDecoder().decode(value);
				if (done) break;
				let newlineIdx = buffer.indexOf("\n");
				while (newlineIdx !== -1) {
					yield buffer.slice(0, newlineIdx);
					buffer = buffer.slice(newlineIdx + 1);
					newlineIdx = buffer.indexOf("\n");
				}
			}
			if (buffer.length > 0) yield buffer;
		} finally {
			try {
				await reader.cancel();
			} catch {}
			reader.releaseLock();
		}
	}
	async parseExecutionResult(line, callbacks) {
		if (!line.trim()) return;
		if (!line.startsWith("data: ")) return;
		try {
			const jsonData = line.substring(6);
			const data = JSON.parse(jsonData);
			switch (data.type) {
				case "stdout":
					if (callbacks.onStdout && data.text) await callbacks.onStdout({
						text: data.text,
						timestamp: data.timestamp || Date.now()
					});
					break;
				case "stderr":
					if (callbacks.onStderr && data.text) await callbacks.onStderr({
						text: data.text,
						timestamp: data.timestamp || Date.now()
					});
					break;
				case "result":
					if (callbacks.onResult) {
						const result = new ResultImpl(data);
						await callbacks.onResult(result);
					}
					break;
				case "error": if (callbacks.onError) await callbacks.onError({
					name: data.ename || "Error",
					message: data.evalue || "Unknown error",
					traceback: data.traceback || []
				});
			}
		} catch {}
	}
};
/**
* Client for port readiness operations.
*/
var PortClient = class extends BaseHttpClient {
	/**
	* Watch a port for readiness via SSE stream
	* @param request - Port watch configuration
	* @returns SSE stream that emits PortWatchEvent objects
	*/
	async watchPort(request) {
		return await this.doStreamFetch("/api/port-watch", request);
	}
};
/**
* Client for background process management
*/
var ProcessClient = class extends BaseHttpClient {
	/**
	* Start a background process
	* @param command - Command to execute as a background process
	* @param sessionId - The session ID for this operation
	* @param options - Optional settings (processId)
	*/
	async startProcess(command, sessionId, options) {
		const data = {
			command,
			sessionId,
			...options?.origin !== void 0 && { origin: options.origin },
			...options?.processId !== void 0 && { processId: options.processId },
			...options?.timeoutMs !== void 0 && { timeoutMs: options.timeoutMs },
			...options?.env !== void 0 && { env: options.env },
			...options?.cwd !== void 0 && { cwd: options.cwd },
			...options?.encoding !== void 0 && { encoding: options.encoding },
			...options?.autoCleanup !== void 0 && { autoCleanup: options.autoCleanup }
		};
		return await this.post("/api/process/start", data);
	}
	/**
	* List all processes (sandbox-scoped, not session-scoped)
	*/
	async listProcesses() {
		return await this.get(`/api/process/list`);
	}
	/**
	* Get information about a specific process (sandbox-scoped, not session-scoped)
	* @param processId - ID of the process to retrieve
	*/
	async getProcess(processId) {
		const url = `/api/process/${processId}`;
		return await this.get(url);
	}
	/**
	* Kill a specific process (sandbox-scoped, not session-scoped)
	* @param processId - ID of the process to kill
	*/
	async killProcess(processId) {
		const url = `/api/process/${processId}`;
		return await this.delete(url);
	}
	/**
	* Kill all running processes (sandbox-scoped, not session-scoped)
	*/
	async killAllProcesses() {
		return await this.delete(`/api/process/kill-all`);
	}
	/**
	* Get logs from a specific process (sandbox-scoped, not session-scoped)
	* @param processId - ID of the process to get logs from
	*/
	async getProcessLogs(processId) {
		const url = `/api/process/${processId}/logs`;
		return await this.get(url);
	}
	/**
	* Stream logs from a specific process (sandbox-scoped, not session-scoped)
	* @param processId - ID of the process to stream logs from
	*/
	async streamProcessLogs(processId) {
		const url = `/api/process/${processId}/stream`;
		return await this.doStreamFetch(url, void 0, "GET");
	}
};
/**
* Client for health checks and utility operations
*/
var UtilityClient = class extends BaseHttpClient {
	/**
	* Ping the sandbox to check if it's responsive
	*/
	async ping() {
		return (await this.get("/api/ping")).message;
	}
	/**
	* Get list of available commands in the sandbox environment
	*/
	async getCommands() {
		return (await this.get("/api/commands")).availableCommands;
	}
	/**
	* Create a new execution session
	* @param options - Session configuration (id, env, cwd)
	*/
	async createSession(options) {
		return await this.post("/api/session/create", options);
	}
	/**
	* Delete an execution session
	* @param sessionId - Session ID to delete
	*/
	async deleteSession(sessionId) {
		return await this.post("/api/session/delete", { sessionId });
	}
	/**
	* Get the container version
	* Returns the version embedded in the Docker image during build
	*/
	async getVersion() {
		try {
			return (await this.get("/api/version")).version;
		} catch (error) {
			this.logger.debug("Failed to get container version (may be old container)", { error });
			return "unknown";
		}
	}
	listSessions() {
		throw new Error("listSessions requires the RPC transport. Set SANDBOX_TRANSPORT=rpc.");
	}
};
/**
* Client for file watch operations
* Uses inotify under the hood for native filesystem event notifications
*
* @internal This client is used internally by the SDK.
* Users should use `sandbox.watch()` or `sandbox.checkChanges()` instead.
*/
var WatchClient = class extends BaseHttpClient {
	/**
	* Check whether a path changed since a previously returned version.
	*/
	async checkChanges(request) {
		return this.post("/api/watch/check", request);
	}
	/**
	* Start watching a directory for changes.
	* The returned promise resolves only after the watcher is established
	* on the filesystem (i.e. the `watching` SSE event has been received).
	* The returned stream still contains the `watching` event so consumers
	* using `parseSSEStream` will see the full event sequence.
	*
	* @param request - Watch request with path and options
	*/
	async watch(request) {
		const stream = await this.doStreamFetch("/api/watch", request);
		return await this.waitForReadiness(stream);
	}
	/**
	* Read SSE chunks until the `watching` event appears, then return a
	* wrapper stream that replays the buffered chunks followed by the
	* remaining original stream data.
	*/
	async waitForReadiness(stream) {
		const reader = stream.getReader();
		const bufferedChunks = [];
		const decoder = new TextDecoder();
		let buffer = "";
		let currentEvent = { data: [] };
		let watcherReady = false;
		const processEventData = (eventData) => {
			let event;
			try {
				event = JSON.parse(eventData);
			} catch {
				return;
			}
			if (event.type === "watching") watcherReady = true;
			if (event.type === "error") throw new Error(event.error || "Watch failed to establish");
		};
		try {
			while (!watcherReady) {
				const { done, value } = await reader.read();
				if (done) {
					const finalParsed = parseSSEFrames(`${buffer}\n\n`, currentEvent);
					for (const frame of finalParsed.events) {
						processEventData(frame.data);
						if (watcherReady) break;
					}
					if (watcherReady) break;
					throw new Error("Watch stream ended before watcher was established");
				}
				bufferedChunks.push(value);
				buffer += decoder.decode(value, { stream: true });
				const parsed = parseSSEFrames(buffer, currentEvent);
				buffer = parsed.remaining;
				currentEvent = parsed.currentEvent;
				for (const frame of parsed.events) {
					processEventData(frame.data);
					if (watcherReady) break;
				}
			}
		} catch (error) {
			reader.cancel().catch(() => {});
			throw error;
		}
		let replayIndex = 0;
		return new ReadableStream({
			pull(controller) {
				if (replayIndex < bufferedChunks.length) {
					controller.enqueue(bufferedChunks[replayIndex++]);
					return;
				}
				return reader.read().then(({ done: d, value: v }) => {
					if (d) {
						controller.close();
						return;
					}
					controller.enqueue(v);
				});
			},
			cancel() {
				return reader.cancel();
			}
		});
	}
};
/**
* Route-based compatibility sandbox client that composes all domain-specific
* HTTP API clients.
*
* This client supports the route-based HTTP and custom WebSocket transports.
* The primary DO-to-container control path is ContainerControlClient under
* `container-control/`. This client supports route-based compatibility,
* debugging, local development, and fallback behavior.
*/
var SandboxClient = class {
	backup;
	commands;
	files;
	processes;
	ports;
	git;
	interpreter;
	utils;
	watch;
	/**
	* Tunnels are RPC-only — the route-based transport does not implement them.
	* This getter exists so the `PublicKeys<SandboxClient> satisfies
	* PublicKeys<SandboxAPI>` compile-time check holds. Calling any method on
	* the returned proxy throws a clear `RPC transport required` error.
	*/
	tunnels = createTunnelsNotImplemented();
	transport = null;
	constructor(options) {
		if (options.transportMode === "websocket" && options.wsUrl) this.transport = createTransport({
			mode: options.transportMode,
			wsUrl: options.wsUrl,
			baseUrl: options.baseUrl,
			logger: options.logger,
			stub: options.stub,
			port: options.port,
			retryTimeoutMs: options.retryTimeoutMs
		});
		const clientOptions = {
			baseUrl: "http://localhost:3000",
			...options,
			transport: this.transport ?? options.transport
		};
		this.backup = new BackupClient(clientOptions);
		this.commands = new CommandClient(clientOptions);
		this.files = new FileClient(clientOptions);
		this.processes = new ProcessClient(clientOptions);
		this.ports = new PortClient(clientOptions);
		this.git = new GitClient(clientOptions);
		this.interpreter = new InterpreterClient(clientOptions);
		this.utils = new UtilityClient(clientOptions);
		this.watch = new WatchClient(clientOptions);
	}
	/**
	* Update the transport retry budget without recreating the client.
	*
	* In WebSocket mode a single shared transport is used, so one update covers
	* every sub-client. In HTTP mode each sub-client owns its own transport, so
	* all of them are updated individually.
	*/
	setRetryTimeoutMs(ms) {
		if (this.transport) this.transport.setRetryTimeoutMs(ms);
		else {
			this.backup.setRetryTimeoutMs(ms);
			this.commands.setRetryTimeoutMs(ms);
			this.files.setRetryTimeoutMs(ms);
			this.processes.setRetryTimeoutMs(ms);
			this.ports.setRetryTimeoutMs(ms);
			this.git.setRetryTimeoutMs(ms);
			this.interpreter.setRetryTimeoutMs(ms);
			this.utils.setRetryTimeoutMs(ms);
			this.watch.setRetryTimeoutMs(ms);
		}
	}
	/**
	* Get the current transport mode
	*/
	getTransportMode() {
		return this.transport?.getMode() ?? "http";
	}
	/**
	* Check if WebSocket is connected (only relevant in WebSocket mode)
	*/
	isWebSocketConnected() {
		return this.transport?.isConnected() ?? false;
	}
	/**
	* Connect WebSocket transport (no-op in HTTP mode)
	* Called automatically on first request, but can be called explicitly
	* to establish connection upfront.
	*/
	async connect() {
		if (this.transport) await this.transport.connect();
	}
	/**
	* Disconnect WebSocket transport (no-op in HTTP mode)
	* Should be called when the sandbox is destroyed.
	*/
	disconnect() {
		if (this.transport) this.transport.disconnect();
	}
};
function createTunnelsNotImplemented() {
	const message = "sandbox.tunnels.* requires the RPC transport. Enable it with transport: \"rpc\" in sandbox options.";
	return new Proxy({}, { get() {
		return () => {
			throw new Error(message);
		};
	} });
}
var SUPERSEDED_ISOLATE_PATTERN = /reset because its code was updated|this script has been upgraded/i;
var CONNECTION_LOST_PATTERN = /network connection lost/i;
var DO_STORAGE_STARTUP_RESET_PATTERN = /internal error while starting up durable object storage caused object to be reset/i;
function errorMessageOf(error) {
	return error instanceof Error ? error.message : typeof error === "string" ? error : "";
}
/**
* Extract a matchable message from any thrown value, reading a `.message`
* property even when the value is not an `Error` instance. The Containers
* runtime raises admission failures from the container binding, which may
* live in a different realm — so `instanceof Error` can be false for a
* genuine error. Mirrors the base `@cloudflare/containers` `isErrorOfType`
* helper: coerce to a string, then match case-insensitively.
*/
function realmSafeMessageOf(error) {
	const message = error?.message;
	return typeof message === "string" ? message : String(error);
}
/**
* Platform messages emitted by the Containers runtime when it cannot admit a
* container for a Durable Object during startup. Matched case-insensitively as
* lowercase substrings. Single source of truth for both the RPC connection
* path (connection.ts) and the HTTP `containerFetch` path (sandbox.ts).
*/
var CONTAINER_UNAVAILABLE_SIGNATURES = [
	{
		substring: "there is no container instance that can be provided to this durable object",
		reason: "no_container_instance_available"
	},
	{
		substring: "there is no container instance available at this time",
		reason: "no_container_instance_available"
	},
	{
		substring: "maximum number of running container instances exceeded",
		reason: "max_container_instances_exceeded"
	}
];
/**
* Classify a container-startup error as a platform admission/capacity failure,
* returning the categorical reason or null. Realm-safe (does not gate on
* `instanceof Error`), case-insensitive, and walks the `.cause` chain so a
* wrapped admission failure is still recognized.
*/
function matchContainerUnavailable(error) {
	for (const candidate of selfAndCauses(error)) {
		const text = realmSafeMessageOf(candidate).toLowerCase();
		const match = CONTAINER_UNAVAILABLE_SIGNATURES.find((sig) => text.includes(sig.substring));
		if (match) return match.reason;
	}
	return null;
}
function* selfAndCauses(error) {
	let current = error;
	for (let depth = 0; depth < 8 && current != null; depth += 1) {
		yield current;
		current = typeof current === "object" ? current.cause : void 0;
	}
}
function isErrorRetryable(error) {
	if (typeof error !== "object" || error === null) return false;
	const message = String(error);
	const typed = error;
	return typed.retryable === true && typed.overloaded !== true && !message.includes("Durable Object is overloaded");
}
/**
* Whether an error was raised because the Durable Object itself was reset, by
* a code update or a storage startup failure, rather than by the operation
* that observed it.
*/
function isDurableObjectReset(error) {
	for (const candidate of selfAndCauses(error)) {
		const message = errorMessageOf(candidate);
		if (SUPERSEDED_ISOLATE_PATTERN.test(message)) return true;
		if (DO_STORAGE_STARTUP_RESET_PATTERN.test(message)) return true;
	}
	return false;
}
/**
* Whether an error represents a transient platform lifecycle/storage failure,
* not an application-level sandbox failure.
*/
function isPlatformTransientError(error) {
	for (const candidate of selfAndCauses(error)) {
		const message = errorMessageOf(candidate);
		if (SUPERSEDED_ISOLATE_PATTERN.test(message)) return true;
		if (CONNECTION_LOST_PATTERN.test(message)) return true;
		if (DO_STORAGE_STARTUP_RESET_PATTERN.test(message)) return true;
		if (isErrorRetryable(candidate)) return true;
	}
	return false;
}
/**
* Absolute directory prefixes supported by backup and restore operations.
*/
var BACKUP_ALLOWED_PREFIXES = [
	"/workspace",
	"/home",
	"/tmp",
	"/var/tmp",
	"/app"
];
function normalizeBackupExcludePattern(pattern) {
	let normalized = pattern;
	while (normalized.startsWith("**/")) normalized = normalized.slice(3);
	while (normalized.includes("/**/")) normalized = normalized.replace(/\/\*\*\//g, "/");
	if (normalized.endsWith("/**")) normalized = normalized.slice(0, -3);
	if (!normalized || normalized === "**") return null;
	return normalized;
}
var DISABLE_SESSION_TOKEN = "__DISABLE_SESSION__";
var CURRENT_RUNTIME_IDENTITY_STORAGE_KEY = "currentRuntimeIdentity";
var RuntimeIdentityInactiveError = class extends Error {
	constructor() {
		super("Runtime identity is no longer active");
		this.name = "RuntimeIdentityInactiveError";
	}
};
var RuntimeIdentity = class {
	id;
	constructor(record) {
		this.id = record.id;
	}
	owns(record) {
		return record.runtimeIdentityID === this.id;
	}
	scope(value) {
		return {
			...value,
			runtimeIdentityID: this.id
		};
	}
};
var CurrentRuntimeIdentity = class {
	/**
	* Runtime identity is stored in Durable Object storage so a reconstructed DO
	* can still recognize the live container runtime it owns. In-memory state is
	* only a cache and cannot define runtime-scoped correctness.
	*/
	constructor(storage, getContainerState, isContainerRunning) {
		this.storage = storage;
		this.getContainerState = getContainerState;
		this.isContainerRunning = isContainerRunning;
	}
	async get() {
		const status = await this.getStatus();
		return status.status === "active" ? status.runtime : null;
	}
	async getStatus() {
		const state = await this.getContainerState();
		if (state.status !== "healthy") return {
			status: "inactive",
			reason: "runtime-not-healthy",
			containerStatus: state.status
		};
		if (!this.isContainerRunning()) return {
			status: "inactive",
			reason: "runtime-not-running",
			containerStatus: state.status
		};
		const runtime = await this.getStored();
		if (!runtime) return {
			status: "inactive",
			reason: "missing-runtime-id",
			containerStatus: state.status
		};
		return {
			status: "active",
			runtime,
			containerStatus: state.status
		};
	}
	async getStored(storage = this.storage) {
		const record = await storage.get(CURRENT_RUNTIME_IDENTITY_STORAGE_KEY) ?? null;
		return record ? new RuntimeIdentity(record) : null;
	}
	async markStarted() {
		const record = { id: crypto.randomUUID() };
		await this.storage.put(CURRENT_RUNTIME_IDENTITY_STORAGE_KEY, record);
		return new RuntimeIdentity(record);
	}
	async clear() {
		await this.storage.delete(CURRENT_RUNTIME_IDENTITY_STORAGE_KEY);
	}
	async isActive(runtime) {
		return (await this.get())?.id === runtime.id;
	}
	async assertActive(runtime) {
		if (!await this.isActive(runtime)) throw new RuntimeIdentityInactiveError();
	}
};
var SANDBOX_LIFETIME_STORAGE_KEY = "sandbox:lifetime";
var SandboxLifetimeChangedError = class extends Error {
	constructor() {
		super("Sandbox lifetime is no longer current");
		this.name = "SandboxLifetimeChangedError";
	}
};
var SandboxLifetime = class {
	id;
	generation;
	createdAt;
	updatedAt;
	constructor(record) {
		this.record = record;
		this.id = record.id;
		this.generation = record.generation;
		this.createdAt = record.createdAt;
		this.updatedAt = record.updatedAt;
	}
	owns(record) {
		return record.sandboxLifetimeID === this.id;
	}
	scope(value) {
		return {
			...value,
			sandboxLifetimeID: this.id
		};
	}
};
var CurrentSandboxLifetime = class {
	constructor(storage) {
		this.storage = storage;
	}
	async get() {
		const record = await this.storage.get(SANDBOX_LIFETIME_STORAGE_KEY) ?? null;
		return record ? new SandboxLifetime(record) : null;
	}
	/**
	* Returns the current lifetime if one exists, or creates and persists a new
	* one. The id is stable for the lifetime of the sandbox — it only changes
	* when `rotate()` is called (on `destroy()`).
	*/
	async getOrCreate() {
		const existing = await this.get();
		if (existing) return existing;
		const now = (/* @__PURE__ */ new Date()).toISOString();
		const record = {
			id: crypto.randomUUID(),
			generation: 1,
			createdAt: now,
			updatedAt: now
		};
		await this.storage.put(SANDBOX_LIFETIME_STORAGE_KEY, record);
		return new SandboxLifetime(record);
	}
	/**
	* Creates and persists a new lifetime id, incrementing the generation
	* counter. Called during `sandbox.destroy()` before runtime state is
	* cleared so in-flight operations can detect the lifetime change.
	*/
	async rotate() {
		const existing = await this.get();
		const now = (/* @__PURE__ */ new Date()).toISOString();
		const record = {
			id: crypto.randomUUID(),
			generation: (existing?.generation ?? 0) + 1,
			createdAt: now,
			updatedAt: now
		};
		await this.storage.put(SANDBOX_LIFETIME_STORAGE_KEY, record);
		return new SandboxLifetime(record);
	}
	async isCurrent(lifetime) {
		return (await this.get())?.id === lifetime.id;
	}
	/**
	* Throws `SandboxLifetimeChangedError` if the given lifetime is no longer
	* the current one. Used by operation runners to abort operations that
	* started before a `destroy()` call.
	*/
	async assertCurrent(lifetime) {
		if (!await this.isCurrent(lifetime)) throw new SandboxLifetimeChangedError();
	}
};
var OPERATION_STORAGE_PREFIX = "operations:";
function backupRestoreOperationKey(backupId, dir) {
	return `restore:${backupId}:${dir}`;
}
function createBackupRestoreOperationRecord(params) {
	return {
		operationKey: backupRestoreOperationKey(params.backupId, params.dir),
		kind: "backup.restore",
		sandboxLifetimeID: params.sandboxLifetimeID,
		phase: "validating",
		status: "running",
		payload: {
			backupId: params.backupId,
			dir: params.dir
		},
		createdAt: params.now,
		updatedAt: params.now
	};
}
var BackupRestoreOperationStore = class {
	constructor(storage) {
		this.storage = storage;
	}
	async get(operationKey) {
		return await this.storage.get(this.storageKey(operationKey)) ?? null;
	}
	async put(record) {
		await this.storage.put(this.storageKey(record.operationKey), record);
	}
	storageKey(operationKey) {
		return `${OPERATION_STORAGE_PREFIX}${operationKey}`;
	}
};
var BACKUP_RESTORE_MAX_RECOVERY_ATTEMPTS = 2;
var RestoreLifecycleRunner = class {
	operationRecords;
	constructor(deps) {
		this.deps = deps;
		this.operationRecords = new BackupRestoreOperationStore(deps.storage);
	}
	async execute(params) {
		return await this.runWithRecovery(async () => {
			const { lifetime, operation } = await this.startOperation(params.backupId, params.dir);
			let currentOperation = operation;
			let runtime;
			const context = {
				lifetime,
				runtimeReady: async () => {
					try {
						runtime = await this.captureRuntime();
						await this.deps.currentLifetime.assertCurrent(lifetime);
					} catch (error) {
						throw await this.translateFenceError(error, currentOperation, "validating", "unknown") ?? error;
					}
					currentOperation = await this.markRuntimeReady(currentOperation, runtime);
					return {
						runtime,
						operation: currentOperation
					};
				},
				archiveReady: async (archiveSize) => {
					if (!runtime) throw new Error("Backup restore archiveReady requires runtimeReady()");
					try {
						await this.assertFences(runtime, lifetime);
					} catch (error) {
						throw await this.translateFenceError(error, currentOperation, currentOperation.phase, true) ?? error;
					}
					currentOperation = await this.markArchiveReady(currentOperation, runtime, archiveSize);
					return {
						runtime,
						operation: currentOperation
					};
				},
				verify: async (result) => {
					if (!runtime) throw new Error("Backup restore verification requires runtimeReady()");
					try {
						await this.assertFences(runtime, lifetime);
					} catch (error) {
						throw await this.translateFenceError(error, currentOperation, "archive_ready", true) ?? error;
					}
					currentOperation = await this.markVerified(currentOperation, runtime, result);
					return currentOperation;
				}
			};
			try {
				return await params.attempt(context);
			} catch (error) {
				const translatedRPC = await this.translateRPCError(error, currentOperation);
				if (translatedRPC) throw translatedRPC;
				const translatedFence = await this.translateFenceError(error, currentOperation, currentOperation.phase, "unknown");
				if (translatedFence) throw translatedFence;
				if (!(error instanceof OperationInterruptedError)) await this.markFailed(currentOperation, error);
				throw error;
			}
		});
	}
	async runWithRecovery(attempt) {
		let recoveryAttempts = 0;
		while (true) try {
			return await attempt();
		} catch (error) {
			if (!(error instanceof OperationInterruptedError)) throw error;
			if (!error.context.retryable) throw error;
			if (recoveryAttempts >= BACKUP_RESTORE_MAX_RECOVERY_ATTEMPTS) throw this.createRecoveryExhaustedError(error, recoveryAttempts);
			recoveryAttempts++;
		}
	}
	async startOperation(backupId, dir) {
		const lifetime = await this.deps.currentLifetime.getOrCreate();
		const operation = createBackupRestoreOperationRecord({
			sandboxLifetimeID: lifetime.id,
			backupId,
			dir,
			now: (/* @__PURE__ */ new Date()).toISOString()
		});
		await this.operationRecords.put(operation);
		return {
			lifetime,
			operation
		};
	}
	async captureRuntime() {
		const runtime = await this.deps.currentRuntime.get() ?? await this.deps.currentRuntime.markStarted();
		await this.deps.currentRuntime.assertActive(runtime);
		return runtime;
	}
	async assertFences(runtime, lifetime) {
		await this.deps.currentRuntime.assertActive(runtime);
		await this.deps.currentLifetime.assertCurrent(lifetime);
	}
	async markRuntimeReady(operation, runtime) {
		const next = {
			...operation,
			phase: "runtime_ready",
			runtimeIdentityID: runtime.id,
			updatedAt: (/* @__PURE__ */ new Date()).toISOString()
		};
		await this.operationRecords.put(next);
		return next;
	}
	async markArchiveReady(operation, runtime, archiveSize) {
		const next = {
			...operation,
			phase: "archive_ready",
			runtimeIdentityID: runtime.id,
			payload: {
				...operation.payload,
				...archiveSize !== void 0 && { archiveSize }
			},
			updatedAt: (/* @__PURE__ */ new Date()).toISOString()
		};
		await this.operationRecords.put(next);
		return next;
	}
	async markVerified(operation, runtime, result) {
		const completedAt = (/* @__PURE__ */ new Date()).toISOString();
		const next = {
			...operation,
			phase: "verified",
			status: "committed",
			runtimeIdentityID: runtime.id,
			result,
			completedAt,
			updatedAt: completedAt
		};
		await this.operationRecords.put(next);
		return next;
	}
	async markFailed(operation, error) {
		const completedAt = (/* @__PURE__ */ new Date()).toISOString();
		const message = error instanceof Error ? error.message : String(error);
		const code = error instanceof Error && "code" in error && typeof error.code === "string" ? error.code : "UNKNOWN";
		const next = {
			...operation,
			phase: "failed",
			status: "failed",
			error: {
				code,
				message,
				retryable: false
			},
			completedAt,
			updatedAt: completedAt
		};
		await this.operationRecords.put(next);
		return next;
	}
	async markInterrupted(operation, message, retryable) {
		const next = {
			...operation,
			phase: "interrupted",
			status: "interrupted",
			error: {
				code: ErrorCode.OPERATION_INTERRUPTED,
				message,
				retryable
			},
			updatedAt: (/* @__PURE__ */ new Date()).toISOString()
		};
		await this.operationRecords.put(next);
		return next;
	}
	async translateFenceError(error, operation, phase, admitted) {
		if (!(error instanceof RuntimeIdentityInactiveError || error instanceof SandboxLifetimeChangedError)) return null;
		const reason = error instanceof RuntimeIdentityInactiveError ? "runtime_replaced" : "sandbox_lifetime_changed";
		const retryable = reason !== "sandbox_lifetime_changed";
		const message = "Backup restore was interrupted before completion could be verified";
		const interrupted = await this.markInterrupted(operation, message, retryable);
		return this.createInterruptedError({
			reason,
			phase,
			admitted,
			retryable,
			message,
			operation: interrupted
		});
	}
	async translateRPCError(error, operation) {
		if (!(error instanceof RPCTransportError)) return null;
		const message = "Backup restore was interrupted before completion could be verified";
		const interruptedPhase = operation.phase;
		const interrupted = await this.markInterrupted(operation, message, true);
		return this.createInterruptedError({
			reason: "transport_disposed",
			phase: interruptedPhase,
			admitted: "unknown",
			retryable: true,
			message,
			operation: interrupted
		});
	}
	createInterruptedError(params) {
		return new OperationInterruptedError({
			message: params.message,
			code: ErrorCode.OPERATION_INTERRUPTED,
			httpStatus: 409,
			context: {
				reason: params.reason,
				operation: "backup.restore",
				phase: params.phase,
				admitted: params.admitted,
				retryable: params.retryable
			},
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			suggestion: this.suggestionFor(params.retryable)
		});
	}
	createRecoveryExhaustedError(error, recoveryAttempts) {
		return new OperationInterruptedError({
			message: "Backup restore recovery attempts were exhausted",
			code: ErrorCode.OPERATION_INTERRUPTED,
			httpStatus: 409,
			context: {
				reason: "recovery_exhausted",
				operation: error.context.operation,
				phase: "interrupted",
				admitted: error.context.admitted,
				retryable: false,
				recoveryAttempts,
				maxRecoveryAttempts: BACKUP_RESTORE_MAX_RECOVERY_ATTEMPTS
			},
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			suggestion: this.suggestionFor(false)
		});
	}
	suggestionFor(retryable) {
		return retryable ? "Retry restoreBackup() with the same backup handle so the SDK can reconcile the restore operation." : "Start a new restoreBackup() call only if restoring this backup is still desired for the current sandbox.";
	}
};
/**
* Thin tracing helper for the RPC control path.
*
* Wraps `cloudflare:workers` `tracing.enterSpan` so the connection/client code
* can emit spans for RPC calls, the connect/disconnect lifecycle, and
* individual upgrade attempts — without hard-failing in environments where the
* tracing API is unavailable.
*
* Error convention: the Cloudflare trace UI surfaces `error` and `error.stack`
* span attributes specially (this differs from the OpenTelemetry standard,
* which uses exception events). We therefore stamp both attributes on the span
* when the wrapped work throws, so failures are visible in the GUI.
*
* Cause chain: the base `@cloudflare/containers` class wraps the true failure
* inside `new Error(NO_CONTAINER_INSTANCE_ERROR, { cause })`, so the real
* reason (e.g. "the container is not listening", "Network connection lost", a
* non-zero exit code) is only visible on `.cause`. Every distinct failure mode
* therefore collapses to the same generic top-level message in traces. We walk
* the cause chain and stamp it so a trace names the actual root cause.
*/
/** Bound on cause-chain traversal — guards against cycles and runaway depth. */
var MAX_CAUSE_DEPTH = 8;
/** Read a string `code` property off an arbitrary value, if present. */
function stringCode(value) {
	const code = value?.code;
	return typeof code === "string" ? code : void 0;
}
/** Render any thrown value as a short human-readable message. */
function messageOf(value) {
	return value instanceof Error ? value.message : String(value);
}
/**
* Compute the Cloudflare-convention error span attributes for any thrown value,
* including the wrapped `.cause` chain. Pure and side-effect-free so it can be
* unit-tested without a live tracer.
*
* Emits:
*   - `error`            — top-level message (or stringified non-Error)
*   - `error.stack`      — top-level stack, when available
*   - `error.code`       — top-level string `code`, when available
*   - `error.cause`      — immediate cause message, when a cause exists
*   - `error.cause.code` — immediate cause string `code`, when available
*   - `error.cause_chain`— all nested cause messages joined by " <- "
*/
function computeErrorAttributes(error) {
	const attrs = {};
	if (error instanceof Error) {
		attrs.error = error.message;
		if (typeof error.stack === "string") attrs["error.stack"] = error.stack;
		const code = stringCode(error);
		if (code !== void 0) attrs["error.code"] = code;
	} else {
		attrs.error = String(error);
		return attrs;
	}
	const chain = [];
	const seen = /* @__PURE__ */ new Set([error]);
	let current = error.cause;
	let depth = 0;
	while (current !== void 0 && current !== null && depth < MAX_CAUSE_DEPTH) {
		if (seen.has(current)) break;
		seen.add(current);
		if (depth === 0) {
			attrs["error.cause"] = messageOf(current);
			const causeCode = stringCode(current);
			if (causeCode !== void 0) attrs["error.cause.code"] = causeCode;
		}
		chain.push(messageOf(current));
		current = current instanceof Error ? current.cause : void 0;
		depth++;
	}
	if (chain.length > 0) attrs["error.cause_chain"] = chain.join(" <- ");
	return attrs;
}
/**
* Stamp the Cloudflare-convention error attributes onto a span. Safe to call
* with any thrown value.
*/
function setErrorAttributes(span, error) {
	for (const [key, value] of Object.entries(computeErrorAttributes(error))) if (value !== void 0) span.setAttribute(key, value);
}
/**
* Run `fn` inside a span named `name`, applying `attributes` up front and
* stamping `error`/`error.stack` if it throws. Re-throws the original error.
*
* Falls back to running `fn` directly if the tracing API is unavailable, so a
* missing tracer never changes behavior.
*/
async function withSpan(name, attributes, fn) {
	const enter = tracing?.enterSpan?.bind(tracing);
	if (typeof enter !== "function") return fn({ setAttribute: () => {} });
	return enter(name, async (span) => {
		for (const [key, value] of Object.entries(attributes)) if (value !== void 0) span.setAttribute(key, value);
		try {
			return await fn(span);
		} catch (error) {
			setErrorAttributes(span, error);
			throw error;
		}
	});
}
/**
* Emit a zero-duration marker span for a lifecycle event (e.g. disconnect).
* Best-effort: never throws, never changes behavior.
*/
function traceEvent(name, attributes) {
	const enter = tracing?.enterSpan?.bind(tracing);
	if (typeof enter !== "function") return;
	try {
		enter(name, (span) => {
			for (const [key, value] of Object.entries(attributes)) if (value !== void 0) span.setAttribute(key, value);
		});
	} catch {}
}
/**
* Attempt to parse a structured CONTAINER_UNAVAILABLE JSON body from a
* non-101 upgrade response. Returns a typed ContainerUnavailableError when
* the body contains a recognized code, or null if the response is not
* JSON / not a container availability error.
*
* The response body is consumed only once via `clone()` so the caller still
* holds the original Response.
*/
async function tryParseContainerUnavailable(response) {
	if ((response.headers.get("content-type") ?? "").includes("application/json")) try {
		const body = await response.clone().json();
		if (body.code !== ErrorCode.CONTAINER_UNAVAILABLE) return null;
		const context = {
			reason: body.context?.reason === "container_starting" || body.context?.reason === "container_unhealthy" || body.context?.reason === "container_replaced" || body.context?.reason === "rpc_upgrade_failed" || body.context?.reason === "no_container_instance_available" || body.context?.reason === "max_container_instances_exceeded" ? body.context.reason : "container_replaced",
			retryable: true,
			...typeof body.context?.retryAfterMs === "number" && { retryAfterMs: body.context.retryAfterMs },
			...typeof body.context?.originalMessage === "string" && { originalMessage: body.context.originalMessage }
		};
		return createErrorFromResponse({
			code: ErrorCode.CONTAINER_UNAVAILABLE,
			message: body.message ?? "Container is unavailable",
			context,
			httpStatus: getHttpStatus(ErrorCode.CONTAINER_UNAVAILABLE),
			suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, context),
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
	} catch {
		return null;
	}
	try {
		const text = await response.clone().text();
		const reason = matchContainerUnavailable(text);
		if (!reason) return null;
		return buildContainerUnavailableError(reason, text);
	} catch {
		return null;
	}
}
/**
* True when a thrown connection-startup error matches a known platform
* container-admission failure. These are transient: the platform asks the
* caller to try again later, so they are safe to retry within the budget.
* Delegates to the shared matcher in platform-errors.ts.
*/
function isPlatformUnavailableError(error) {
	return matchContainerUnavailable(error) !== null;
}
/**
* Build a typed ContainerUnavailableError for a matched platform
* container-admission failure, preserving the original message verbatim.
*/
function buildContainerUnavailableError(reason, originalMessage, cause) {
	const context = {
		reason,
		retryable: true,
		originalMessage
	};
	return createErrorFromResponse({
		code: ErrorCode.CONTAINER_UNAVAILABLE,
		message: originalMessage,
		context,
		httpStatus: getHttpStatus(ErrorCode.CONTAINER_UNAVAILABLE),
		suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, context),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	}, cause !== void 0 ? { cause } : void 0);
}
/**
* Convert a raw connection-startup error into a typed ContainerUnavailableError
* when it matches a known platform container-admission failure. Returns null
* for anything else so the caller preserves the original error.
*/
function tryConvertPlatformUnavailable(error) {
	if (error instanceof SandboxError) return error;
	const reason = matchContainerUnavailable(error);
	if (!reason) return null;
	return buildContainerUnavailableError(reason, error instanceof Error ? error.message : String(error), error);
}
var DEFAULT_CONNECT_TIMEOUT_MS = 3e4;
var DEFAULT_RETRY_TIMEOUT_MS = 12e4;
var MIN_TIME_FOR_RETRY_MS = 15e3;
/**
* Manages a capnweb WebSocket RPC session to the container.
*
* The RPC stub is created eagerly in the constructor using a deferred
* transport. Calls made before `connect()` completes are queued in the
* transport and flushed once the WebSocket is established.
*/
var ContainerControlConnection = class {
	stub;
	session;
	transport;
	ws = null;
	connected = false;
	connectPromise = null;
	containerStub;
	port;
	logger;
	retryTimeoutMs;
	onClose;
	onConnectionError;
	onConnected;
	startContainer;
	getSandboxInfo;
	constructor(options) {
		this.containerStub = options.stub;
		this.port = options.port ?? 3e3;
		this.logger = options.logger ?? createNoOpLogger();
		this.retryTimeoutMs = options.retryTimeoutMs ?? DEFAULT_RETRY_TIMEOUT_MS;
		this.onClose = options.onClose;
		this.onConnectionError = options.onConnectionError;
		this.onConnected = options.onConnected;
		this.startContainer = options.startContainer;
		this.getSandboxInfo = options.getSandboxInfo;
		this.transport = new DeferredTransport();
		this.session = new RpcSession2(this.transport, options.localMain);
		this.stub = this.session.getRemoteMain();
	}
	/**
	* Get the typed RPC stub.
	*
	* The stub is available immediately — calls made before connect()
	* completes are queued in the deferred transport and flushed once
	* the WebSocket is established.
	*/
	rpc() {
		if (!this.connected && !this.connectPromise) this.connect().catch(() => {});
		return this.stub;
	}
	/**
	* Return capnweb session statistics. The `imports` and `exports` counts
	* reflect all in-flight RPC calls, streams, and peer-held references.
	* An idle session has imports <= 1 && exports <= 1 (the bootstrap stubs).
	*/
	getStats() {
		return this.session.getStats();
	}
	isConnected() {
		return this.connected;
	}
	/**
	* True while a connection attempt is in progress (upgrade not yet
	* established and not yet failed). Owners use this to avoid tearing the
	* connection down mid-attempt.
	*/
	isConnecting() {
		return this.connectPromise !== null;
	}
	/**
	* Resolve once any in-flight connection attempt settles (success or
	* failure). Resolves immediately when no attempt is in progress. Never
	* rejects — callers only care that the attempt is done.
	*/
	async whenSettled() {
		const pending = this.connectPromise;
		if (!pending) return;
		await pending.catch(() => {});
	}
	async connect() {
		if (this.connected) return;
		if (this.connectPromise) return this.connectPromise;
		this.connectPromise = this.doConnect();
		try {
			await this.connectPromise;
		} finally {
			this.connectPromise = null;
		}
	}
	/**
	* Tear down the connection. `cause` (a lifecycle teardown reason from the
	* owning DO) is used only for the disconnect trace event here; the owner
	* is responsible for stamping it as a *weak* connection cause (one that
	* never overwrites an authoritative failure already captured from a
	* connection attempt), since a teardown is usually a downstream
	* consequence of that earlier failure rather than the root cause.
	*/
	disconnect(cause) {
		if (cause !== void 0) traceEvent("sandbox.rpc.disconnect", {
			...this.spanAttrs(),
			reason: cause instanceof Error ? cause.message : String(cause)
		});
		else traceEvent("sandbox.rpc.disconnect", this.spanAttrs());
		try {
			this.stub[Symbol.dispose]?.();
		} catch {}
		if (this.ws) {
			this.ws.removeEventListener("close", this.onWebSocketClose);
			this.ws.removeEventListener("error", this.onWebSocketError);
			try {
				this.ws.close();
			} catch {}
			this.ws = null;
		}
		this.connected = false;
		this.connectPromise = null;
	}
	/**
	* Update the upgrade retry budget without recreating the connection. Takes
	* effect on the next `connect()`; an in-flight connect uses the value
	* captured at start. Mirrors `WebSocketTransport.setRetryTimeoutMs`.
	*/
	setRetryTimeoutMs(ms) {
		this.retryTimeoutMs = ms;
	}
	/**
	* Base span attributes for this connection: the container port plus the
	* sandbox identifiers (`sandbox.id` = DO id, `sandbox.name` = user name)
	* when available.
	*/
	spanAttrs() {
		const info = this.getSandboxInfo?.();
		return {
			"sandbox.rpc.port": this.port,
			"sandbox.id": info?.id,
			"sandbox.name": info?.name
		};
	}
	/**
	* Run the owner-provided `onClose` callback exactly once per call,
	* swallowing any errors so a buggy listener can't keep the connection
	* object in a half-torn-down state.
	*/
	fireOnClose() {
		if (!this.onClose) return;
		try {
			this.onClose();
		} catch (err) {
			this.logger.warn("ContainerControlConnection onClose handler threw", { error: err instanceof Error ? err.message : String(err) });
		}
	}
	/**
	* Run the owner-provided `onConnectionError` callback, swallowing any
	* listener errors.
	*/
	fireConnectionError(error) {
		if (!this.onConnectionError) return;
		try {
			this.onConnectionError(error);
		} catch (err) {
			this.logger.warn("ContainerControlConnection onConnectionError handler threw", { error: err instanceof Error ? err.message : String(err) });
		}
	}
	/**
	* WebSocket `close` listener. Defined as a bound arrow field so the
	* same reference can be passed to both `addEventListener` and
	* `removeEventListener` — a fresh anonymous lambda would silently
	* fail to unbind.
	*/
	onWebSocketClose = () => {
		const wasConnected = this.connected;
		this.connected = false;
		this.ws = null;
		this.logger.debug("ContainerControlConnection WebSocket closed");
		if (wasConnected) this.fireOnClose();
	};
	/**
	* WebSocket `error` listener. Same field-form rationale as
	* {@link onWebSocketClose}.
	*/
	onWebSocketError = () => {
		const wasConnected = this.connected;
		this.connected = false;
		this.ws = null;
		if (wasConnected) this.fireOnClose();
	};
	async doConnect() {
		return withSpan("sandbox.rpc.connect", this.spanAttrs(), () => this.doConnectInner());
	}
	async doConnectInner() {
		try {
			const response = await this.fetchUpgradeWithRetry();
			if (response.status !== 101) {
				const structured = await tryParseContainerUnavailable(response);
				if (structured) throw structured;
				if (isRetryableWebSocketUpgradeResponse(response)) throw createErrorFromResponse({
					code: ErrorCode.CONTAINER_UNAVAILABLE,
					message: `Container was unavailable after exhausting upgrade retry budget (status ${response.status})`,
					context: {
						reason: "rpc_upgrade_failed",
						retryable: true
					},
					httpStatus: getHttpStatus(ErrorCode.CONTAINER_UNAVAILABLE),
					suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, {}),
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
				throw new Error(`WebSocket upgrade failed: ${response.status} ${response.statusText}`);
			}
			const ws = response.webSocket;
			if (!ws) throw new Error("No WebSocket in upgrade response");
			ws.accept();
			ws.addEventListener("close", this.onWebSocketClose);
			ws.addEventListener("error", this.onWebSocketError);
			this.ws = ws;
			this.transport.activate(ws);
			this.connected = true;
			try {
				this.onConnected?.();
			} catch (err) {
				this.logger.warn("ContainerControlConnection onConnected handler threw", { error: err instanceof Error ? err.message : String(err) });
			}
			this.logger.debug("ContainerControlConnection established", { port: this.port });
		} catch (error) {
			this.connected = false;
			const connectionError = tryConvertPlatformUnavailable(error) ?? error;
			this.fireConnectionError(connectionError);
			this.transport.abort(connectionError);
			this.fireOnClose();
			this.logger.error("ContainerControlConnection failed", connectionError instanceof Error ? connectionError : new Error(String(connectionError)));
			throw connectionError;
		}
	}
	/**
	* Issue WebSocket upgrade fetches, retrying transient control-plane
	* unavailability responses until either the upgrade succeeds, a
	* non-retryable status is returned, or the retry budget runs out.
	*/
	async fetchUpgradeWithRetry() {
		return fetchWithResponseRetry(() => this.fetchUpgradeAttempt(), {
			retryTimeoutMs: this.retryTimeoutMs,
			minTimeForRetryMs: MIN_TIME_FOR_RETRY_MS,
			logger: this.logger,
			retryLogMessage: "ContainerControlConnection upgrade returned retryable status, retrying",
			shouldRetry: isRetryableWebSocketUpgradeResponse,
			shouldRetryError: isPlatformUnavailableError
		});
	}
	/**
	* Single WebSocket-upgrade fetch attempt.
	*
	* Container start and the upgrade fetch have deliberately separate timeout
	* scopes:
	*
	*   - `startContainer()` runs under the base `Container` class's own
	*     instance-get / port-ready budget. It must NOT be cut short by the
	*     per-attempt connect timeout: the base class only emits the
	*     classifiable `NO_CONTAINER_INSTANCE_ERROR` after its internal budget
	*     is exhausted, and it checks its abort signal *before* that throw
	*     (see @cloudflare/containers `doStartContainer`). Aborting it early
	*     yields a generic "Aborted waiting for container to start" error that
	*     we can't classify — which is what masked the real cause as
	*     OPERATION_INTERRUPTED. Letting it run its own budget means the
	*     platform capacity failure throws here, in our retry loop, where
	*     `shouldRetryError` retries it and `doConnect`'s catch converts it to
	*     a typed ContainerUnavailableError.
	*
	*   - The WebSocket upgrade fetch gets its own fresh AbortController so
	*     each retry has an independent connect timeout for the *upgrade only*.
	*/
	async fetchUpgradeAttempt() {
		return withSpan("sandbox.rpc.connect.attempt", this.spanAttrs(), async () => {
			if (this.startContainer) try {
				await this.startContainer();
			} catch (error) {
				this.fireConnectionError(tryConvertPlatformUnavailable(error) ?? error);
				throw error;
			}
			const controller = new AbortController();
			const timeout = setTimeout(() => controller.abort(), DEFAULT_CONNECT_TIMEOUT_MS);
			try {
				const url = `http://localhost:${this.port}/rpc`;
				const request = new Request(url, {
					headers: {
						Upgrade: "websocket",
						Connection: "Upgrade"
					},
					signal: controller.signal
				});
				return await this.containerStub.fetch(request);
			} finally {
				clearTimeout(timeout);
			}
		});
	}
};
/**
* RPC transport that queues sends and blocks receives until a WebSocket
* is provided via `activate()`. Allows the RPC stub to be created before
* the connection is established — queued calls flush automatically.
*/
var DeferredTransport = class {
	#ws = null;
	#sendQueue = [];
	#receiveQueue = [];
	#receiveResolver;
	#receiveRejecter;
	#error;
	activate(ws) {
		this.#ws = ws;
		ws.addEventListener("message", (event) => {
			if (this.#error) return;
			if (typeof event.data === "string") if (this.#receiveResolver) {
				this.#receiveResolver(event.data);
				this.#receiveResolver = void 0;
				this.#receiveRejecter = void 0;
			} else this.#receiveQueue.push(event.data);
			else this.#fail(/* @__PURE__ */ new TypeError("Received non-string message from WebSocket."));
		});
		ws.addEventListener("close", (event) => {
			this.#fail(/* @__PURE__ */ new Error(`Peer closed WebSocket: ${event.code} ${event.reason}`));
		});
		ws.addEventListener("error", () => {
			this.#fail(/* @__PURE__ */ new Error("WebSocket connection failed."));
		});
		for (const msg of this.#sendQueue) ws.send(msg);
		this.#sendQueue = [];
	}
	async send(message) {
		if (this.#ws) this.#ws.send(message);
		else this.#sendQueue.push(message);
	}
	async receive() {
		if (this.#receiveQueue.length > 0) return this.#receiveQueue.shift();
		if (this.#error) throw this.#error;
		return new Promise((resolve, reject) => {
			this.#receiveResolver = resolve;
			this.#receiveRejecter = reject;
		});
	}
	abort(reason) {
		this.#fail(reason instanceof Error ? reason : new Error(String(reason)));
		if (this.#ws) {
			const message = reason instanceof Error ? reason.message : String(reason);
			this.#ws.close(3e3, message);
		}
	}
	#fail(err) {
		if (this.#error) return;
		this.#error = err;
		this.#receiveRejecter?.(err);
		this.#receiveResolver = void 0;
		this.#receiveRejecter = void 0;
	}
};
/** Close the idle capnweb WebSocket promptly so the DO can sleep. */
var DEFAULT_IDLE_DISCONNECT_MS = 1e3;
/**
* How often the busy/idle poller samples `getStats()`.
*
* Sets two worst-case bounds:
*
*   1. **Idle-detection lag.** Time between the session going idle on
*      the wire and the DO observing it (and arming the disconnect).
*      Bounded by `pollInterval`.
*   2. **Activity-renewal lag while busy.** While a stream is active we
*      renew the DO's activity timeout once per tick. The alarm could
*      fire as late as `sleepAfter` after the last renew, so the
*      effective margin against a mid-stream sleep is
*      `sleepAfter - pollInterval`.
*
* **Invariant: `pollInterval` must be comfortably less than the
* smallest configurable `sleepAfter`.** Aim for at least 2-3× headroom.
* The minimum `sleepAfter` exercised by the E2E suite is 3s, so 1s gives
* 3× margin and at least two renewals during a 3s window. If a smaller
* `sleepAfter` is ever supported, drop this proportionally.
*/
var BUSY_POLL_INTERVAL_MS = 1e3;
/**
* Baseline getStats() values for an idle session. The bootstrap stub on each
* side accounts for 1 import and 1 export.
*/
var IDLE_IMPORT_THRESHOLD = 1;
var IDLE_EXPORT_THRESHOLD = 1;
function translateRPCError(error, context = {}) {
	if (error instanceof SandboxError) throw error;
	if (error instanceof Error) {
		const propagated = error;
		if (typeof propagated.code === "string" && Object.hasOwn(ErrorCode, propagated.code)) {
			const code = propagated.code;
			const context$1 = propagated.details && typeof propagated.details === "object" ? propagated.details : {};
			throw createErrorFromResponse({
				code,
				message: error.message,
				context: context$1,
				httpStatus: getHttpStatus(code),
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
		let payload;
		try {
			payload = JSON.parse(error.message);
		} catch {}
		if (payload && typeof payload.code === "string" && typeof payload.message === "string") throw createErrorFromResponse({
			code: payload.code,
			message: payload.message,
			context: payload.context ?? {},
			httpStatus: getHttpStatus(payload.code),
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		const transportResponse = buildTransportErrorResponse(error);
		const captured = maybePreferConnectionError(transportResponse, context);
		if (captured) throw captured;
		if (context.sessionEstablished === false) throw createErrorFromResponse(buildNeverConnectedUnavailableResponse(transportResponse, context) ?? transportResponse, { cause: error });
		throw createErrorFromResponse(buildInterruptedOperationResponse(transportResponse, context) ?? transportResponse, { cause: error });
	}
	throw createErrorFromResponse(buildTransportErrorResponse(new Error(String(error))), { cause: error });
}
/**
* Inspect a transport-level Error's message and produce the ErrorResponse
* that becomes an RPCTransportError. Pattern strings are pinned to the exact
* messages emitted by capnweb's WebSocketTransport (see capnweb's
* src/websocket.ts) and our DeferredTransport in container-control/connection.ts —
* notably the trailing period in `WebSocket connection failed.` matches
* capnweb verbatim. The DeferredTransport tests in
* tests/container-connection.test.ts pin the literal strings.
*/
function buildTransportErrorResponse(error) {
	const message = error.message;
	const errorName = error.name;
	let kind = "unknown";
	let closeCode;
	let closeReason;
	if (errorName === "TypeError") kind = "invalid_frame";
	else if (errorName === "SyntaxError") kind = "protocol_error";
	else {
		const peerCloseMatch = message.match(/^Peer closed WebSocket: (\d+) ?(.*)$/);
		if (peerCloseMatch) {
			kind = "peer_closed";
			closeCode = Number(peerCloseMatch[1]);
			closeReason = peerCloseMatch[2] || void 0;
		} else if (message === "WebSocket connection failed.") kind = "connection_failed";
		else if (message.startsWith("WebSocket upgrade failed")) kind = "upgrade_failed";
		else if (message === "No WebSocket in upgrade response") kind = "upgrade_failed";
		else if (message === "RPC session was shut down by disposing the main stub" || message === "RPC was canceled because the RpcPromise was disposed.") kind = "session_disposed";
	}
	const context = {
		kind,
		originalMessage: message,
		errorName,
		...closeCode !== void 0 ? { closeCode } : {},
		...closeReason !== void 0 ? { closeReason } : {}
	};
	return {
		code: ErrorCode.RPC_TRANSPORT_ERROR,
		message,
		context,
		httpStatus: getHttpStatus(ErrorCode.RPC_TRANSPORT_ERROR),
		suggestion: getSuggestion(ErrorCode.RPC_TRANSPORT_ERROR, context),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	};
}
/**
* Extract a recognized structured error shape from a captured connection cause.
* Accepts both same-realm SandboxError instances and plain error-like objects
* that carry a known `code` plus either `context` or `details`.
*/
function extractCapturedErrorShape(captured) {
	if (captured instanceof SandboxError) return {
		code: captured.code,
		message: captured.message,
		context: captured.context ?? {}
	};
	const shape = captured;
	if (!shape || typeof shape.code !== "string" || !Object.hasOwn(ErrorCode, shape.code)) return null;
	const code = shape.code;
	const structured = shape.context && typeof shape.context === "object" ? shape.context : shape.details && typeof shape.details === "object" ? shape.details : {};
	return {
		code,
		message: typeof shape.message === "string" ? shape.message : code,
		context: structured
	};
}
var OPERATION_INTERRUPTED_REASONS = /* @__PURE__ */ new Set([
	"runtime_replaced",
	"transport_disposed",
	"sandbox_lifetime_changed",
	"recovery_exhausted"
]);
function asOperationInterruptedReason(value) {
	return typeof value === "string" && OPERATION_INTERRUPTED_REASONS.has(value) ? value : null;
}
function asInterruptedAdmitted(value) {
	if (typeof value === "boolean" || value === "unknown") return value;
}
/**
* Lifecycle disconnect causes are stamped with a generic connection-level
* operation identity. When they interrupt a concrete RPC method, rebind the
* public interruption context onto that method while preserving the lifecycle
* reason, retryability, and stop metadata.
*/
function rebindInterruptedOperationContext(shape, context, cause) {
	if (shape.code !== ErrorCode.OPERATION_INTERRUPTED || typeof context.operation !== "string" || context.operation.length === 0) return createErrorFromResponse({
		code: shape.code,
		message: shape.message,
		context: shape.context,
		httpStatus: getHttpStatus(shape.code),
		suggestion: getSuggestion(shape.code, shape.context),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	}, { cause });
	const reason = asOperationInterruptedReason(shape.context.reason) ?? "transport_disposed";
	const admitted = context.sessionEstablished === true ? true : context.sessionEstablished === false ? false : asInterruptedAdmitted(shape.context.admitted) ?? "unknown";
	const retryable = typeof shape.context.retryable === "boolean" ? shape.context.retryable : false;
	const interruptedContext = {
		reason,
		operation: context.operation,
		phase: "rpc_call",
		admitted,
		retryable,
		...typeof shape.context.recoveryAttempts === "number" && { recoveryAttempts: shape.context.recoveryAttempts },
		...typeof shape.context.maxRecoveryAttempts === "number" && { maxRecoveryAttempts: shape.context.maxRecoveryAttempts },
		...typeof shape.context.containerExitCode === "number" && { containerExitCode: shape.context.containerExitCode },
		...typeof shape.context.stopReason === "string" && { stopReason: shape.context.stopReason }
	};
	return new OperationInterruptedError({
		code: ErrorCode.OPERATION_INTERRUPTED,
		message: shape.message,
		context: interruptedContext,
		httpStatus: getHttpStatus(ErrorCode.OPERATION_INTERRUPTED),
		suggestion: getSuggestion(ErrorCode.OPERATION_INTERRUPTED, interruptedContext),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	}, { cause });
}
/**
* When a queued RPC call rejects with a transport error that a connection
* abort could have caused (session disposed, connection failed, upgrade
* failed, or peer closed), and the connection captured a real startup or
* lifecycle error, return that captured error in preference to the masking
* transport error.
*
* The captured error is accepted whether it is:
*   - a same-realm `SandboxError`, or
*   - any structured, error-like value carrying a recognized `code` — e.g. a
*     raw or cross-realm error decorated with `code: 'CONTAINER_UNAVAILABLE'`
*     and optional `context`/`details`/`message`. Such values are rehydrated
*     via `createErrorFromResponse` into a typed SandboxError.
*
* Lifecycle interruption causes are rebound onto the pending RPC method so the
* public error names that operation and keeps the lifecycle reason,
* retryability, and stop metadata.
*
* Anything without a recognized code is ignored so the caller falls back to
* normal transport classification.
*/
function maybePreferConnectionError(transportResponse, context) {
	const captured = context.connectionError;
	if (!captured) return null;
	const { kind } = transportResponse.context;
	if (kind !== "session_disposed" && kind !== "connection_failed" && kind !== "upgrade_failed" && kind !== "peer_closed") return null;
	const shape = extractCapturedErrorShape(captured);
	if (!shape) return null;
	return rebindInterruptedOperationContext(shape, context, captured);
}
/**
* When the session never established a live connection and a queued RPC call
* rejects with a teardown-family transport error (disposed / connection
* failed / peer closed), surface a clean, retryable `ContainerUnavailableError`
* instead of the raw capnweb string (e.g. "RPC session was shut down by
* disposing the main stub").
*
* Reaching this point means: the container never became reachable (so no
* OPERATION_INTERRUPTED — nothing was admitted) AND no structured connection
* error was captured (so `maybePreferConnectionError` didn't fire). That's the
* Durable Object being torn down/evicted mid-startup under capacity pressure
* before `doConnect` recorded a cause — which is, from the caller's view, the
* container being unavailable. Retryable, with the raw transport message
* preserved as `originalMessage` for diagnostics.
*
* `upgrade_failed` is intentionally excluded here. Unlike disposal/close
* during startup, an HTTP upgrade failure with no captured structured cause can
* be a permanent configuration or routing error (for example, a 404 on `/rpc`),
* so the generic transport classification is more accurate than retryable
* container unavailability.
*/
function buildNeverConnectedUnavailableResponse(transportResponse, context) {
	if (context.sessionEstablished !== false) return null;
	const { kind } = transportResponse.context;
	if (kind !== "session_disposed" && kind !== "connection_failed" && kind !== "peer_closed") return null;
	const ctx = {
		reason: "container_unreachable",
		retryable: true,
		originalMessage: transportResponse.context.originalMessage
	};
	return {
		code: ErrorCode.CONTAINER_UNAVAILABLE,
		message: "The sandbox container was unavailable: the connection was torn down before it became reachable. Retry the operation.",
		context: ctx,
		httpStatus: getHttpStatus(ErrorCode.CONTAINER_UNAVAILABLE),
		suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, ctx),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	};
}
function buildInterruptedOperationResponse(transportResponse, context) {
	if (!context.operation) return null;
	const { kind } = transportResponse.context;
	if (kind !== "session_disposed" && kind !== "peer_closed" && kind !== "connection_failed") return null;
	const interruptedContext = {
		reason: kind === "session_disposed" ? "transport_disposed" : "runtime_replaced",
		operation: context.operation,
		phase: "rpc_call",
		admitted: context.sessionEstablished === true ? true : context.sessionEstablished === false ? false : "unknown",
		retryable: false
	};
	const action = kind === "session_disposed" ? "was closing" : "closed unexpectedly";
	return {
		code: ErrorCode.OPERATION_INTERRUPTED,
		message: `Sandbox operation ${context.operation} was interrupted while the runtime connection ${action}`,
		context: interruptedContext,
		httpStatus: getHttpStatus(ErrorCode.OPERATION_INTERRUPTED),
		suggestion: getSuggestion(ErrorCode.OPERATION_INTERRUPTED, interruptedContext),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	};
}
/**
* Wrap a capnweb RPC stub so that every method call translates errors
* from the JSON wire format into typed SandboxError instances and signals
* activity at call start.
*
* `onCallStarted` fires synchronously when an RPC method is invoked, and
* `onCallSettled` fires when the returned promise settles. The
* ContainerControlClient uses these hooks to keep the session marked busy
* even if capnweb stats briefly report the bootstrap baseline while a call is
* still pending.
*
* A method whose returned promise resolves with a `ReadableStream` is *not*
* finished when the promise settles — capnweb keeps the export alive until
* the stream ends. The busy/idle poll on `getStats()` remains the source of
* truth for stream lifetimes after the initial RPC promise settles.
*/
function wrapStub(stub, domain, onCallStarted, onCallSettled, getConnectionError, getSessionEstablished, getSpanAttrs) {
	return new Proxy(stub, { get(target, prop, receiver) {
		const value = Reflect.get(target, prop, receiver);
		if (typeof value !== "function") return value;
		return (...args) => {
			onCallStarted();
			const operation = typeof prop === "string" ? `${domain}.${prop}` : domain;
			try {
				const result = Reflect.apply(value, target, args);
				if (result != null && typeof result.then === "function") return withSpan(`sandbox.rpc.call ${operation}`, {
					...getSpanAttrs(),
					operation
				}, () => result.catch((err) => translateRPCError(err, {
					operation,
					connectionError: getConnectionError(),
					sessionEstablished: getSessionEstablished()
				}))).finally(onCallSettled);
				onCallSettled();
				return result;
			} catch (err) {
				onCallSettled();
				translateRPCError(err, {
					operation,
					connectionError: getConnectionError(),
					sessionEstablished: getSessionEstablished()
				});
			}
		};
	} });
}
/**
* SandboxClient-compatible facade backed by direct capnweb RPC.
*
* All operations call the container's SandboxAPI control interface directly
* over capnweb, bypassing the HTTP handler/router layer entirely.
*
* Manages its own WebSocket lifecycle: a fresh `ContainerControlConnection` is
* created on demand and torn down after `idleDisconnectMs` of inactivity.
* Busy/idle detection relies on `RpcSession.getStats()` which tracks all
* in-flight RPC calls and stream exports — including long-lived streaming
* RPCs that would be invisible to a simple per-call request counter (see
* the file-level comment for the full rationale).
*/
var ContainerControlClient = class {
	connOptions;
	idleDisconnectMs;
	busyPollIntervalMs;
	logger;
	onActivity;
	onSessionBusy;
	onSessionIdle;
	conn = null;
	/**
	* Real cause captured by the connection during startup failure (e.g. a
	* platform container-allocation error). Preferred over the generic capnweb
	* disposal error when translating queued RPC rejections. Cleared each time a
	* fresh connection is created.
	*/
	lastConnectionError = null;
	/**
	* Whether `lastConnectionError` was captured from an actual connection
	* attempt failure (authoritative root cause) rather than a lifecycle
	* teardown reason (weak). A weak teardown cause — e.g. `onStop` firing
	* `runtime_replaced` — is usually a downstream *consequence* of the real
	* failure, so it must not overwrite an authoritative cause already
	* captured from the connect attempt.
	*/
	connectionErrorIsAuthoritative = false;
	/**
	* Whether the current connection ever established a live session to a
	* running container. Set true by the connection's `onConnected` callback,
	* reset when a fresh connection is created. Lets `translateRPCError`
	* distinguish a true interruption (established, then dropped) from a
	* never-connected failure (container never started).
	*/
	sessionEstablished = false;
	idleTimer = null;
	busyPollTimer = null;
	/** Number of RPC method promises that have started but not settled. */
	activeCalls = 0;
	/** Tracks whether we currently believe the session is busy. */
	busy = false;
	constructor(options) {
		this.connOptions = {
			stub: options.stub,
			port: options.port,
			localMain: options.localMain,
			logger: options.logger,
			retryTimeoutMs: options.retryTimeoutMs,
			getSandboxInfo: options.getSandboxInfo,
			startContainer: options.startContainer,
			onConnected: () => {
				this.sessionEstablished = true;
				this.lastConnectionError = null;
				this.connectionErrorIsAuthoritative = false;
			},
			onClose: () => {
				if (this.conn) this.destroyConnection();
			},
			onConnectionError: (error) => {
				this.lastConnectionError = error;
				this.connectionErrorIsAuthoritative = true;
			}
		};
		this.idleDisconnectMs = options.idleDisconnectMs ?? DEFAULT_IDLE_DISCONNECT_MS;
		this.busyPollIntervalMs = options.busyPollIntervalMs ?? BUSY_POLL_INTERVAL_MS;
		this.logger = options.logger ?? createNoOpLogger();
		this.onActivity = options.onActivity;
		this.onSessionBusy = options.onSessionBusy;
		this.onSessionIdle = options.onSessionIdle;
	}
	/**
	* Return the current connection, creating one when the client is disconnected.
	* Starts the busy-poll timer the first time a connection is materialized.
	*/
	getConnection() {
		if (!this.conn) {
			this.lastConnectionError = null;
			this.connectionErrorIsAuthoritative = false;
			this.sessionEstablished = false;
			this.conn = new ContainerControlConnection(this.connOptions);
			this.startBusyPoll();
		}
		return this.conn;
	}
	/**
	* Stamp a *weak* connection cause (a lifecycle teardown reason). Only takes
	* effect if no authoritative connect-attempt failure has been captured, so
	* a teardown consequence never masks the real root cause.
	*/
	stampWeakConnectionCause(cause) {
		if (cause === void 0) return;
		if (this.connectionErrorIsAuthoritative) return;
		this.lastConnectionError = cause;
	}
	fireUserCallback(name, callback) {
		if (!callback) return;
		try {
			callback();
		} catch (error) {
			this.logger.warn("ContainerControlClient callback threw", {
				callback: name,
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}
	fireActivity() {
		this.fireUserCallback("onActivity", this.onActivity);
	}
	fireSessionBusy() {
		this.fireUserCallback("onSessionBusy", this.onSessionBusy);
	}
	fireSessionIdle() {
		this.fireUserCallback("onSessionIdle", this.onSessionIdle);
	}
	markBusy() {
		if (!this.busy) {
			this.busy = true;
			this.fireSessionBusy();
		}
		this.clearIdleTimer();
	}
	isSessionBusy(conn) {
		const { imports, exports } = conn.getStats();
		return this.activeCalls > 0 || imports > IDLE_IMPORT_THRESHOLD || exports > IDLE_EXPORT_THRESHOLD;
	}
	maybeTransitionIdle() {
		const conn = this.conn;
		if (!conn) return;
		if (!conn.isConnected()) return;
		this.transitionIdleIfReady(conn);
	}
	transitionIdleIfReady(conn) {
		if (this.isSessionBusy(conn)) {
			this.markBusy();
			return;
		}
		if (this.busy) {
			this.busy = false;
			this.fireSessionIdle();
			this.scheduleIdleDisconnect();
		} else if (!this.idleTimer) this.scheduleIdleDisconnect();
	}
	/**
	* Called synchronously at the start of each RPC method invocation.
	* Renews the DO activity timeout so the sleepAfter alarm is pushed
	* forward before the container processes the call, and pins the RPC
	* WebSocket as busy until the method's promise settles.
	*/
	recordCallStarted = () => {
		this.activeCalls++;
		this.markBusy();
		this.fireActivity();
	};
	recordCallSettled = () => {
		this.activeCalls = Math.max(0, this.activeCalls - 1);
		this.maybeTransitionIdle();
	};
	/** Return the last connection-startup error captured, if any. */
	getLastConnectionError = () => this.lastConnectionError;
	/** Whether the current connection ever established a live session. */
	getSessionEstablished = () => this.sessionEstablished;
	/**
	* Base span attributes for RPC-call spans: sandbox identifiers plus the
	* container port. Mirrors the connection's `spanAttrs()` so all
	* `sandbox.rpc.*` spans share a consistent shape.
	*/
	getSpanAttrs = () => {
		const info = this.connOptions.getSandboxInfo?.();
		return {
			"sandbox.id": info?.id,
			"sandbox.name": info?.name,
			"sandbox.rpc.port": this.connOptions.port !== void 0 ? String(this.connOptions.port) : void 0
		};
	};
	/**
	* Sample `getStats()` and update busy/idle state. While busy, renews the
	* activity timeout each tick so an in-flight stream keeps pushing the
	* sleepAfter deadline forward. On the busy → idle edge, fires
	* `onSessionIdle` and schedules the WebSocket disconnect.
	*
	* If the WebSocket has dropped underneath us (container crash, network
	* blip) we tear the connection down here. `destroyConnection()` fires
	* `onSessionIdle` if we were busy, so the DO's inflight counter doesn't
	* stay pinned forever waiting for a peer that's never going to reply.
	*/
	pollBusyState = () => {
		const conn = this.conn;
		if (!conn) return;
		if (!conn.isConnected()) return;
		if (this.isSessionBusy(conn)) {
			this.markBusy();
			this.fireActivity();
			return;
		}
		this.transitionIdleIfReady(conn);
	};
	startBusyPoll() {
		if (this.busyPollTimer) return;
		this.busyPollTimer = setInterval(this.pollBusyState, this.busyPollIntervalMs);
	}
	stopBusyPoll() {
		if (this.busyPollTimer) {
			clearInterval(this.busyPollTimer);
			this.busyPollTimer = null;
		}
	}
	scheduleIdleDisconnect() {
		this.clearIdleTimer();
		this.idleTimer = setTimeout(() => {
			this.idleTimer = null;
			const conn = this.conn;
			if (!conn || !conn.isConnected()) return;
			if (!this.isSessionBusy(conn)) {
				this.logger.debug("Disconnecting idle RPC connection");
				this.destroyConnection();
			}
		}, this.idleDisconnectMs);
	}
	clearIdleTimer() {
		if (this.idleTimer) {
			clearTimeout(this.idleTimer);
			this.idleTimer = null;
		}
	}
	destroyConnection(cause) {
		this.stopBusyPoll();
		this.clearIdleTimer();
		this.activeCalls = 0;
		if (this.busy) {
			this.busy = false;
			this.fireSessionIdle();
		}
		if (this.conn) {
			this.stampWeakConnectionCause(cause);
			this.conn.disconnect(cause);
			this.conn = null;
		}
	}
	get commands() {
		return wrapStub(this.getConnection().rpc().commands, "commands", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get files() {
		return wrapStub(this.getConnection().rpc().files, "files", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get processes() {
		return wrapStub(this.getConnection().rpc().processes, "processes", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get ports() {
		return wrapStub(this.getConnection().rpc().ports, "ports", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get git() {
		return wrapStub(this.getConnection().rpc().git, "git", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get utils() {
		return wrapStub(this.getConnection().rpc().utils, "utils", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get backup() {
		return wrapStub(this.getConnection().rpc().backup, "backup", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get watch() {
		return wrapStub(this.getConnection().rpc().watch, "watch", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get tunnels() {
		return wrapStub(this.getConnection().rpc().tunnels, "tunnels", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	get interpreter() {
		return wrapStub(this.getConnection().rpc().interpreter, "interpreter", this.recordCallStarted, this.recordCallSettled, this.getLastConnectionError, this.getSessionEstablished, this.getSpanAttrs);
	}
	/**
	* Update the upgrade retry budget. Applies to the current connection
	* (if any) and is remembered for any future connections created after the
	* client is torn down and reconnected.
	*/
	setRetryTimeoutMs(ms) {
		this.connOptions.retryTimeoutMs = ms;
		this.conn?.setRetryTimeoutMs(ms);
	}
	getTransportMode() {
		return "rpc";
	}
	isWebSocketConnected() {
		return this.conn?.isConnected() ?? false;
	}
	async connect() {
		await this.getConnection().connect();
	}
	/**
	* Tear down the active connection.
	*
	* When a connection attempt is still in progress, the teardown is deferred
	* until that attempt settles — so a lifecycle disconnect (e.g. the DO's
	* alarm firing `onStop`) cannot rip the transport out from under an
	* in-flight connect and reject queued calls with a generic disposal error.
	* The provided `cause` is stamped immediately so that if the attempt fails,
	* queued calls surface it; if the attempt succeeds, the (now-established)
	* connection is then torn down cleanly with the cause.
	*
	* During this deferral window `this.conn` still points at the connecting
	* transport so queued calls can keep their original connection context.
	* Container lifecycle code treats `disconnect()` as terminal and does not
	* issue more RPC calls after requesting it.
	*
	* `cause` should be a typed `SandboxError` describing why the connection is
	* being torn down (sandbox stopping, lifetime change, transport switch).
	*/
	disconnect(cause) {
		const conn = this.conn;
		if (conn?.isConnecting()) {
			this.stopBusyPoll();
			this.clearIdleTimer();
			this.activeCalls = 0;
			if (this.busy) {
				this.busy = false;
				this.fireSessionIdle();
			}
			this.stampWeakConnectionCause(cause);
			conn.whenSettled().then(() => {
				if (this.conn === conn) this.destroyConnection(cause);
			});
			return;
		}
		this.destroyConnection(cause);
	}
};
/**
* Parse SSE (Server-Sent Events) lines from a stream
*/
async function* parseSSE(stream) {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	let currentEvent = { data: [] };
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			buffer += decoder.decode(value, { stream: true });
			const parsed = parseSSEFrames(buffer, currentEvent);
			buffer = parsed.remaining;
			currentEvent = parsed.currentEvent;
			for (const frame of parsed.events) try {
				yield JSON.parse(frame.data);
			} catch {}
		}
		const finalParsed = parseSSEFrames(`${buffer}\n\n`, currentEvent);
		for (const frame of finalParsed.events) try {
			yield JSON.parse(frame.data);
		} catch {}
	} finally {
		try {
			await reader.cancel();
		} catch {}
		reader.releaseLock();
	}
}
/**
* Stream a file from the sandbox with automatic base64 decoding for binary files
*
* @param stream - The ReadableStream from readFileStream()
* @returns AsyncGenerator that yields FileChunk (string for text, Uint8Array for binary)
*
* @example
* ```ts
* const stream = await sandbox.readFileStream('/path/to/file.png');
* for await (const chunk of streamFile(stream)) {
*   if (chunk instanceof Uint8Array) {
*     // Binary chunk
*     console.log('Binary chunk:', chunk.length, 'bytes');
*   } else {
*     // Text chunk
*     console.log('Text chunk:', chunk);
*   }
* }
* ```
*/
async function* streamFile(stream) {
	const { chunks } = await openFileStream(stream);
	return yield* chunks;
}
/**
* Read the metadata event at the head of a file stream and return it with
* the decoded chunks that follow. Callers that need the file size before
* consuming the body, such as sizing a FixedLengthStream, use this instead of
* streamFile(). Call cancel() to release the stream without reading the rest.
*/
async function openFileStream(stream) {
	const events = parseSSE(stream);
	const cancel = async () => {
		await events.return(void 0);
	};
	try {
		const first = await events.next();
		if (first.done) throw new Error("Stream ended unexpectedly");
		const metadata = readMetadataEvent(first.value);
		return {
			metadata,
			chunks: decodeChunks(events, metadata),
			cancel
		};
	} catch (error) {
		await cancel();
		throw error;
	}
}
function readMetadataEvent(event) {
	switch (event.type) {
		case "metadata": return toFileMetadata(event);
		case "chunk": throw new Error("Received chunk before metadata");
		case "complete": throw new Error("Stream completed without metadata");
		case "error": throw new Error(`File streaming error: ${event.error}`);
	}
}
async function* decodeChunks(events, initialMetadata) {
	let metadata = initialMetadata;
	for await (const event of events) switch (event.type) {
		case "metadata":
			metadata = toFileMetadata(event);
			break;
		case "chunk":
			if (metadata.isBinary && metadata.encoding === "base64") {
				const binaryString = atob(event.data);
				const bytes = new Uint8Array(binaryString.length);
				for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
				yield bytes;
			} else yield event.data;
			break;
		case "complete": return metadata;
		case "error": throw new Error(`File streaming error: ${event.error}`);
	}
	throw new Error("Stream ended unexpectedly");
}
function toFileMetadata(event) {
	return {
		mimeType: event.mimeType,
		size: event.size,
		isBinary: event.isBinary,
		encoding: event.encoding
	};
}
/**
* Security utilities for URL construction and input validation
*
* This module contains critical security functions to prevent:
* - URL injection attacks
* - SSRF (Server-Side Request Forgery) attacks
* - DNS rebinding attacks
* - Host header injection
* - Open redirect vulnerabilities
*/
var SandboxSecurityError = class extends Error {
	constructor(message, code) {
		super(message);
		this.code = code;
		this.name = "SandboxSecurityError";
	}
};
/**
* Validates port numbers for sandbox services.
*
* Rules:
* - Range: 1024-65535 (privileged ports require root, which containers don't have)
* - Reserved: 3000 (sandbox control plane)
*/
function validatePort(port) {
	if (!Number.isInteger(port)) return false;
	if (port < 1024 || port > 65535) return false;
	if ([3e3].includes(port)) return false;
	return true;
}
/**
* Sanitizes and validates sandbox IDs for DNS compliance and security
* Only enforces critical requirements - allows maximum developer flexibility
*/
function sanitizeSandboxId(id) {
	if (!id || id.length > 63) throw new SandboxSecurityError("Sandbox ID must be 1-63 characters long.", "INVALID_SANDBOX_ID_LENGTH");
	if (id.startsWith("-") || id.endsWith("-")) throw new SandboxSecurityError("Sandbox ID cannot start or end with hyphens (DNS requirement).", "INVALID_SANDBOX_ID_HYPHENS");
	const reservedNames = [
		"www",
		"api",
		"admin",
		"root",
		"system",
		"cloudflare",
		"workers"
	];
	const lowerCaseId = id.toLowerCase();
	if (reservedNames.includes(lowerCaseId)) throw new SandboxSecurityError(`Reserved sandbox ID '${id}' is not allowed.`, "RESERVED_SANDBOX_ID");
	return id;
}
/**
* Validates language for code interpreter
* Only allows supported languages
*/
function validateLanguage(language) {
	if (!language) return;
	const supportedLanguages = [
		"python",
		"python3",
		"javascript",
		"js",
		"node",
		"typescript",
		"ts"
	];
	const normalized = language.toLowerCase();
	if (!supportedLanguages.includes(normalized)) throw new SandboxSecurityError(`Unsupported language '${language}'. Supported languages: python, javascript, typescript`, "INVALID_LANGUAGE");
}
/**
* Validates a single DNS label for use as a Cloudflare Tunnel hostname.
*
* Used by `sandbox.tunnels.get(port, { name })` to reject obviously-bad
* input client-side before any network call. Whether the chosen label is
* actually available under the configured zone is left to the Cloudflare
* API (returned as a typed error).
*
* Rules:
* - 1–63 characters
* - Lowercase letters, digits, and internal hyphens only
* - No leading or trailing hyphen
* - No dots — multi-label hostnames need a delegated subdomain zone or
*   Advanced Certificate Manager, which are out of scope for this
*   feature. Universal SSL only covers `<label>.<zone>`.
*
* Throws `SandboxSecurityError` on any violation. Designed to be called
* before any other tunnel work so callers see a fast, deterministic
* failure.
*/
var TUNNEL_NAME_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
function validateTunnelName(name) {
	if (typeof name !== "string") throw new SandboxSecurityError(`Tunnel name must be a string. Received: ${typeof name}`, "INVALID_TUNNEL_NAME");
	if (name.length === 0 || name.length > 63) throw new SandboxSecurityError(`Tunnel name '${name}' must be 1–63 characters long.`, "INVALID_TUNNEL_NAME_LENGTH");
	if (!TUNNEL_NAME_REGEX.test(name)) throw new SandboxSecurityError(`Tunnel name '${name}' is not a valid DNS label. Use lowercase letters, digits, and internal hyphens only (no dots, no leading/trailing hyphens).`, "INVALID_TUNNEL_NAME_FORMAT");
}
var CodeInterpreter = class {
	getInterpreterClient;
	contexts = /* @__PURE__ */ new Map();
	constructor(interpreterClient) {
		this.getInterpreterClient = typeof interpreterClient === "function" ? interpreterClient : () => interpreterClient;
	}
	/**
	* Create a new code execution context
	*/
	async createCodeContext(options = {}) {
		validateLanguage(options.language);
		const context = await this.getInterpreterClient().createCodeContext(options);
		this.contexts.set(context.id, context);
		return context;
	}
	/**
	* Run code with optional context
	*/
	async runCode(code, options = {}) {
		let context = options.context;
		if (!context) {
			const language = options.language || "python";
			context = await this.getOrCreateDefaultContext(language);
		}
		const execution = new Execution(code, context);
		await this.getInterpreterClient().runCodeStream(context.id, code, options.language, {
			onStdout: (output) => {
				execution.logs.stdout.push(output.text);
				if (options.onStdout) return options.onStdout(output);
			},
			onStderr: (output) => {
				execution.logs.stderr.push(output.text);
				if (options.onStderr) return options.onStderr(output);
			},
			onResult: async (result) => {
				execution.results.push(new ResultImpl(result));
				if (options.onResult) return options.onResult(result);
			},
			onError: (error) => {
				execution.error = error;
				if (options.onError) return options.onError(error);
			}
		});
		return execution;
	}
	/**
	* Run code and return a streaming response
	*/
	async runCodeStream(code, options = {}) {
		let context = options.context;
		if (!context) {
			const language = options.language || "python";
			context = await this.getOrCreateDefaultContext(language);
		}
		return this.getInterpreterClient().streamCode(context.id, code, options.language);
	}
	/**
	* List all code contexts
	*/
	async listCodeContexts() {
		const contexts = await this.getInterpreterClient().listCodeContexts();
		for (const context of contexts) this.contexts.set(context.id, context);
		return contexts;
	}
	/**
	* Delete a code context
	*/
	async deleteCodeContext(contextId) {
		await this.getInterpreterClient().deleteCodeContext(contextId);
		this.contexts.delete(contextId);
	}
	async getOrCreateDefaultContext(language) {
		for (const context of this.contexts.values()) if (context.language === language) return context;
		return this.createCodeContext({ language });
	}
};
/**
* Server-Sent Events (SSE) parser for streaming responses
* Converts ReadableStream<Uint8Array> to typed AsyncIterable<T>
*/
/**
* Parse a ReadableStream of SSE events into typed AsyncIterable
* @param stream - The ReadableStream from fetch response
* @param signal - Optional AbortSignal for cancellation
*/
async function* parseSSEStream(stream, signal) {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	let currentEvent = { data: [] };
	let isAborted = signal?.aborted ?? false;
	const emitEvent = (data) => {
		if (data === "[DONE]" || data.trim() === "") return;
		try {
			return JSON.parse(data);
		} catch {
			return;
		}
	};
	const onAbort = () => {
		isAborted = true;
		reader.cancel().catch(() => {});
	};
	if (signal && !signal.aborted) signal.addEventListener("abort", onAbort);
	try {
		while (true) {
			if (isAborted) throw new Error("Operation was aborted");
			const { done, value } = await reader.read();
			if (isAborted) throw new Error("Operation was aborted");
			if (done) break;
			buffer += decoder.decode(value, { stream: true });
			const parsed = parseSSEFrames(buffer, currentEvent);
			buffer = parsed.remaining;
			currentEvent = parsed.currentEvent;
			for (const frame of parsed.events) {
				const event = emitEvent(frame.data);
				if (event !== void 0) yield event;
			}
		}
		if (isAborted) throw new Error("Operation was aborted");
		const finalParsed = parseSSEFrames(`${buffer}\n\n`, currentEvent);
		for (const frame of finalParsed.events) {
			const event = emitEvent(frame.data);
			if (event !== void 0) yield event;
		}
	} finally {
		if (signal) signal.removeEventListener("abort", onAbort);
		try {
			await reader.cancel();
		} catch {}
		reader.releaseLock();
	}
}
/**
* Bucket mount and unmount error classes
*
* Validation errors (InvalidMountConfigError, MissingCredentialsError) are thrown
* before any container interaction. BucketUnmountError is thrown after a failed
* fusermount call inside the container.
*/
/**
* Base error for bucket mounting operations
*/
var BucketMountError = class extends Error {
	code;
	constructor(message, code = ErrorCode.BUCKET_MOUNT_ERROR) {
		super(message);
		this.name = "BucketMountError";
		this.code = code;
	}
};
/**
* Thrown when S3FS mount command fails
*/
var S3FSMountError = class extends BucketMountError {
	constructor(message) {
		super(message, ErrorCode.S3FS_MOUNT_ERROR);
		this.name = "S3FSMountError";
	}
};
/**
* Thrown when fusermount -u fails to unmount a FUSE filesystem
*/
var BucketUnmountError = class extends BucketMountError {
	constructor(message) {
		super(message, ErrorCode.BUCKET_UNMOUNT_ERROR);
		this.name = "BucketUnmountError";
	}
};
/**
* Thrown when no credentials found in environment
*/
var MissingCredentialsError = class extends BucketMountError {
	constructor(message) {
		super(message, ErrorCode.MISSING_CREDENTIALS);
		this.name = "MissingCredentialsError";
	}
};
/**
* Thrown when bucket name, mount path, or options are invalid
*/
var InvalidMountConfigError = class extends BucketMountError {
	constructor(message) {
		super(message, ErrorCode.INVALID_MOUNT_CONFIG);
		this.name = "InvalidMountConfigError";
	}
};
/**
* Detect credentials for bucket mounting from environment variables
* Priority order:
* 1. Explicit options.credentials
* 2. Standard AWS env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
* 3. Standard R2 env vars: R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY
* 4. Error: no credentials found
*
* @param options - Mount options
* @param envVars - Environment variables
* @returns Detected credentials
* @throws MissingCredentialsError if no credentials found
*/
function detectCredentials(options, envVars) {
	if (options.credentials) return options.credentials;
	const awsAccessKeyId = envVars.AWS_ACCESS_KEY_ID;
	const awsSecretAccessKey = envVars.AWS_SECRET_ACCESS_KEY;
	if (awsAccessKeyId && awsSecretAccessKey) return {
		accessKeyId: awsAccessKeyId,
		secretAccessKey: awsSecretAccessKey
	};
	/**
	* Priority 3: Standard R2 env vars
	*
	* AWS vars still take precedence over R2 vars in case both are set
	*/
	const r2AccessKeyId = envVars.R2_ACCESS_KEY_ID;
	const r2SecretAccessKey = envVars.R2_SECRET_ACCESS_KEY;
	if (r2AccessKeyId && r2SecretAccessKey) return {
		accessKeyId: r2AccessKeyId,
		secretAccessKey: r2SecretAccessKey
	};
	throw new MissingCredentialsError("No credentials found. Set R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables, or pass explicit credentials in options.");
}
/**
* Detect provider from endpoint URL using pattern matching
*/
function detectProviderFromUrl(endpoint) {
	try {
		const hostname = new URL(endpoint).hostname.toLowerCase();
		if (hostname.endsWith(".r2.cloudflarestorage.com")) return "r2";
		if (hostname.endsWith(".amazonaws.com") || hostname === "s3.amazonaws.com") return "s3";
		if (hostname === "storage.googleapis.com") return "gcs";
		return null;
	} catch {
		return null;
	}
}
/**
* Get s3fs flags for a given provider
*
* Based on s3fs-fuse wiki recommendations:
* https://github.com/s3fs-fuse/s3fs-fuse/wiki/Non-Amazon-S3
*/
function getProviderFlags(provider) {
	if (!provider) return ["use_path_request_style"];
	switch (provider) {
		case "r2": return ["nomixupload"];
		case "s3": return [];
		case "gcs": return [];
		default: return ["use_path_request_style"];
	}
}
/**
* Resolve s3fs options by combining provider defaults with user overrides
*/
function resolveS3fsOptions(provider, userOptions) {
	const providerFlags = getProviderFlags(provider);
	if (!userOptions || userOptions.length === 0) return providerFlags;
	const allFlags = [...providerFlags, ...userOptions];
	const flagMap = /* @__PURE__ */ new Map();
	for (const flag of allFlags) {
		const [flagName] = flag.split("=");
		flagMap.set(flagName, flag);
	}
	return Array.from(flagMap.values());
}
/**
* Type guard for R2Bucket binding.
* Checks for the minimal R2Bucket interface methods we use.
*/
function isR2Bucket(value) {
	return typeof value === "object" && value !== null && "put" in value && typeof value.put === "function" && "get" in value && typeof value.get === "function" && "head" in value && typeof value.head === "function" && "delete" in value && typeof value.delete === "function" && "list" in value && typeof value.list === "function";
}
function validatePrefix(prefix) {
	if (!prefix.startsWith("/")) throw new InvalidMountConfigError(`Prefix must start with '/': "${prefix}"`);
}
function validateBucketName(bucket, mountPath) {
	if (bucket.includes(":")) {
		const [bucketName, prefixPart] = bucket.split(":");
		throw new InvalidMountConfigError(`Bucket name cannot contain ':'. To mount a prefix, use the 'prefix' option:\n  mountBucket('${bucketName}', '${mountPath}', { ...options, prefix: '${prefixPart}' })`);
	}
	if (!/^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$/.test(bucket)) throw new InvalidMountConfigError(`Invalid bucket name: "${bucket}". Bucket names must be 3-63 characters, lowercase alphanumeric, dots, or hyphens, and cannot start/end with dots or hyphens.`);
}
function validateBucketBindingName(bucketBinding, mountPath) {
	if (bucketBinding.includes(":")) {
		const [bucketName, prefixPart] = bucketBinding.split(":");
		throw new InvalidMountConfigError(`Bucket name cannot contain ':'. To mount a prefix, use the 'prefix' option:\n  mountBucket('${bucketName}', '${mountPath}', { ...options, prefix: '${prefixPart}' })`);
	}
	if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(bucketBinding)) throw new InvalidMountConfigError(`Invalid R2 binding name: "${bucketBinding}". Binding names must start with a letter or underscore and contain only letters, numbers, or underscores.`);
}
/**
* Builds the s3fs source string from bucket name and optional prefix.
* Format: "bucket" or "bucket:/prefix/" for subdirectory mounts.
*
* @param bucket - The bucket name
* @param prefix - Optional prefix/subdirectory path
* @returns The s3fs source string
*/
function buildS3fsSource(bucket, prefix) {
	return prefix ? `${bucket}:${prefix}` : bucket;
}
var DEFAULT_POLL_INTERVAL_MS = 1e3;
var DEFAULT_ECHO_SUPPRESS_TTL_MS = 2e3;
var MAX_BACKOFF_MS = 3e4;
var SYNC_CONCURRENCY = 5;
var STREAM_TO_CONTAINER_THRESHOLD_BYTES = 4194304;
var UPLOAD_DEBOUNCE_MS = 1500;
/** Watch rejections that a retry with the same request cannot fix. */
var PERMANENT_WATCH_ERRORS = /* @__PURE__ */ new Set([ErrorCode.PERMISSION_DENIED, ErrorCode.VALIDATION_FAILED]);
/**
* Manages bidirectional sync between an R2 binding and a container directory.
*
* R2 -> Container: polls bucket.list() to detect changes, then transfers diffs.
* Container -> R2: uses inotifywait via the watch API to detect file changes.
*/
var LocalMountSyncManager = class {
	bucket;
	mountPath;
	prefix;
	readOnly;
	client;
	sessionId;
	logger;
	pollIntervalMs;
	echoSuppressTtlMs;
	snapshot = /* @__PURE__ */ new Map();
	echoSuppressTimers = /* @__PURE__ */ new Map();
	uploadTimers = /* @__PURE__ */ new Map();
	containerToR2Queue = Promise.resolve();
	pollTimer = null;
	watchReconnectTimer = null;
	watchAbortController = null;
	running = false;
	consecutivePollFailures = 0;
	consecutiveWatchFailures = 0;
	constructor(options) {
		this.bucket = options.bucket;
		this.mountPath = options.mountPath;
		if (options.prefix !== void 0) validatePrefix(options.prefix);
		this.prefix = options.prefix?.replace(/^\//, "") || void 0;
		this.readOnly = options.readOnly;
		this.client = options.client;
		this.sessionId = options.sessionId;
		this.logger = options.logger.child({ operation: "local-mount-sync" });
		this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
		this.echoSuppressTtlMs = options.echoSuppressTtlMs ?? DEFAULT_ECHO_SUPPRESS_TTL_MS;
	}
	/**
	* Start bidirectional sync. Performs initial full sync, then starts
	* the R2 poll loop and (if not readOnly) the container watch loop.
	*/
	async start() {
		this.running = true;
		await this.client.files.mkdir(this.mountPath, this.sessionId, { recursive: true });
		await this.fullSyncR2ToContainer();
		this.schedulePoll();
		if (!this.readOnly) this.startContainerWatch();
		this.logger.info("Local mount sync started", {
			mountPath: this.mountPath,
			prefix: this.prefix,
			readOnly: this.readOnly,
			pollIntervalMs: this.pollIntervalMs
		});
	}
	/**
	* Stop all sync activity and clean up resources.
	*/
	async stop() {
		this.running = false;
		if (this.pollTimer) {
			clearTimeout(this.pollTimer);
			this.pollTimer = null;
		}
		if (this.watchReconnectTimer) {
			clearTimeout(this.watchReconnectTimer);
			this.watchReconnectTimer = null;
		}
		if (this.watchAbortController) {
			this.watchAbortController.abort();
			this.watchAbortController = null;
		}
		for (const timer of this.uploadTimers.values()) clearTimeout(timer);
		this.uploadTimers.clear();
		for (const timer of this.echoSuppressTimers.values()) clearTimeout(timer);
		this.echoSuppressTimers.clear();
		this.snapshot.clear();
		this.logger.info("Local mount sync stopped", { mountPath: this.mountPath });
	}
	async fullSyncR2ToContainer() {
		const objects = await this.listAllR2Objects();
		const newSnapshot = /* @__PURE__ */ new Map();
		for (let i = 0; i < objects.length; i += SYNC_CONCURRENCY) {
			const batch = objects.slice(i, i + SYNC_CONCURRENCY);
			await Promise.all(batch.map(async (obj) => {
				const containerPath = this.r2KeyToContainerPath(obj.key);
				newSnapshot.set(obj.key, {
					etag: obj.etag,
					size: obj.size
				});
				await this.ensureParentDir(containerPath);
				await this.transferR2ObjectToContainer(obj.key, containerPath);
			}));
		}
		this.snapshot = newSnapshot;
		this.logger.debug("Initial R2 -> Container sync complete", { objectCount: objects.length });
	}
	schedulePoll() {
		if (!this.running) return;
		const backoffMs = this.consecutivePollFailures > 0 ? Math.min(this.pollIntervalMs * 2 ** this.consecutivePollFailures, MAX_BACKOFF_MS) : this.pollIntervalMs;
		this.pollTimer = setTimeout(async () => {
			try {
				await this.pollR2ForChanges();
				this.consecutivePollFailures = 0;
			} catch (error) {
				this.consecutivePollFailures++;
				this.logger.error("R2 poll cycle failed", error instanceof Error ? error : new Error(String(error)));
			}
			this.schedulePoll();
		}, backoffMs);
	}
	async pollR2ForChanges() {
		const objects = await this.listAllR2Objects();
		const newSnapshot = /* @__PURE__ */ new Map();
		const changed = [];
		for (const obj of objects) {
			newSnapshot.set(obj.key, {
				etag: obj.etag,
				size: obj.size
			});
			const existing = this.snapshot.get(obj.key);
			if (!existing || existing.etag !== obj.etag) changed.push({
				key: obj.key,
				action: existing ? "modified" : "created"
			});
		}
		for (let i = 0; i < changed.length; i += SYNC_CONCURRENCY) {
			const batch = changed.slice(i, i + SYNC_CONCURRENCY);
			await Promise.all(batch.map(async ({ key, action }) => {
				try {
					const containerPath = this.r2KeyToContainerPath(key);
					await this.ensureParentDir(containerPath);
					this.suppressEcho(containerPath);
					await this.transferR2ObjectToContainer(key, containerPath);
					this.suppressEcho(containerPath);
					this.logger.debug("R2 -> Container: synced object", {
						key,
						action
					});
				} catch (error) {
					this.logger.error(`R2 -> Container: failed to sync object ${key}`, error instanceof Error ? error : new Error(String(error)));
				}
			}));
		}
		for (const [key] of this.snapshot) if (!newSnapshot.has(key)) {
			const containerPath = this.r2KeyToContainerPath(key);
			this.suppressEcho(containerPath);
			try {
				await this.client.files.deleteFile(containerPath, this.sessionId);
				this.logger.debug("R2 -> Container: deleted file", { key });
			} catch (error) {
				this.logger.error("R2 -> Container: failed to delete", error instanceof Error ? error : new Error(String(error)));
			}
		}
		this.snapshot = newSnapshot;
	}
	async listAllR2Objects() {
		const results = [];
		let cursor;
		do {
			const listResult = await this.bucket.list({
				...this.prefix && { prefix: this.prefix },
				...cursor && { cursor }
			});
			for (const obj of listResult.objects) results.push({
				key: obj.key,
				etag: obj.etag,
				size: obj.size
			});
			cursor = listResult.truncated ? listResult.cursor : void 0;
		} while (cursor);
		return results;
	}
	async transferR2ObjectToContainer(key, containerPath) {
		const obj = await this.bucket.get(key);
		if (!obj) return;
		if (obj.size > STREAM_TO_CONTAINER_THRESHOLD_BYTES && this.client.getTransportMode() === "rpc") {
			try {
				await this.client.files.writeFileStream(containerPath, obj.body, this.sessionId);
			} catch (error) {
				await obj.body.cancel().catch(() => {});
				throw error;
			}
			return;
		}
		const arrayBuffer = await obj.arrayBuffer();
		const base64 = uint8ArrayToBase64(new Uint8Array(arrayBuffer));
		await this.client.files.writeFile(containerPath, base64, this.sessionId, { encoding: "base64" });
	}
	async ensureParentDir(containerPath) {
		const parentDir = containerPath.substring(0, containerPath.lastIndexOf("/"));
		if (parentDir && parentDir !== this.mountPath) await this.client.files.mkdir(parentDir, this.sessionId, { recursive: true });
	}
	startContainerWatch() {
		this.watchAbortController = new AbortController();
		this.runWatchWithRetry();
	}
	runWatchWithRetry() {
		if (!this.running) return;
		this.runContainerWatchLoop().then(() => {
			this.consecutiveWatchFailures = 0;
			this.scheduleWatchReconnect();
		}).catch((error) => {
			if (!this.running) return;
			const err = error instanceof Error ? error : new Error(String(error));
			if (PERMANENT_WATCH_ERRORS.has(Reflect.get(err, "code"))) {
				this.logger.error("Container rejected the mount watch; changes made in the container will not sync to R2. Update the container image to match the SDK version.", err, { mountPath: this.mountPath });
				return;
			}
			this.consecutiveWatchFailures++;
			this.logger.error("Container watch loop failed", err);
			this.scheduleWatchReconnect();
		});
	}
	scheduleWatchReconnect() {
		if (!this.running) return;
		const backoffMs = this.consecutiveWatchFailures > 0 ? Math.min(this.pollIntervalMs * 2 ** this.consecutiveWatchFailures, MAX_BACKOFF_MS) : this.pollIntervalMs;
		this.logger.debug("Reconnecting container watch", {
			backoffMs,
			failures: this.consecutiveWatchFailures
		});
		this.watchReconnectTimer = setTimeout(() => {
			this.watchReconnectTimer = null;
			if (!this.running) return;
			this.watchAbortController = new AbortController();
			this.runWatchWithRetry();
		}, backoffMs);
	}
	async runContainerWatchLoop() {
		const stream = await this.client.watch.watch({
			path: this.mountPath,
			recursive: true,
			sessionId: this.sessionId
		});
		for await (const event of parseSSEStream(stream, this.watchAbortController?.signal)) {
			if (!this.running) break;
			this.consecutiveWatchFailures = 0;
			if (event.type !== "event") continue;
			if (event.isDirectory) continue;
			const containerPath = event.path;
			if (this.echoSuppressTimers.has(containerPath)) continue;
			const r2Key = this.containerPathToR2Key(containerPath);
			if (!r2Key) continue;
			switch (event.eventType) {
				case "create":
				case "modify":
				case "move_to":
					this.scheduleUpload(containerPath, r2Key);
					break;
				case "delete":
				case "move_from":
					this.cancelScheduledUpload(containerPath);
					this.enqueueContainerToR2(containerPath, async () => {
						await this.bucket.delete(r2Key);
						this.snapshot.delete(r2Key);
						this.logger.debug("Container -> R2: deleted object", {
							path: containerPath,
							key: r2Key
						});
					});
			}
		}
	}
	/**
	* Upload a changed file once its burst of watch events settles. Each new
	* event for the path restarts the wait.
	*/
	scheduleUpload(containerPath, r2Key) {
		this.cancelScheduledUpload(containerPath);
		const timer = setTimeout(() => {
			this.uploadTimers.delete(containerPath);
			this.enqueueContainerToR2(containerPath, async () => {
				await this.uploadFileToR2(containerPath, r2Key);
				this.logger.debug("Container -> R2: synced file", {
					path: containerPath,
					key: r2Key
				});
			});
		}, UPLOAD_DEBOUNCE_MS);
		this.uploadTimers.set(containerPath, timer);
	}
	cancelScheduledUpload(containerPath) {
		const timer = this.uploadTimers.get(containerPath);
		if (timer !== void 0) {
			clearTimeout(timer);
			this.uploadTimers.delete(containerPath);
		}
	}
	enqueueContainerToR2(containerPath, operation) {
		this.containerToR2Queue = this.containerToR2Queue.then(async () => {
			if (!this.running) return;
			try {
				await operation();
			} catch (error) {
				this.logger.error(`Container -> R2 sync failed for ${containerPath}`, error instanceof Error ? error : new Error(String(error)));
			}
		});
	}
	/**
	* Stream a container file into R2, then update the local snapshot so the
	* next poll cycle doesn't echo the write back.
	*/
	async uploadFileToR2(containerPath, r2Key) {
		const file = await openFileStream(await this.client.files.readFileStream(containerPath, this.sessionId, { encoding: "base64" }));
		if (file.metadata.isBinary && file.metadata.encoding === "base64") await this.putFileStream(r2Key, file);
		else {
			await file.cancel();
			const result = await this.client.files.readFile(containerPath, this.sessionId, { encoding: "base64" });
			await this.bucket.put(r2Key, base64ToUint8Array(result.content));
		}
		const head = await this.bucket.head(r2Key);
		if (head) this.snapshot.set(r2Key, {
			etag: head.etag,
			size: head.size
		});
	}
	async putFileStream(r2Key, file) {
		const body = new ReadableStream({
			async pull(controller) {
				const next = await file.chunks.next();
				if (next.done) controller.close();
				else if (typeof next.value === "string") controller.error(/* @__PURE__ */ new Error("Expected binary file chunks"));
				else controller.enqueue(next.value);
			},
			cancel: () => file.cancel()
		});
		const sized = new FixedLengthStream(file.metadata.size);
		const pipeAbort = new AbortController();
		body.pipeTo(sized.writable, { signal: pipeAbort.signal }).catch(() => {});
		try {
			await this.bucket.put(r2Key, sized.readable);
		} catch (error) {
			pipeAbort.abort(error);
			throw error;
		}
	}
	suppressEcho(containerPath) {
		clearTimeout(this.echoSuppressTimers.get(containerPath));
		this.echoSuppressTimers.set(containerPath, setTimeout(() => {
			this.echoSuppressTimers.delete(containerPath);
		}, this.echoSuppressTtlMs));
	}
	r2KeyToContainerPath(key) {
		let relativePath = key;
		if (this.prefix) relativePath = key.startsWith(this.prefix) ? key.slice(this.prefix.length) : key;
		return path.join(this.mountPath, relativePath);
	}
	containerPathToR2Key(containerPath) {
		const resolved = path.resolve(containerPath);
		const mount = path.resolve(this.mountPath);
		if (!resolved.startsWith(mount)) return null;
		const relativePath = path.relative(mount, resolved);
		if (!relativePath || relativePath.startsWith("..")) return null;
		return this.prefix ? path.join(this.prefix, relativePath) : relativePath;
	}
};
function uint8ArrayToBase64(bytes) {
	return Buffer.from(bytes).toString("base64");
}
function base64ToUint8Array(base64) {
	return new Uint8Array(Buffer.from(base64, "base64"));
}
async function forwardPreviewRequest(tcpPort, request, lifecycle) {
	const containerURL = request.url.replace("https:", "http:");
	const settleForward = lifecycle.beginForward();
	try {
		const response = await tcpPort.fetch(containerURL, request);
		if (response.webSocket !== null) return {
			status: "response",
			response: bridgePreviewWebSocket(response, lifecycle, settleForward)
		};
		if (response.body !== null) {
			const { readable, writable } = new TransformStream();
			response.body.pipeTo(writable).finally(settleForward).catch(() => {});
			return {
				status: "response",
				response: new Response(readable, response)
			};
		}
		settleForward();
		return {
			status: "response",
			response
		};
	} catch (error) {
		settleForward();
		if (isDurableObjectReset(error)) throw error;
		if (error instanceof Error && error.message.includes("Network connection lost.")) return { status: "network-lost" };
		return {
			status: "failed",
			error
		};
	}
}
function bridgePreviewWebSocket(response, lifecycle, settleForward) {
	const containerWebSocket = response.webSocket;
	if (containerWebSocket === null) {
		settleForward();
		return response;
	}
	const [client, server] = Object.values(new WebSocketPair());
	let settled = false;
	const settle = () => {
		if (!settled) {
			settled = true;
			settleForward();
		}
	};
	containerWebSocket.accept();
	server.accept();
	server.addEventListener("message", async (event) => {
		lifecycle.renewActivity();
		try {
			const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
			containerWebSocket.send(data);
		} catch {
			server.close(1011, "Failed to forward message to container");
		}
	});
	containerWebSocket.addEventListener("message", async (event) => {
		lifecycle.renewActivity();
		try {
			const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
			server.send(data);
		} catch {
			containerWebSocket.close(1011, "Failed to forward message to client");
		}
	});
	server.addEventListener("close", (event) => {
		settle();
		const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
		containerWebSocket.close(code, event.reason);
	});
	containerWebSocket.addEventListener("close", (event) => {
		settle();
		const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
		server.close(code, event.reason);
	});
	server.addEventListener("error", () => {
		settle();
		containerWebSocket.close(1011, "Client WebSocket error");
	});
	containerWebSocket.addEventListener("error", () => {
		settle();
		server.close(1011, "Container WebSocket error");
	});
	return new Response(null, {
		status: response.status,
		webSocket: client,
		headers: response.headers
	});
}
/** @internal */
var PREVIEW_PROXY_HEADER = "x-sandbox-preview-proxy";
/** @internal */
var PREVIEW_PROXY_PORT_HEADER = "x-sandbox-preview-port";
/** @internal */
var PREVIEW_PROXY_TOKEN_HEADER = "x-sandbox-preview-token";
/** @internal */
var PREVIEW_PROXY_SANDBOX_ID_HEADER = "x-sandbox-preview-sandbox-id";
/** @internal */
var PREVIEW_PROXY_HEADERS = [
	PREVIEW_PROXY_HEADER,
	PREVIEW_PROXY_PORT_HEADER,
	PREVIEW_PROXY_TOKEN_HEADER,
	PREVIEW_PROXY_SANDBOX_ID_HEADER
];
function isLocalhostPattern(hostname) {
	if (hostname.startsWith("[")) {
		if (hostname.includes("]:")) return hostname.substring(0, hostname.indexOf("]:") + 1) === "[::1]";
		return hostname === "[::1]";
	}
	if (hostname === "::1") return true;
	const hostPart = hostname.split(":")[0];
	return hostPart === "localhost" || hostPart === "127.0.0.1" || hostPart === "0.0.0.0";
}
async function proxyTerminal(stub, sessionId, request, options) {
	if (!sessionId || typeof sessionId !== "string") throw new Error("sessionId is required for terminal access");
	if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") throw new Error("terminal() requires a WebSocket upgrade request");
	const params = new URLSearchParams({ sessionId });
	if (options?.cols) params.set("cols", String(options.cols));
	if (options?.rows) params.set("rows", String(options.rows));
	if (options?.shell) params.set("shell", options.shell);
	const ptyUrl = `http://localhost/ws/pty?${params}`;
	const ptyRequest = new Request(ptyUrl, request);
	return stub.fetch(switchPort(ptyRequest, 3e3));
}
var SessionInitInvalidatedError = class extends Error {
	constructor() {
		super("Default session initialization was invalidated by a container stop");
		this.name = "SessionInitInvalidatedError";
	}
};
function isSessionInitInvalidated(error) {
	return error instanceof SessionInitInvalidatedError;
}
var XML_NS = "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
var XML_DECL = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
function escapeXML(s) {
	return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function xmlResponse(body, status = 200) {
	return new Response(XML_DECL + body, {
		status,
		headers: { "Content-Type": "application/xml" }
	});
}
function normalizeObjectKey(value) {
	return value.replace(/^\/+/, "");
}
function decodeObjectKey(value) {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}
function trimTrailingSlashes(s) {
	let end = s.length;
	while (end > 0 && s[end - 1] === "/") end--;
	return s.slice(0, end);
}
function normalizeMountPrefix(prefix) {
	if (!prefix) return void 0;
	return trimTrailingSlashes(normalizeObjectKey(prefix)) || void 0;
}
function parsePath(pathname) {
	const stripped = pathname.startsWith("/") ? pathname.slice(1) : pathname;
	if (!stripped) return null;
	const slash = stripped.indexOf("/");
	if (slash === -1) return {
		bucket: stripped,
		key: ""
	};
	return {
		bucket: stripped.slice(0, slash),
		key: normalizeObjectKey(stripped.slice(slash + 1))
	};
}
function resolveR2Bucket(env$1, name) {
	if (typeof env$1 !== "object" || env$1 === null) return null;
	const val = env$1[name];
	return isR2Bucket(val) ? val : null;
}
function parseRange(header) {
	if (!header) return void 0;
	const m = header.match(/^bytes=(\d*)-(\d*)$/);
	if (!m) return void 0;
	const start = m[1] ? parseInt(m[1], 10) : void 0;
	const end = m[2] ? parseInt(m[2], 10) : void 0;
	if (start === void 0 && end !== void 0) return { suffix: end };
	if (start !== void 0 && end !== void 0) return {
		offset: start,
		length: end - start + 1
	};
	if (start !== void 0) return { offset: start };
}
function buildListObjectsV2Xml(bucketName, prefix, delimiter, maxKeys, result) {
	const contents = result.objects.map((obj) => `<Contents><Key>${escapeXML(obj.key)}</Key><LastModified>${obj.uploaded.toISOString()}</LastModified><ETag>${escapeXML(obj.httpEtag)}</ETag><Size>${obj.size}</Size><StorageClass>STANDARD</StorageClass></Contents>`).join("");
	const commonPrefixes = result.delimitedPrefixes.map((p) => `<CommonPrefixes><Prefix>${escapeXML(p)}</Prefix></CommonPrefixes>`).join("");
	const nextToken = result.truncated && result.cursor ? `<NextContinuationToken>${escapeXML(result.cursor)}</NextContinuationToken>` : "";
	const keyCount = result.objects.length + result.delimitedPrefixes.length;
	return `<ListBucketResult ${XML_NS}><Name>${escapeXML(bucketName)}</Name><Prefix>${escapeXML(prefix)}</Prefix><KeyCount>${keyCount}</KeyCount><MaxKeys>${maxKeys}</MaxKeys>` + (delimiter ? `<Delimiter>${escapeXML(delimiter)}</Delimiter>` : "") + `<IsTruncated>${result.truncated}</IsTruncated>` + nextToken + contents + commonPrefixes + `</ListBucketResult>`;
}
function buildLocationXml() {
	return `<LocationConstraint ${XML_NS}/>`;
}
function buildInitiateMultipartUploadXml(bucketName, key, uploadId) {
	return `<InitiateMultipartUploadResult ${XML_NS}><Bucket>${escapeXML(bucketName)}</Bucket><Key>${escapeXML(key)}</Key><UploadId>${escapeXML(uploadId)}</UploadId></InitiateMultipartUploadResult>`;
}
function buildCompleteMultipartUploadXml(bucketName, key, etag) {
	return `<CompleteMultipartUploadResult ${XML_NS}><Location>http://r2.internal/${escapeXML(bucketName)}/${escapeXML(key)}</Location><Bucket>${escapeXML(bucketName)}</Bucket><Key>${escapeXML(key)}</Key><ETag>${escapeXML(etag)}</ETag></CompleteMultipartUploadResult>`;
}
function buildCopyObjectXml(etag, uploaded) {
	return `<CopyObjectResult ${XML_NS}><LastModified>${uploaded.toISOString()}</LastModified><ETag>${escapeXML(etag)}</ETag></CopyObjectResult>`;
}
function extractXmlTagContent(segment, tagName) {
	const openTag = `<${tagName}>`;
	const closeTag = `</${tagName}>`;
	const start = segment.indexOf(openTag);
	if (start === -1) return null;
	const contentStart = start + openTag.length;
	const end = segment.indexOf(closeTag, contentStart);
	if (end === -1) return null;
	return segment.slice(contentStart, end);
}
function parseCompleteMultipartUploadBody(body) {
	const parts = [];
	let pos = 0;
	while (pos < body.length) {
		const start = body.indexOf("<Part>", pos);
		if (start === -1) break;
		const end = body.indexOf("</Part>", start + 6);
		if (end === -1) break;
		const segment = body.slice(start, end + 7);
		pos = end + 7;
		const partNumberText = extractXmlTagContent(segment, "PartNumber");
		const etagText = extractXmlTagContent(segment, "ETag");
		const partNumber = partNumberText ? parseInt(partNumberText, 10) : NaN;
		if (Number.isFinite(partNumber) && etagText) parts.push({
			partNumber,
			etag: etagText.replace(/^"|"$/g, "")
		});
	}
	return parts;
}
function buildResponseHeaders(obj) {
	const headers = new Headers();
	headers.set("ETag", obj.httpEtag);
	headers.set("Content-Length", String(obj.size));
	headers.set("Last-Modified", obj.uploaded.toUTCString());
	headers.set("Accept-Ranges", "bytes");
	if (obj.httpMetadata?.contentType) headers.set("Content-Type", obj.httpMetadata.contentType);
	if (obj.httpMetadata?.contentDisposition) headers.set("Content-Disposition", obj.httpMetadata.contentDisposition);
	if (obj.httpMetadata?.contentEncoding) headers.set("Content-Encoding", obj.httpMetadata.contentEncoding);
	if (obj.httpMetadata?.contentLanguage) headers.set("Content-Language", obj.httpMetadata.contentLanguage);
	if (obj.httpMetadata?.cacheControl) headers.set("Cache-Control", obj.httpMetadata.cacheControl);
	return headers;
}
function buildContentRange(range, totalSize) {
	if ("suffix" in range) return `bytes ${Math.max(0, totalSize - range.suffix)}-${totalSize - 1}/${totalSize}`;
	const start = range.offset ?? 0;
	return `bytes ${start}-${range.length !== void 0 ? start + range.length - 1 : totalSize - 1}/${totalSize}`;
}
function getRangeContentLength(range, totalSize) {
	if ("suffix" in range) return Math.min(range.suffix, totalSize);
	const start = range.offset ?? 0;
	if (start >= totalSize) return 0;
	const requestedLength = range.length !== void 0 ? range.length : totalSize - start;
	return Math.min(requestedLength, totalSize - start);
}
function extractHttpMetadata(request) {
	const meta = {};
	const ct = request.headers.get("Content-Type");
	if (ct) meta.contentType = ct;
	const cd = request.headers.get("Content-Disposition");
	if (cd) meta.contentDisposition = cd;
	const ce = request.headers.get("Content-Encoding");
	if (ce) meta.contentEncoding = ce;
	const cl = request.headers.get("Content-Language");
	if (cl) meta.contentLanguage = cl;
	const cc = request.headers.get("Cache-Control");
	if (cc) meta.cacheControl = cc;
	return meta;
}
function parseCopySource(header) {
	const sourcePath = header.split("?")[0] ?? "";
	if (!sourcePath) return null;
	const decoded = decodeURIComponent(sourcePath);
	const parsed = parsePath(decoded.startsWith("/") ? decoded : `/${decoded}`);
	return parsed ? {
		bucket: parsed.bucket,
		key: normalizeObjectKey(parsed.key)
	} : null;
}
function normalizeStorageClass(storageClass) {
	if (storageClass === "Standard" || storageClass === "InfrequentAccess") return storageClass;
}
async function putRequestBody(r2, key, request, options) {
	const contentLength = request.headers.get("Content-Length");
	const length = contentLength ? Number.parseInt(contentLength, 10) : NaN;
	if (!Number.isFinite(length) || length < 0) return new Response("Bad Request: missing or invalid Content-Length", { status: 400 });
	if (length === 0) return r2.put(key, /* @__PURE__ */ new Uint8Array(0), options);
	if (!request.body) return new Response("Bad Request: missing request body", { status: 400 });
	const { readable, writable } = new FixedLengthStream(length);
	const pipe = request.body.pipeTo(writable);
	const result = await r2.put(key, readable, options);
	await pipe;
	return result;
}
async function handleListObjects(r2, bucketName, url, mountPrefix) {
	const queryPrefix = normalizeObjectKey(url.searchParams.get("prefix") ?? "");
	const delimiter = url.searchParams.get("delimiter") ?? "";
	const maxKeys = Math.min(parseInt(url.searchParams.get("max-keys") ?? "1000", 10) || 1e3, 1e3);
	const continuationToken = url.searchParams.get("continuation-token") ?? void 0;
	const listOpts = {
		prefix: (mountPrefix ? `${mountPrefix}/${queryPrefix}` : queryPrefix) || void 0,
		delimiter: delimiter || void 0,
		limit: maxKeys,
		cursor: continuationToken
	};
	const result = await r2.list(listOpts);
	const stripKey = mountPrefix ? (k) => k.startsWith(`${mountPrefix}/`) ? k.slice(mountPrefix.length + 1) : k : (k) => k;
	return xmlResponse(buildListObjectsV2Xml(bucketName, queryPrefix, delimiter, maxKeys, {
		objects: result.objects.map((obj) => ({
			key: stripKey(obj.key),
			uploaded: obj.uploaded,
			httpEtag: obj.httpEtag,
			size: obj.size
		})),
		delimitedPrefixes: result.delimitedPrefixes.map(stripKey),
		truncated: result.truncated,
		cursor: result.truncated ? result.cursor : void 0
	}));
}
async function handleHeadObject(r2, key) {
	const obj = await r2.head(key);
	if (!obj) return new Response(null, { status: 404 });
	return new Response(null, {
		status: 200,
		headers: buildResponseHeaders(obj)
	});
}
async function handleGetObject(r2, key, request) {
	const range = parseRange(request.headers.get("Range"));
	if (!range) {
		const obj = await r2.get(key);
		if (!obj) return new Response(null, { status: 404 });
		return new Response(obj.body, {
			status: 200,
			headers: buildResponseHeaders(obj)
		});
	}
	const [headObj, rangeObj] = await Promise.all([r2.head(key), r2.get(key, { range })]);
	if (!headObj || !rangeObj) return new Response(null, { status: 404 });
	const headers = buildResponseHeaders(rangeObj);
	headers.set("Content-Range", buildContentRange(range, headObj.size));
	headers.set("Content-Length", String(getRangeContentLength(range, headObj.size)));
	return new Response(rangeObj.body, {
		status: 206,
		headers
	});
}
async function handlePutObject(r2, bucketName, key, request, env$1, buckets) {
	const copySourceHeader = request.headers.get("x-amz-copy-source");
	if (copySourceHeader) {
		const copySource = parseCopySource(copySourceHeader);
		if (!copySource || !copySource.key) return new Response("Bad Request: invalid x-amz-copy-source", { status: 400 });
		if (!Object.hasOwn(buckets, copySource.bucket)) return new Response(`Access to R2 bucket "${copySource.bucket}" is not permitted. Call mountBucket() with this bucket before accessing it.`, { status: 403 });
		const sourceParams = buckets[copySource.bucket];
		const sourceBucket = copySource.bucket === bucketName ? r2 : resolveR2Bucket(env$1, copySource.bucket);
		if (!sourceBucket) return new Response(`R2 binding "${copySource.bucket}" not found in Worker env. Ensure the binding name matches the bucket name passed to mountBucket().`, { status: 500 });
		const sourcePrefix = normalizeMountPrefix(sourceParams.prefix);
		const sourceKey = sourcePrefix ? `${sourcePrefix}/${copySource.key}` : copySource.key;
		const sourceObject = await sourceBucket.get(sourceKey);
		if (!sourceObject) return new Response(null, { status: 404 });
		const httpMetadata = request.headers.get("x-amz-metadata-directive")?.toUpperCase() === "REPLACE" ? extractHttpMetadata(request) : sourceObject.httpMetadata;
		const result$1 = await r2.put(key, sourceObject.body, {
			httpMetadata,
			customMetadata: sourceObject.customMetadata,
			storageClass: normalizeStorageClass(sourceObject.storageClass)
		});
		return xmlResponse(buildCopyObjectXml(result$1.httpEtag, result$1.uploaded));
	}
	const result = await putRequestBody(r2, key, request, { httpMetadata: extractHttpMetadata(request) });
	if (result instanceof Response) return result;
	const headers = new Headers();
	headers.set("ETag", result.httpEtag);
	return new Response(null, {
		status: 200,
		headers
	});
}
async function handleDeleteObject(r2, key) {
	await r2.delete(key);
	return new Response(null, { status: 204 });
}
async function handleCreateMultipartUpload(r2, bucketName, key, request) {
	const httpMetadata = extractHttpMetadata(request);
	return xmlResponse(buildInitiateMultipartUploadXml(bucketName, key, (await r2.createMultipartUpload(key, { httpMetadata })).uploadId));
}
async function handleUploadPart(r2, key, url, request) {
	const uploadId = url.searchParams.get("uploadId") ?? "";
	const partNumber = parseInt(url.searchParams.get("partNumber") ?? "0", 10);
	if (!uploadId || !partNumber) return new Response("Bad Request: missing uploadId or partNumber", { status: 400 });
	if (!request.body) return new Response("Bad Request: missing request body", { status: 400 });
	const contentLength = request.headers.get("Content-Length");
	const partLength = contentLength ? Number.parseInt(contentLength, 10) : NaN;
	if (!Number.isFinite(partLength) || partLength < 0) return new Response("Bad Request: missing or invalid Content-Length", { status: 400 });
	const upload = r2.resumeMultipartUpload(key, uploadId);
	let part;
	if (partLength === 0) part = await upload.uploadPart(partNumber, /* @__PURE__ */ new Uint8Array(0));
	else {
		const { readable, writable } = new FixedLengthStream(partLength);
		const pipe = request.body.pipeTo(writable);
		part = await upload.uploadPart(partNumber, readable);
		await pipe;
	}
	const headers = new Headers();
	headers.set("ETag", `"${part.etag}"`);
	return new Response(null, {
		status: 200,
		headers
	});
}
async function handleCompleteMultipartUpload(r2, bucketName, key, url, request) {
	const uploadId = url.searchParams.get("uploadId") ?? "";
	if (!uploadId) return new Response("Bad Request: missing uploadId", { status: 400 });
	const r2Parts = parseCompleteMultipartUploadBody(await request.text()).map((p) => ({
		partNumber: p.partNumber,
		etag: p.etag
	}));
	return xmlResponse(buildCompleteMultipartUploadXml(bucketName, key, (await r2.resumeMultipartUpload(key, uploadId).complete(r2Parts)).httpEtag));
}
async function handleAbortMultipartUpload(r2, key, url) {
	const uploadId = url.searchParams.get("uploadId") ?? "";
	if (!uploadId) return new Response("Bad Request: missing uploadId", { status: 400 });
	await r2.resumeMultipartUpload(key, uploadId).abort();
	return new Response(null, { status: 204 });
}
var r2EgressHandler = async (request, env$1, ctx) => {
	const url = new URL(request.url);
	const parsed = parsePath(url.pathname);
	if (!parsed) return new Response("Bad Request: empty path", { status: 400 });
	const { bucket: bucketName, key: encodedKey } = parsed;
	const key = decodeObjectKey(encodedKey);
	if (!ctx.params?.buckets || !(bucketName in ctx.params.buckets)) return new Response(`Access to R2 bucket "${bucketName}" is not permitted. Call mountBucket() with this bucket before accessing it.`, { status: 403 });
	const bucketParams = ctx.params.buckets[bucketName];
	const mountPrefix = normalizeMountPrefix(bucketParams.prefix);
	const readOnly = bucketParams.readOnly ?? false;
	const r2 = resolveR2Bucket(env$1, bucketName);
	if (!r2) return new Response(`R2 binding "${bucketName}" not found in Worker env. Ensure the binding name matches the bucket name passed to mountBucket().`, { status: 500 });
	const { method } = request;
	if (!key) {
		if (method === "GET" && url.searchParams.has("location")) return xmlResponse(buildLocationXml());
		if (method === "GET" && url.searchParams.get("list-type") === "2") return handleListObjects(r2, bucketName, url, mountPrefix);
		if (method === "GET") return handleListObjects(r2, bucketName, url, mountPrefix);
		return new Response("Method Not Allowed", { status: 405 });
	}
	const fullKey = mountPrefix ? `${mountPrefix}/${key}` : key;
	if (readOnly && (method === "PUT" || method === "DELETE" || method === "POST" && (url.searchParams.has("uploads") || url.searchParams.has("uploadId")))) return new Response("Forbidden: bucket mount is read-only", { status: 403 });
	if (method === "POST" && url.searchParams.has("uploads")) return handleCreateMultipartUpload(r2, bucketName, fullKey, request);
	if (method === "POST" && url.searchParams.has("uploadId")) return handleCompleteMultipartUpload(r2, bucketName, fullKey, url, request);
	if (method === "PUT" && url.searchParams.has("partNumber") && url.searchParams.has("uploadId")) return handleUploadPart(r2, fullKey, url, request);
	if (method === "DELETE" && url.searchParams.has("uploadId")) return handleAbortMultipartUpload(r2, fullKey, url);
	switch (method) {
		case "HEAD": return handleHeadObject(r2, fullKey);
		case "GET": return handleGetObject(r2, fullKey, request);
		case "PUT": return handlePutObject(r2, bucketName, fullKey, request, env$1, ctx.params.buckets);
		case "DELETE": return handleDeleteObject(r2, fullKey);
		default: return new Response("Method Not Allowed", { status: 405 });
	}
};
var PER_MOUNT_SUFFIX = ".s3-credential-proxy.internal";
var SELF_TEST_PATH = "/__sandbox_credential_proxy_self_test__";
var DIAGNOSTICS_PATH = "/__sandbox_credential_proxy_diagnostics__";
var DEFAULT_SLOW_REQUEST_MS = 1e3;
var ERROR_RESPONSE_BODY_LIMIT = 2048;
var MAX_DIAGNOSTIC_EVENTS = 500;
var DUMMY_AUTH_HEADERS = /* @__PURE__ */ new Set([
	"authorization",
	"x-amz-date",
	"x-amz-content-sha256",
	"x-amz-security-token",
	"x-goog-date",
	"x-goog-content-sha256"
]);
var sigV4ClientCache = /* @__PURE__ */ new Map();
var directoryMarkerCache = /* @__PURE__ */ new Map();
var credentialProxyDiagnosticEvents = [];
var credentialProxyDiagnosticEventCount = 0;
function evictSigV4ClientCacheEntry(mountId) {
	sigV4ClientCache.delete(mountId);
}
function evictDirectoryMarkerCacheForMount(mountId) {
	const prefix = `${mountId}:`;
	for (const key of directoryMarkerCache.keys()) if (key.startsWith(prefix)) directoryMarkerCache.delete(key);
}
function toHex(buffer) {
	return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(data) {
	return toHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)));
}
async function hmacSHA256(key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, {
		name: "HMAC",
		hash: "SHA-256"
	}, false, ["sign"]);
	return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}
function detectS3Region(provider, endpoint) {
	if (provider === "r2") return "auto";
	try {
		const host = new URL(endpoint).hostname;
		const m = host.match(/s3[.-]([a-z0-9-]+)\.amazonaws\.com/);
		if (m && m[1] !== "amazonaws") return m[1];
		if (host === "s3.amazonaws.com") return "us-east-1";
	} catch {}
	return "auto";
}
function buildCleanHeaders(original) {
	const clean = new Headers();
	for (const [k, v] of original) {
		const lower = k.toLowerCase();
		if (!DUMMY_AUTH_HEADERS.has(lower) && lower !== "host") clean.set(k, v);
	}
	const contentSHA256 = original.get("x-amz-content-sha256");
	if (contentSHA256 && isValidContentSHA256(contentSHA256)) clean.set("x-amz-content-sha256", contentSHA256);
	return clean;
}
function isValidContentSHA256(value) {
	return value === "UNSIGNED-PAYLOAD" || /^[a-fA-F0-9]{64}$/.test(value);
}
function getCredentialProxyDebugConfig(env$1) {
	const envRecord = env$1;
	const enabled = envRecord.SANDBOX_CREDENTIAL_PROXY_DEBUG === "true";
	const diagnosticsEndpointEnabled = envRecord.SANDBOX_CREDENTIAL_PROXY_DIAGNOSTICS_ENDPOINT === "true";
	const configuredSlowRequestMs = Number(envRecord.SANDBOX_CREDENTIAL_PROXY_SLOW_REQUEST_MS);
	return {
		diagnosticsEndpointEnabled,
		enabled,
		slowRequestMs: Number.isFinite(configuredSlowRequestMs) && configuredSlowRequestMs >= 0 ? configuredSlowRequestMs : DEFAULT_SLOW_REQUEST_MS
	};
}
function recordCredentialProxyDiagnosticEvent(event) {
	credentialProxyDiagnosticEvents.push(event);
	credentialProxyDiagnosticEventCount++;
	while (credentialProxyDiagnosticEvents.length > MAX_DIAGNOSTIC_EVENTS) credentialProxyDiagnosticEvents.shift();
}
function getCredentialProxyDiagnosticsResponse(url, containerId) {
	const since = Number(url.searchParams.get("since") ?? "0");
	const bufferStartCount = credentialProxyDiagnosticEventCount - credentialProxyDiagnosticEvents.length;
	const events = credentialProxyDiagnosticEvents.filter((event, index) => {
		if (event.containerId !== containerId) return false;
		return !Number.isFinite(since) || bufferStartCount + index >= since;
	});
	return Response.json({
		nextCursor: credentialProxyDiagnosticEventCount,
		events
	});
}
async function withCredentialProxyDiagnostics(requestInfo, debugConfig, containerId, path$1, operation) {
	const started = Date.now();
	try {
		const response = await operation();
		const durationMs = Date.now() - started;
		if (debugConfig.enabled) recordCredentialProxyDiagnosticEvent({
			...requestInfo,
			containerId,
			durationMs,
			ok: response.ok,
			path: path$1,
			status: response.status,
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		if (debugConfig.enabled || durationMs >= debugConfig.slowRequestMs) console.info("sandbox.s3_credential_proxy.request", {
			...requestInfo,
			durationMs,
			ok: response.ok,
			status: response.status,
			responseContentLength: response.headers.get("content-length")
		});
		if (!response.ok) {
			const responseForLog = response.clone();
			const requestInfoSnapshot = { ...requestInfo };
			responseForLog.text().then((body) => {
				console.warn("sandbox.s3_credential_proxy.upstream_error", {
					...requestInfoSnapshot,
					durationMs,
					status: response.status,
					statusText: response.statusText,
					errorBody: body.slice(0, ERROR_RESPONSE_BODY_LIMIT)
				});
			}).catch(() => {});
		}
		return response;
	} catch (error) {
		const durationMs = Date.now() - started;
		console.warn("sandbox.s3_credential_proxy.request_error", {
			...requestInfo,
			durationMs,
			error: error instanceof Error ? error.message : String(error)
		});
		throw error;
	}
}
function getSigV4Client(mountId, endpoint, provider, credentials, region) {
	const cached = sigV4ClientCache.get(mountId);
	if (cached && cached.accessKeyId === credentials.accessKeyId && cached.secretAccessKey === credentials.secretAccessKey && cached.endpoint === endpoint && cached.provider === provider && cached.region === region) return cached.client;
	const client = new AwsClient({
		accessKeyId: credentials.accessKeyId,
		secretAccessKey: credentials.secretAccessKey,
		service: "s3",
		region,
		retries: 0
	});
	sigV4ClientCache.set(mountId, {
		client,
		accessKeyId: credentials.accessKeyId,
		secretAccessKey: credentials.secretAccessKey,
		endpoint,
		provider,
		region
	});
	return client;
}
function encodeCanonicalQueryPart(value) {
	return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}
function getCanonicalURI(url) {
	return url.pathname.split("/").map((segment) => segment.split(/(%[0-9A-Fa-f]{2})/g).map((part) => /^%[0-9A-Fa-f]{2}$/.test(part) ? part.toUpperCase() : encodeCanonicalQueryPart(part)).join("")).join("/");
}
function getCanonicalQueryString(url) {
	const query = url.search.startsWith("?") ? url.search.slice(1) : url.search;
	if (!query) return "";
	return query.split("&").map((part) => {
		const separatorIndex = part.indexOf("=");
		if (separatorIndex === -1) return [part, ""];
		return [part.slice(0, separatorIndex), part.slice(separatorIndex + 1)];
	}).map(([key, value]) => [encodeCanonicalQueryPart(decodeURIEncodedQueryPart(key)), encodeCanonicalQueryPart(decodeURIEncodedQueryPart(value))]).sort(([leftKey, leftValue], [rightKey, rightValue]) => {
		if (leftKey < rightKey) return -1;
		if (leftKey > rightKey) return 1;
		if (leftValue < rightValue) return -1;
		if (leftValue > rightValue) return 1;
		return 0;
	}).map(([key, value]) => `${key}=${value}`).join("&");
}
function decodeURIEncodedQueryPart(value) {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}
function getSigV4PayloadHash(headers) {
	const existingHash = headers.get("x-amz-content-sha256");
	if (existingHash && existingHash !== "UNSIGNED-PAYLOAD") return {
		hash: existingHash,
		mode: "signed"
	};
	return {
		hash: "UNSIGNED-PAYLOAD",
		mode: "unsigned"
	};
}
function isZeroLengthDirectoryMarkerPUT(request, realPath) {
	return request.method.toUpperCase() === "PUT" && request.headers.get("content-length") === "0" && realPath.endsWith("/");
}
function isDirectoryMarkerHEAD(request) {
	return request.method.toUpperCase() === "HEAD";
}
function getDirectoryMarkerCacheKey(mountId, realPath) {
	return `${mountId}:${realPath.replace(/\/+$/, "")}`;
}
function getDirectoryMarkerResponseHeaders(request) {
	const headers = [
		["Accept-Ranges", "bytes"],
		["Content-Length", "0"],
		["ETag", "\"d41d8cd98f00b204e9800998ecf8427e\""],
		["Last-Modified", (/* @__PURE__ */ new Date()).toUTCString()]
	];
	const contentType = request.headers.get("content-type");
	if (contentType) headers.push(["Content-Type", contentType]);
	for (const [name, value] of request.headers) if (name.toLowerCase().startsWith("x-amz-meta-")) headers.push([name, value]);
	return headers;
}
function normalizePrefix(prefix) {
	if (!prefix) return void 0;
	return prefix.replace(/^\/+/, "").replace(/\/+$/, "");
}
function getObjectKeyForPath(realPath, bucket) {
	const pathSegments = realPath.split("/").filter(Boolean);
	if (pathSegments[0] !== bucket) return null;
	return pathSegments.slice(1).join("/");
}
function isObjectKeyWithinPrefix(objectKey, prefix) {
	const normalizedPrefix = normalizePrefix(prefix);
	if (!normalizedPrefix) return true;
	return objectKey === normalizedPrefix || objectKey.startsWith(`${normalizedPrefix}/`);
}
function parseCopySourceHeader(value) {
	const encodedPath = value.split("?", 1)[0];
	if (!encodedPath) return null;
	let decodedPath;
	try {
		decodedPath = decodeURIComponent(encodedPath);
	} catch {
		return null;
	}
	const path$1 = decodedPath.startsWith("/") ? decodedPath.slice(1) : decodedPath;
	const separatorIndex = path$1.indexOf("/");
	if (separatorIndex <= 0 || separatorIndex === path$1.length - 1) return null;
	return {
		bucket: path$1.slice(0, separatorIndex),
		objectKey: path$1.slice(separatorIndex + 1)
	};
}
function validateCopySourceWithinMountScope(headers, bucket, prefix) {
	const copySources = [["x-amz-copy-source", headers.get("x-amz-copy-source")], ["x-goog-copy-source", headers.get("x-goog-copy-source")]].filter((entry) => entry[1] !== null);
	if (copySources.length > 1) return new Response("Bad Request: multiple copy source headers", { status: 400 });
	if (copySources.length === 0) return null;
	const [headerName, value] = copySources[0];
	const copySource = parseCopySourceHeader(value);
	if (!copySource) return new Response(`Bad Request: invalid ${headerName}`, { status: 400 });
	if (copySource.bucket !== bucket || !isObjectKeyWithinPrefix(copySource.objectKey, prefix)) return new Response("Forbidden: copy source is outside mounted scope", { status: 403 });
	return null;
}
function isRequestWithinMountScope(realPath, url, bucket, prefix) {
	const objectKey = getObjectKeyForPath(realPath, bucket);
	if (objectKey === null) return false;
	const requestedPrefix = url.searchParams.get("prefix");
	if (objectKey !== "" && !isObjectKeyWithinPrefix(objectKey, prefix)) return false;
	if (objectKey === "" && normalizePrefix(prefix) !== void 0 && url.search !== "" && requestedPrefix === null) return false;
	if (requestedPrefix !== null) return isObjectKeyWithinPrefix(requestedPrefix, prefix);
	return true;
}
function isBucketRootProbe(request, realPath, url, bucket) {
	const method = request.method.toUpperCase();
	return (method === "GET" || method === "HEAD") && url.search === "" && getObjectKeyForPath(realPath, bucket) === "";
}
function isBucketRootMutation(request, realPath, bucket) {
	const method = request.method.toUpperCase();
	return method !== "GET" && method !== "HEAD" && method !== "OPTIONS" && getObjectKeyForPath(realPath, bucket) === "";
}
function deleteDirectoryMarkerCacheEntry(mountId, realPath) {
	directoryMarkerCache.delete(getDirectoryMarkerCacheKey(mountId, realPath));
}
function getContentLength(request) {
	const contentLength = request.headers.get("content-length");
	if (contentLength === null) return null;
	const parsed = Number(contentLength);
	if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
	return parsed;
}
function getSigV4ForwardInit(request) {
	const contentLength = getContentLength(request);
	if (contentLength === 0) return { body: /* @__PURE__ */ new Uint8Array(0) };
	if (contentLength === null || request.body === null) return {};
	const { readable, writable } = new FixedLengthStream(contentLength);
	request.body.pipeTo(writable).catch((error) => {
		writable.abort(error).catch(() => {});
	});
	return { body: readable };
}
function getGCSHeaders(request) {
	const headers = new Headers();
	for (const [k, v] of request.headers) {
		const lower = k.toLowerCase();
		if (DUMMY_AUTH_HEADERS.has(lower) || lower === "host" || lower === "content-length" || lower === "expect") continue;
		if (lower.startsWith("x-amz-meta-")) {
			headers.set(`x-goog-meta-${lower.slice(11)}`, v);
			continue;
		}
		if (lower.startsWith("x-amz-")) continue;
		headers.set(k, v);
	}
	return headers;
}
async function signAndForwardSigV4(request, mountId, endpoint, provider, credentials, requestInfo) {
	const signingStarted = Date.now();
	const region = detectS3Region(provider, endpoint);
	const payload = getSigV4PayloadHash(request.headers);
	const client = getSigV4Client(mountId, endpoint, provider, credentials, region);
	requestInfo.payloadHashMode = payload.mode;
	requestInfo.clientSetupMs = Date.now() - signingStarted;
	const upstreamStarted = Date.now();
	const forwardInit = getSigV4ForwardInit(request);
	requestInfo.bodyPresent = forwardInit?.body !== void 0 || request.body !== null;
	const response = await client.fetch(request, forwardInit);
	requestInfo.upstreamMs = Date.now() - upstreamStarted;
	return response;
}
async function signAndForwardGCS(request, credentials, requestInfo) {
	const url = new URL(request.url);
	const gcsHeaders = getGCSHeaders(request);
	const dateStr = `${(/* @__PURE__ */ new Date()).toISOString().replace(/[:-]/g, "").replace(/\.\d+Z$/, "")}Z`;
	const dateOnly = dateStr.slice(0, 8);
	const location = "auto";
	const service = "storage";
	const credentialScope = `${dateOnly}/${location}/${service}/goog4_request`;
	const bodyHash = "UNSIGNED-PAYLOAD";
	const headerEntries = [
		["host", url.host],
		["x-goog-content-sha256", bodyHash],
		["x-goog-date", dateStr]
	];
	for (const [k, v] of gcsHeaders) headerEntries.push([k.toLowerCase(), v.trim()]);
	headerEntries.sort((a, b) => a[0].localeCompare(b[0]));
	const signedHeaders = headerEntries.map(([k]) => k).join(";");
	const canonicalHeaders = headerEntries.map(([k, v]) => `${k}:${v}\n`).join("");
	const stringToSign = [
		"GOOG4-HMAC-SHA256",
		dateStr,
		credentialScope,
		await sha256Hex([
			request.method,
			getCanonicalURI(url),
			getCanonicalQueryString(url),
			canonicalHeaders,
			signedHeaders,
			bodyHash
		].join("\n"))
	].join("\n");
	const signature = toHex(await hmacSHA256(await hmacSHA256(await hmacSHA256(await hmacSHA256(await hmacSHA256(new TextEncoder().encode(`GOOG4${credentials.secretAccessKey}`), dateOnly), location), service), "goog4_request"), stringToSign));
	const authorization = `GOOG4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
	const newHeaders = new Headers(gcsHeaders);
	newHeaders.set("x-goog-date", dateStr);
	newHeaders.set("x-goog-content-sha256", bodyHash);
	newHeaders.set("Authorization", authorization);
	const gcsBody = getContentLength(request) === 0 ? /* @__PURE__ */ new Uint8Array(0) : request.body;
	const upstreamStarted = Date.now();
	const response = await fetch(new Request(request.url, {
		method: request.method,
		headers: newHeaders,
		body: gcsBody
	}));
	requestInfo.upstreamMs = Date.now() - upstreamStarted;
	return response;
}
var s3CredentialProxyHandler = async (request, env$1, ctx) => {
	const url = new URL(request.url);
	if (url.pathname === SELF_TEST_PATH) return new Response("OK", { status: 200 });
	const debugConfig = getCredentialProxyDebugConfig(env$1);
	if (url.pathname === DIAGNOSTICS_PATH) {
		if (!debugConfig.enabled || !debugConfig.diagnosticsEndpointEnabled) return new Response("Not Found", { status: 404 });
		return getCredentialProxyDiagnosticsResponse(url, ctx.containerId);
	}
	const segments = url.pathname.split("/").filter(Boolean);
	const hostname = url.hostname;
	let mountId;
	let realPath;
	if (hostname.endsWith(PER_MOUNT_SUFFIX)) {
		mountId = hostname.slice(0, -29);
		realPath = url.pathname;
	} else {
		mountId = segments[0] ?? null;
		realPath = mountId ? url.pathname.slice(`/${mountId}`.length) || "/" : "/";
	}
	if (!mountId) return new Response("Bad Request: missing mount ID", { status: 400 });
	const mount = ctx.params?.mounts[mountId];
	if (!mount) return new Response(`Forbidden: unknown mount ID "${mountId}"`, { status: 403 });
	if (mount.readOnly) {
		const method = request.method.toUpperCase();
		if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") return new Response("Forbidden: bucket mount is read-only", { status: 403 });
	}
	const realUrl = new URL(realPath + (url.search || ""), mount.endpoint);
	if (isBucketRootProbe(request, realPath, url, mount.bucket)) return new Response(null, { status: 200 });
	if (isBucketRootMutation(request, realPath, mount.bucket)) return new Response("Method Not Allowed", { status: 405 });
	if (!isRequestWithinMountScope(realPath, url, mount.bucket, mount.prefix)) return new Response("Forbidden: request is outside mounted bucket scope", { status: 403 });
	const copySourceError = validateCopySourceWithinMountScope(request.headers, mount.bucket, mount.prefix);
	if (copySourceError) return copySourceError;
	const cleanHeaders = buildCleanHeaders(request.headers);
	const cleanRequest = new Request(realUrl.toString(), {
		method: request.method,
		headers: cleanHeaders,
		body: request.body
	});
	const requestInfo = {
		authStrategy: mount.authStrategy,
		bucket: mount.bucket,
		contentLength: request.headers.get("content-length"),
		method: request.method,
		mountId,
		query: [...url.searchParams.keys()].sort()
	};
	if (isZeroLengthDirectoryMarkerPUT(cleanRequest, realPath)) {
		const responseHeaders = getDirectoryMarkerResponseHeaders(cleanRequest);
		requestInfo.bodyPresent = request.body !== null;
		if (mount.authStrategy === "s3-sigv4") requestInfo.payloadHashMode = getSigV4PayloadHash(cleanRequest.headers).mode;
		return withCredentialProxyDiagnostics(requestInfo, debugConfig, ctx.containerId, realPath, async () => {
			const response = mount.authStrategy === "gcs" ? await signAndForwardGCS(cleanRequest, mount.credentials, requestInfo) : await signAndForwardSigV4(cleanRequest, mountId, mount.endpoint, mount.provider, mount.credentials, requestInfo);
			if (response.ok) directoryMarkerCache.set(getDirectoryMarkerCacheKey(mountId, realPath), responseHeaders);
			return response;
		});
	}
	if (isDirectoryMarkerHEAD(cleanRequest)) {
		const responseHeaders = directoryMarkerCache.get(getDirectoryMarkerCacheKey(mountId, realPath));
		if (responseHeaders) {
			requestInfo.bodyPresent = false;
			if (mount.authStrategy === "s3-sigv4") requestInfo.payloadHashMode = getSigV4PayloadHash(cleanRequest.headers).mode;
			return withCredentialProxyDiagnostics(requestInfo, debugConfig, ctx.containerId, realPath, () => Promise.resolve(new Response(null, {
				status: 200,
				headers: responseHeaders
			})));
		}
	}
	if (cleanRequest.method.toUpperCase() !== "HEAD") deleteDirectoryMarkerCacheEntry(mountId, realPath);
	if (mount.authStrategy === "gcs") return withCredentialProxyDiagnostics(requestInfo, debugConfig, ctx.containerId, realPath, () => signAndForwardGCS(cleanRequest, mount.credentials, requestInfo));
	return withCredentialProxyDiagnostics(requestInfo, debugConfig, ctx.containerId, realPath, () => signAndForwardSigV4(cleanRequest, mountId, mount.endpoint, mount.provider, mount.credentials, requestInfo));
};
/**
* Resolve a Cloudflare account id from environment with documented
* precedence. Used by features that need to address a specific account
* (Cloudflare Tunnel, R2 backup) to find their account id without
* forcing every caller to set the same env var.
*
* Precedence (first non-empty wins):
*   1. The feature-specific override env var (e.g. `CLOUDFLARE_TUNNEL_ACCOUNT_ID`).
*   2. `CLOUDFLARE_ACCOUNT_ID`.
*   3. The single account `CLOUDFLARE_API_TOKEN` is scoped to, via
*      `GET /user/tokens/verify`. Multi-account tokens are rejected.
*
* The resolver is feature-agnostic; only the `overrideKey` differs per
* caller. Throws on any failure with a message that names the env vars
* the caller can set to fix it.
*/
var TOKEN_VERIFY_URL = "https://api.cloudflare.com/client/v4/user/tokens/verify";
var ACCOUNTS_LIST_URL = "https://api.cloudflare.com/client/v4/accounts";
/**
* Per-request timeout for the credential introspection calls below.
* Without one a hung Cloudflare control-plane call wedges every
* first-time named-tunnel `get()` on the DO (the resolver promises are
* memoised on `Sandbox`, so the first caller's hang is everyone's hang).
*/
var CREDENTIALS_TIMEOUT_MS = 1e4;
/**
* Fetch wrapper that adds an `AbortSignal.timeout` and surfaces a
* timeout as a labelled `Error` so the caller can blame the right URL.
*/
async function fetchWithTimeout(fetcher, url, init, timeoutMs = CREDENTIALS_TIMEOUT_MS) {
	try {
		return await fetcher(url, {
			...init,
			signal: AbortSignal.timeout(timeoutMs)
		});
	} catch (err) {
		if (err instanceof Error && err.name === "TimeoutError") throw new Error(`Cloudflare API request to ${url} timed out after ${timeoutMs}ms`);
		throw err;
	}
}
/**
* Cloudflare error code returned by `GET /user/tokens/verify` when the
* presented token is an account-owned (`cfat-`) token rather than a
* user-owned one. Matches the heuristic wrangler uses in
* `src/user/whoami.ts` (`getTokenType`).
*/
var ACCOUNT_OWNED_TOKEN_CODE = 1e3;
async function resolveAccountId(env$1, options) {
	const override = getEnvString(env$1, options.overrideKey);
	if (override) return override;
	const generic = getEnvString(env$1, "CLOUDFLARE_ACCOUNT_ID");
	if (generic) return generic;
	const token = getEnvString(env$1, "CLOUDFLARE_API_TOKEN");
	if (!token) throw new Error(`Cloudflare account id could not be resolved. Set one of: ${options.overrideKey}, CLOUDFLARE_ACCOUNT_ID, or CLOUDFLARE_API_TOKEN (a token scoped to a single account).`);
	const fetcher = options.fetcher ?? fetch;
	const response = await fetchWithTimeout(fetcher, TOKEN_VERIFY_URL, {
		method: "GET",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json"
		}
	});
	let body;
	try {
		body = await response.json();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cloudflare token verification returned malformed JSON: ${message}`);
	}
	if (response.ok && body?.success) {
		const derived = body.result_info?.account?.id;
		if (!derived) throw new Error(`Cloudflare token is not scoped to a single account (ambiguous). Set ${options.overrideKey} or CLOUDFLARE_ACCOUNT_ID explicitly.`);
		return derived;
	}
	if (body?.errors?.some((e) => e.code === ACCOUNT_OWNED_TOKEN_CODE)) return await deriveAccountIdViaAccountToken(token, fetcher, options);
	throw new Error(`Cloudflare token verification failed with status ${response.status}. Check that CLOUDFLARE_API_TOKEN is valid or set ${options.overrideKey} / CLOUDFLARE_ACCOUNT_ID explicitly.`);
}
/**
* Account-owned token (cfat-) fallback: list the accounts the token can
* see, and — if there's exactly one — confirm with the account-scoped
* verify endpoint before returning the id.
*
* Common failure modes get specific, actionable error messages:
*   - `/accounts` 403 (token lacks `account:read`): tell the caller to
*     set `CLOUDFLARE_ACCOUNT_ID` explicitly.
*   - multiple accounts: same.
*   - zero accounts: same.
*   - confirm step fails: surface the API error code verbatim.
*/
async function deriveAccountIdViaAccountToken(token, fetcher, options) {
	const listResponse = await fetchWithTimeout(fetcher, `${ACCOUNTS_LIST_URL}?per_page=2`, {
		method: "GET",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json"
		}
	});
	let listBody;
	try {
		listBody = await listResponse.json();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cloudflare account-owned token: /accounts returned malformed JSON: ${message}`);
	}
	if (!listResponse.ok || !listBody?.success) throw new Error(`Cloudflare account-owned token (cfat-...) detected, but /accounts returned status ${listResponse.status}. The token may lack account:read scope. Set CLOUDFLARE_ACCOUNT_ID explicitly to skip introspection.`);
	const accounts = listBody.result ?? [];
	if (accounts.length === 0) throw new Error("Cloudflare account-owned token has access to no accounts. Set CLOUDFLARE_ACCOUNT_ID explicitly.");
	if (accounts.length > 1) throw new Error("Cloudflare account-owned token has access to multiple accounts (ambiguous). Set CLOUDFLARE_ACCOUNT_ID explicitly to disambiguate.");
	const accountId = accounts[0]?.id;
	if (!accountId) throw new Error("Cloudflare /accounts returned a result without an id field.");
	const verifyResponse = await fetchWithTimeout(fetcher, `${ACCOUNTS_LIST_URL}/${encodeURIComponent(accountId)}/tokens/verify`, {
		method: "GET",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json"
		}
	});
	let verifyBody;
	try {
		verifyBody = await verifyResponse.json();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cloudflare account token verify returned malformed JSON: ${message}`);
	}
	if (!verifyResponse.ok || !verifyBody?.success) {
		const detail = verifyBody?.errors?.map((e) => `${e.code}: ${e.message}`).join("; ") ?? `HTTP ${verifyResponse.status}`;
		throw new Error(`Cloudflare account token verify failed for account ${accountId}: ${detail}`);
	}
	return accountId;
}
var ZONES_LIST_URL = "https://api.cloudflare.com/client/v4/zones";
/**
* Resolve a Cloudflare zone id.
*
* Precedence:
*   1. `CLOUDFLARE_ZONE_ID` env var.
*   2. The single zone the token can see under `accountId`, via
*      `GET /zones?account.id=<accountId>&per_page=2`.
*
* Step 2 deliberately fetches at most two results: one is the happy path,
* two (or more) means the token is ambiguous and we refuse to guess.
* Multi-zone tokens must set `CLOUDFLARE_ZONE_ID` explicitly so the
* caller's intent is unambiguous.
*/
async function resolveZoneId(env$1, options) {
	const envZone = getEnvString(env$1, "CLOUDFLARE_ZONE_ID");
	if (envZone) return envZone;
	const response = await fetchWithTimeout(options.fetcher ?? fetch, `${ZONES_LIST_URL}?account.id=${encodeURIComponent(options.accountId)}&per_page=2`, {
		method: "GET",
		headers: {
			authorization: `Bearer ${options.token}`,
			"content-type": "application/json"
		}
	});
	if (!response.ok) throw new Error(`Cloudflare zones lookup failed with status ${response.status}. Set CLOUDFLARE_ZONE_ID explicitly or grant the API token Zone:Read.`);
	let body;
	try {
		body = await response.json();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cloudflare zones lookup returned malformed JSON: ${message}`);
	}
	const zones = body.result ?? [];
	if (zones.length === 0) throw new Error(`Cloudflare API token has access to no zones in account ${options.accountId}. Set CLOUDFLARE_ZONE_ID explicitly or grant the token Zone:Read on the intended zone.`);
	if (zones.length > 1) throw new Error(`Cloudflare API token has access to multiple zones in account ${options.accountId} (ambiguous). Set CLOUDFLARE_ZONE_ID explicitly to disambiguate.`);
	const zoneId = zones[0]?.id;
	if (!zoneId) throw new Error("Cloudflare zones lookup returned a result without an id field.");
	return zoneId;
}
var SandboxControlCallbackImpl = class extends RpcTarget4 {
	constructor(getHandler, logger) {
		super();
		this.getHandler = getHandler;
		this.logger = logger;
	}
	async onTunnelExit(id, port, exitCode, runId) {
		const handler = this.getHandler();
		if (!handler) {
			this.logger.debug("onTunnelExit: no handler bound; ignoring", {
				id,
				port,
				exitCode,
				runId
			});
			return;
		}
		await handler(id, port, exitCode, runId);
	}
};
/**
* Cloudflare API client for named-tunnel orchestration.
*
* Design notes:
*
* - The Cloudflare API envelope is `{ success, result, errors }`. We
*   unwrap `result` on success and surface a thrown `Error` with the
*   API error code/message on failure. Transport-level errors
*   propagate unchanged.
* - Delete endpoints are idempotent from the caller's perspective:
*   a 404 (already gone) resolves successfully so destroy() can run
*   without special-casing.
* - `upsertCNAME` is the most subtle wrapper: it lists existing
*   records, reuses a matching one, and refuses to mutate a record
*   whose content differs from what we want. This is the fence that
*   stops two sandboxes from racing on the same hostname.
*/
var API_BASE = "https://api.cloudflare.com/client/v4";
/**
* Default request timeout. Cloudflare API P99 latency is well under
* this; values much smaller risk false positives on cold control-plane
* paths (e.g. first `cfd_tunnel` POST in a new account).
*/
var DEFAULT_TIMEOUT_MS = 1e4;
/**
* Internal request helper. Centralises auth header, JSON encoding,
* timeout enforcement, and envelope unwrapping so each wrapper above
* stays declarative.
*/
async function cfRequest(url, token, fetcher, options = {}) {
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const init = {
		method: options.method ?? "GET",
		headers: {
			authorization: `Bearer ${token}`,
			"content-type": "application/json"
		},
		signal: AbortSignal.timeout(timeoutMs)
	};
	if (options.body !== void 0) init.body = JSON.stringify(options.body);
	let response;
	try {
		response = await fetcher(url, init);
	} catch (err) {
		if (err instanceof Error && err.name === "TimeoutError") throw new Error(`Cloudflare API request to ${url} timed out after ${timeoutMs}ms`);
		throw err;
	}
	if (options.acceptStatuses?.includes(response.status)) return;
	let envelope;
	try {
		envelope = await response.json();
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		throw new Error(`Cloudflare API returned non-JSON response (status ${response.status}): ${message}`);
	}
	if (!response.ok || envelope.success === false) {
		const errs = envelope.errors ?? [];
		const summary = errs.length ? errs.map((e) => `${e.code ?? "???"}: ${e.message ?? "unknown"}`).join(", ") : `HTTP ${response.status}`;
		throw new Error(`Cloudflare API error: ${summary}`);
	}
	return envelope.result;
}
/**
* Heuristic for the "tags are an Enterprise-only feature" error class.
* Empirically grounded against a non-Enterprise account:
*
*   - DNS create with `tags: [...]` on a non-Enterprise zone rejects with
*     Cloudflare error code 9300 and the message "DNS record has N tags,
*     exceeding the quota of 0.". The error string `cfRequest` constructs
*     embeds both the code and the message, so we match on either signal.
*   - Tunnel create with `tags: [...]` silently succeeds and drops the
*     field on the floor (no error to retry on). The fallback wrapper
*     therefore costs nothing on tunnel writes.
*
* Generic "requires Enterprise" phrasing is also matched as a forward-
* compatibility hedge in case Cloudflare changes the response shape on
* future endpoints.
*/
function isEnterpriseOnlyTagError(error) {
	if (!(error instanceof Error)) return false;
	const msg = error.message.toLowerCase();
	if (msg.includes("9300") && msg.includes("tag")) return true;
	if (!msg.includes("tag")) return false;
	return msg.includes("quota") || msg.includes("enterprise") || msg.includes("not allowed") || msg.includes("not entitled") || msg.includes("not available") || msg.includes("not supported");
}
/**
* Build the `tags` field attached to created Cloudflare resources. The
* tag is `sandboxId:<id>`, the same key used in DNS comments / tunnel
* metadata; together they let an operator find every resource a given
* sandbox owns from the Cloudflare dashboard.
*
* Tags are an Enterprise-only feature. The wrapper `createWithTagFallback`
* automatically retries the request without tags on the documented
* "requires Enterprise" error so non-enterprise accounts succeed without
* any configuration.
*/
function buildSandboxTags(sandboxId) {
	if (!sandboxId) return void 0;
	return [`sandboxId:${sandboxId}`];
}
/**
* Wrap a tagged-create request with an automatic tag-strip retry. The
* callback receives `tags`: pass it through to the request body as-is on
* the first call (`undefined` on the retry). The retry only fires for
* the Enterprise-only tag error class; any other failure surfaces
* verbatim.
*/
async function createWithTagFallback(sandboxId, send) {
	const tags = buildSandboxTags(sandboxId);
	if (!tags) return send(void 0);
	try {
		return await send(tags);
	} catch (err) {
		if (!isEnterpriseOnlyTagError(err)) throw err;
		return send(void 0);
	}
}
async function createTunnel(args) {
	const fetcher = args.fetcher ?? fetch;
	const result = await createWithTagFallback(args.metadata.sandboxId, (tags) => cfRequest(`${API_BASE}/accounts/${encodeURIComponent(args.accountId)}/cfd_tunnel`, args.token, fetcher, {
		method: "POST",
		body: {
			name: args.tunnelName,
			config_src: "cloudflare",
			metadata: args.metadata,
			...tags ? { tags } : {}
		}
	}));
	if (!result) throw new Error("Cloudflare tunnel create returned no result body");
	return {
		id: result.id,
		token: result.token
	};
}
/**
* Look up an existing tunnel by exact name match. Filters out tunnels
* marked `deleted_at != null` defensively in case the API ignores the
* `is_deleted=false` query parameter.
*
* When `expectedSandboxId` is provided, also verify that the tunnel's
* `metadata.sandboxId` tag matches — this is the authoritative "this
* resource was created by this sandbox" check, and the tag is set by
* `createTunnel`. Mismatches are treated as "not found" so the caller
* falls through to creating a fresh tunnel.
*/
async function findTunnelByName(args) {
	const fetcher = args.fetcher ?? fetch;
	const result = await cfRequest(`${API_BASE}/accounts/${encodeURIComponent(args.accountId)}/cfd_tunnel?name=${encodeURIComponent(args.tunnelName)}&is_deleted=false`, args.token, fetcher);
	if (!result) return null;
	const live = result.find((t) => !t.deleted_at);
	if (!live) return null;
	if (args.expectedSandboxId !== void 0) {
		if (live.metadata?.sandboxId !== args.expectedSandboxId) return null;
	}
	return {
		id: live.id,
		name: live.name
	};
}
async function deleteTunnel(args) {
	const fetcher = args.fetcher ?? fetch;
	await cfRequest(`${API_BASE}/accounts/${encodeURIComponent(args.accountId)}/cfd_tunnel/${encodeURIComponent(args.tunnelId)}`, args.token, fetcher, {
		method: "DELETE",
		acceptStatuses: [404]
	});
}
/**
* Fetch the opaque `--token` for an existing tunnel. Used on the retry
* path: when `findTunnelByName` discovers a tunnel left behind from a
* previous failed attempt, we need its token to run `cloudflared` again.
*
* The Cloudflare API returns the token as a bare quoted string in the
* `result` envelope (e.g. `"<base64-token>"`).
*/
async function getTunnelToken(args) {
	const fetcher = args.fetcher ?? fetch;
	const result = await cfRequest(`${API_BASE}/accounts/${encodeURIComponent(args.accountId)}/cfd_tunnel/${encodeURIComponent(args.tunnelId)}/token`, args.token, fetcher);
	if (typeof result !== "string" || result.length === 0) throw new Error(`Cloudflare did not return a token for tunnel ${args.tunnelId}`);
	return result;
}
async function getZoneName(args) {
	const fetcher = args.fetcher ?? fetch;
	const result = await cfRequest(`${API_BASE}/zones/${encodeURIComponent(args.zoneId)}`, args.token, fetcher);
	if (!result?.name) throw new Error(`Cloudflare zone ${args.zoneId} did not return a name`);
	return result.name;
}
async function upsertCNAME(args) {
	const fetcher = args.fetcher ?? fetch;
	const existing = (await cfRequest(`${API_BASE}/zones/${encodeURIComponent(args.zoneId)}/dns_records?type=CNAME&name=${encodeURIComponent(args.hostname)}`, args.token, fetcher) ?? []).find((r) => r.type === "CNAME" && r.name === args.hostname);
	if (existing) {
		if (existing.content === args.cnameTarget) return {
			recordId: existing.id,
			reused: true
		};
		throw new Error(`DNS record for ${args.hostname} already exists with different content (owned by you, not us): existing content="${existing.content}", existing comment="${existing.comment ?? ""}". Delete the record manually to allow the sandbox to manage it.`);
	}
	const createResult = await createWithTagFallback(args.sandboxId, (tags) => cfRequest(`${API_BASE}/zones/${encodeURIComponent(args.zoneId)}/dns_records`, args.token, fetcher, {
		method: "POST",
		body: {
			type: "CNAME",
			name: args.hostname,
			content: args.cnameTarget,
			proxied: true,
			comment: args.comment,
			...tags ? { tags } : {}
		}
	}));
	if (!createResult) throw new Error("Cloudflare DNS create returned no result body");
	return {
		recordId: createResult.id,
		reused: false
	};
}
async function deleteDNSRecord(args) {
	const fetcher = args.fetcher ?? fetch;
	await cfRequest(`${API_BASE}/zones/${encodeURIComponent(args.zoneId)}/dns_records/${encodeURIComponent(args.recordId)}`, args.token, fetcher, {
		method: "DELETE",
		acceptStatuses: [404]
	});
}
var ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
/**
* Generate a URL- and DNS-safe random id. The default 20 characters give
* ~100 bits of entropy, which keeps collisions negligible at any realistic
* volume without a uniqueness retry loop. 32 divides 256 evenly, so masking
* the low 5 bits of each random byte stays uniform.
*/
function randomId(size = 20) {
	const bytes = new Uint8Array(size);
	crypto.getRandomValues(bytes);
	let id = "";
	for (let i = 0; i < size; i += 1) id += ID_ALPHABET[bytes[i] & 31];
	return id;
}
var TUNNEL_GET_MAX_RECOVERY_ATTEMPTS = 2;
function runtimeRunId() {
	return `run-${randomId()}`;
}
function createTunnelInterruptedError(params) {
	return new OperationInterruptedError({
		message: params.reason === "recovery_exhausted" ? "Tunnel recovery attempts were exhausted" : "Tunnel operation was interrupted by a sandbox runtime change",
		code: ErrorCode.OPERATION_INTERRUPTED,
		httpStatus: 409,
		context: {
			reason: params.reason,
			operation: "tunnel.get",
			phase: params.phase,
			admitted: params.admitted,
			retryable: params.retryable,
			...params.recoveryAttempts !== void 0 && { recoveryAttempts: params.recoveryAttempts },
			...params.maxRecoveryAttempts !== void 0 && { maxRecoveryAttempts: params.maxRecoveryAttempts }
		},
		timestamp: (/* @__PURE__ */ new Date()).toISOString(),
		suggestion: params.retryable ? "Retry tunnels.get() for the same port so the SDK can establish a fresh tunnel run." : "Start a new tunnels.get() call only if this tunnel is still desired for the current sandbox."
	});
}
function translateTunnelInterruption(error, phase, admitted) {
	if (error instanceof OperationInterruptedError) return error;
	if (error instanceof RuntimeIdentityInactiveError) return createTunnelInterruptedError({
		reason: "runtime_replaced",
		phase,
		admitted,
		retryable: true
	});
	if (error instanceof SandboxLifetimeChangedError) return createTunnelInterruptedError({
		reason: "sandbox_lifetime_changed",
		phase,
		admitted,
		retryable: false
	});
	if (error instanceof RPCTransportError) return createTunnelInterruptedError({
		reason: "transport_disposed",
		phase,
		admitted: "unknown",
		retryable: true
	});
	return null;
}
var STORAGE_KEY = "tunnels";
var META_STORAGE_KEY = "tunnels:meta";
async function readMap(storage) {
	return await storage.get(STORAGE_KEY) ?? {};
}
async function readMetaMap(storage) {
	return await storage.get(META_STORAGE_KEY) ?? {};
}
function computeOptionsHash(options) {
	if (!options || !options.name) return "v1:quick";
	return `v1:named:${options.name}`;
}
function normaliseHash(hash) {
	return hash.startsWith("v1:") ? hash.slice(3) : hash;
}
function optionsHashesEqual(a, b) {
	return normaliseHash(a) === normaliseHash(b);
}
async function pruneTunnelsForRestart(storage) {
	await storage.transaction(async (txn) => {
		const map = await readMap(txn);
		const meta = await readMetaMap(txn);
		const nextMap = {};
		const nextMeta = {};
		for (const [portKey, info] of Object.entries(map)) if (info.name) {
			nextMap[portKey] = info;
			nextMeta[portKey] = {
				...meta[portKey] ?? { optionsHash: `v1:named:${info.name}` },
				needsRespawn: true
			};
		}
		await txn.put(STORAGE_KEY, nextMap);
		await txn.put(META_STORAGE_KEY, nextMeta);
	});
}
/**
* Tunnels namespace handler. Created once per Sandbox DO instance via
* `createTunnelsHandler(host)` and exposed as `sandbox.tunnels`.
*
* Storage is the source of truth. The DO holds a `Record<portString, TunnelInfo>`
* under the `tunnels` storage key, with internal lifecycle metadata under
* `tunnels:meta`. Container restarts drop quick tunnel records and mark named
* tunnels for respawn, so public list/get calls only return records that are
* usable for the current runtime.
*/
function validateTunnelPort(port) {
	if (!validatePort(port)) throw new SandboxSecurityError(`Invalid port number: ${port}. Must be 1024-65535, excluding reserved ports.`);
}
/** 8-char hex id derived from `crypto.getRandomValues`. Unique per sandbox. */
function shortId() {
	const buf = /* @__PURE__ */ new Uint8Array(4);
	crypto.getRandomValues(buf);
	return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
/**
* Match a structured SandboxError code anywhere on the error — translated
* SandboxErrors expose the code both as a top-level `code` field and on
* the nested `errorResponse.code`. Used for the few error codes the SDK
* recognises and recovers from (TUNNEL_NOT_FOUND, TUNNEL_ALREADY_RUNNING).
*
* Message strings may quote error-code tokens for diagnostics, so matching
* only structured fields keeps recovery branches tied to explicit error
* contracts.
*/
function hasErrorCode(error, code) {
	if (!error || typeof error !== "object") return false;
	const e = error;
	if (e.code === code) return true;
	if (e.errorResponse?.code === code) return true;
	return false;
}
function isTunnelNotFoundError(error) {
	return hasErrorCode(error, "TUNNEL_NOT_FOUND");
}
function isTunnelAlreadyRunningError(error) {
	return hasErrorCode(error, "TUNNEL_ALREADY_RUNNING");
}
/**
* The run holding `request.port` when the container rejected `request`
* with a port conflict. Containers older than this SDK omit
* `activeTunnelId`, which `stopTunnelRun` needs, so their conflicts yield
* `null`.
*/
function conflictingRunOnPort(error, request) {
	if (!hasErrorCode(error, "TUNNEL_RUN_CONFLICT")) return null;
	const context = error.context;
	const runId = context?.activeRunId;
	const tunnelId = context?.activeTunnelId;
	if (context?.port !== request.port || typeof runId !== "string" || typeof tunnelId !== "string" || runId === request.runId) return null;
	return {
		tunnelId,
		runId
	};
}
/**
* Concrete `TunnelsHandler` implementation.
*
* Extends `RpcTarget` for forward compatibility with direct Workers RPC
* pipelining (`stub.tunnels.get(port)`): only `RpcTarget` instances may
* be passed by reference across the Workers RPC boundary. Today the
* public `sandbox.tunnels` proxy in `getSandbox()` dispatches through
* `stub.callTunnels(method, args)` instead — pipelining through
* property getters is broken under the vite-plugin runtime — so the
* `RpcTarget` base is not on the hot call path. It is retained so the
* pipelining shape works once that constraint lifts.
*/
var TunnelsRpcTarget = class extends RpcTarget {
	#host;
	#withPortLock;
	/**
	* Memoised zone name (e.g. `'example.com'`) for the configured
	* `CLOUDFLARE_ZONE_ID`. Filled in lazily on the first named-tunnel
	* `get()` so quick-tunnel callers never hit the zone-lookup endpoint.
	*
	* Only successful resolutions are cached: a rejected lookup clears
	* the slot so the next caller retries, instead of permanently
	* poisoning every subsequent named-tunnel `get()` on the DO with the
	* same transient error.
	*/
	#zoneNamePromise = null;
	constructor(host, withPortLock) {
		super();
		this.#host = host;
		this.#withPortLock = withPortLock;
	}
	/**
	* Resolve the zone name for the configured zone id. Memoised for the
	* lifetime of this handler; the zone name doesn't change while a DO
	* is alive, and one extra GET on first use is cheaper than threading
	* the value through the host.
	*
	* On failure the cached promise is cleared so the next caller retries.
	* Without that, a transient 5xx on the first call would permanently
	* poison every subsequent named-tunnel `get()` until the DO restarts.
	*/
	async #getZoneName(config) {
		if (!this.#zoneNamePromise) {
			const pending = getZoneName({
				token: config.token,
				zoneId: config.zoneId,
				fetcher: this.#host.fetcher
			});
			this.#zoneNamePromise = pending;
			pending.catch(() => {
				if (this.#zoneNamePromise === pending) this.#zoneNamePromise = null;
			});
		}
		return this.#zoneNamePromise;
	}
	async get(port, options) {
		const startTime = Date.now();
		let outcome = "error";
		let cacheState = "miss";
		let caughtError;
		try {
			validateTunnelPort(port);
			if (options?.name !== void 0) validateTunnelName(options.name);
			const requestedHash = computeOptionsHash(options);
			const info = await this.#withPortLock(port, () => this.#getWithRecovery(port, options, async (recovery) => {
				const existing = (await readMap(this.#host.storage))[port.toString()];
				if (existing) {
					const metaEntry = (await readMetaMap(this.#host.storage))[port.toString()];
					if (!optionsHashesEqual(metaEntry?.optionsHash ?? (existing.name ? `v1:named:${existing.name}` : "v1:quick"), requestedHash)) throw new Error(`Tunnel on port ${port} was created with different options. Call destroy(${port}) before changing tunnel options.`);
					if (!existing.name && await this.#quickTunnelRecordIsStale(metaEntry)) {
						await this.#stopStaleQuickTunnel(existing, metaEntry);
						return await this.#provisionQuickTunnel(port, recovery);
					}
					if (metaEntry?.needsRespawn && existing.name) return await this.#provisionNamedTunnel(port, existing.name);
					if (existing.name && this.#host.getNamedTunnelConfig) {
						const currentConfig = await this.#host.getNamedTunnelConfig();
						const storedAccountId = metaEntry?.accountId;
						const storedZoneId = metaEntry?.zoneId;
						if (storedAccountId !== void 0 && storedAccountId !== currentConfig.accountId || storedZoneId !== void 0 && storedZoneId !== currentConfig.zoneId) {
							this.#zoneNamePromise = null;
							return await this.#provisionNamedTunnel(port, existing.name);
						}
					}
					cacheState = "hit";
					return existing;
				}
				if (options?.name) return await this.#provisionNamedTunnel(port, options.name);
				return await this.#provisionQuickTunnel(port, recovery);
			}));
			outcome = "success";
			return info;
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.#host.logger, {
				event: "tunnel.get",
				outcome,
				port,
				cacheState,
				durationMs: Date.now() - startTime,
				error: caughtError
			});
		}
	}
	async #getWithRecovery(port, options, run) {
		let recoveryAttempts = 0;
		const recovery = {};
		while (true) try {
			return await run(recovery);
		} catch (error) {
			const interrupted = translateTunnelInterruption(error, "provisioning", "unknown");
			if (!interrupted || options?.name || !interrupted.context.retryable) throw error;
			if (recoveryAttempts >= TUNNEL_GET_MAX_RECOVERY_ATTEMPTS) {
				await this.#stopAbandonedQuickRun(port, recovery.quickRun);
				await this.#clearQuickTunnelStorage(port);
				throw createTunnelInterruptedError({
					reason: "recovery_exhausted",
					phase: "interrupted",
					admitted: interrupted.context.admitted,
					retryable: false,
					recoveryAttempts,
					maxRecoveryAttempts: TUNNEL_GET_MAX_RECOVERY_ATTEMPTS
				});
			}
			recoveryAttempts++;
			if (interrupted.context.reason === "runtime_replaced") {
				await this.#stopAbandonedQuickRun(port, recovery.quickRun);
				recovery.quickRun = void 0;
			}
			await this.#clearQuickTunnelStorage(port);
		}
	}
	/**
	* Stop a quick tunnel run that `get()` is giving up on, so its
	* cloudflared does not keep holding the port. Best effort: the run may
	* have died with a replaced container.
	*/
	async #stopAbandonedQuickRun(port, run) {
		if (!run) return;
		try {
			await this.#host.client.tunnels.stopTunnelRun(run);
		} catch (error) {
			this.#host.logger.warn("tunnel.get: abandoned run cleanup failed", {
				port,
				...run,
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}
	/**
	* Start or replay a quick tunnel run. The Durable Object owns every
	* tunnel run in its container and holds the port lock, so a different
	* run already on the port lost its storage record. Stop it and retry
	* once instead of failing every later `get()` for the port.
	*/
	async #ensureQuickTunnelRun(request) {
		try {
			return await this.#host.client.tunnels.ensureTunnelRun(request);
		} catch (error) {
			const orphan = conflictingRunOnPort(error, request);
			if (!orphan) throw error;
			this.#host.logger.warn("tunnel.get: stopping orphaned run on port", {
				port: request.port,
				...orphan
			});
			await this.#host.client.tunnels.stopTunnelRun(orphan);
			return await this.#host.client.tunnels.ensureTunnelRun(request);
		}
	}
	async #clearQuickTunnelStorage(port) {
		await this.#host.storage.transaction(async (txn) => {
			const map = await readMap(txn);
			delete map[port.toString()];
			await txn.put(STORAGE_KEY, map);
			const meta = await readMetaMap(txn);
			delete meta[port.toString()];
			await txn.put(META_STORAGE_KEY, meta);
		});
	}
	async #quickTunnelRecordIsStale(metaEntry) {
		if (!this.#host.currentRuntime || !this.#host.currentLifetime) return false;
		if (!metaEntry?.runtimeIdentityID || !metaEntry.sandboxLifetimeID) return true;
		const runtime = await this.#host.currentRuntime.get();
		const lifetime = await this.#host.currentLifetime.getOrCreate();
		return runtime?.id !== metaEntry.runtimeIdentityID || lifetime.id !== metaEntry.sandboxLifetimeID;
	}
	async #stopStaleQuickTunnel(existing, metaEntry) {
		try {
			if (metaEntry?.tunnelRunId) await this.#host.client.tunnels.stopTunnelRun({
				tunnelId: existing.id,
				runId: metaEntry.tunnelRunId
			});
			else await this.#host.client.tunnels.destroyTunnel(existing.id);
		} catch (error) {
			if (!isTunnelNotFoundError(error)) throw error;
		}
	}
	/**
	* Provision a fresh quick tunnel and persist it. Caller holds the
	* per-port lock.
	*
	* Quick-tunnel ids are minted from a 32-bit random source. Collisions
	* are astronomically unlikely, but if the container happens to already
	* have one running under the freshly-minted id it rejects with
	* TUNNEL_ALREADY_RUNNING. Mint a fresh id and try again rather than
	* surfacing the confusing error — the retry budget caps the loop so a
	* persistent failure still surfaces.
	*/
	async #provisionQuickTunnel(port, recovery) {
		if (this.#host.currentRuntime && this.#host.currentLifetime) return await this.#provisionQuickTunnelRun(port, recovery);
		const MAX_ID_RETRIES = 3;
		let lastError;
		for (let attempt = 0; attempt < MAX_ID_RETRIES; attempt += 1) {
			const id = `quick-${shortId()}`;
			try {
				const spawned = await this.#host.client.tunnels.runQuickTunnel(id, port);
				await this.#host.storage.transaction(async (txn) => {
					const nextMap = await readMap(txn);
					nextMap[port.toString()] = spawned;
					await txn.put(STORAGE_KEY, nextMap);
					const nextMeta = await readMetaMap(txn);
					nextMeta[port.toString()] = { optionsHash: "v1:quick" };
					await txn.put(META_STORAGE_KEY, nextMeta);
				});
				return spawned;
			} catch (err) {
				if (!isTunnelAlreadyRunningError(err)) throw err;
				lastError = err;
			}
		}
		throw lastError ?? /* @__PURE__ */ new Error("Failed to mint a unique quick-tunnel id");
	}
	async #provisionQuickTunnelRun(port, recovery) {
		if (!this.#host.currentRuntime || !this.#host.currentLifetime) throw new Error("Quick tunnel runtime fences are not configured");
		const lifetime = await this.#host.currentLifetime.getOrCreate();
		const runtimeBeforeAdmission = await this.#host.currentRuntime.get();
		try {
			await this.#host.currentLifetime.assertCurrent(lifetime);
		} catch (error) {
			throw translateTunnelInterruption(error, "runtime_ready", "unknown") ?? error;
		}
		recovery.quickRun ??= {
			tunnelId: `quick-${randomId()}`,
			runId: runtimeRunId()
		};
		const { tunnelId, runId } = recovery.quickRun;
		let ensureResult;
		let runtime = runtimeBeforeAdmission;
		try {
			ensureResult = await this.#ensureQuickTunnelRun({
				tunnelId,
				runId,
				mode: "quick",
				port
			});
			runtime ??= await this.#host.currentRuntime.get() ?? await this.#host.currentRuntime.markStarted();
			await this.#host.currentRuntime.assertActive(runtime);
			await this.#host.currentLifetime.assertCurrent(lifetime);
		} catch (error) {
			throw translateTunnelInterruption(error, "runtime_ready", "unknown") ?? error;
		}
		const { run } = ensureResult;
		if (!run.url || !run.hostname) throw new Error("Quick tunnel run did not produce a public URL");
		const spawned = {
			id: run.tunnelId,
			port: run.port,
			url: run.url,
			hostname: run.hostname,
			createdAt: run.startedAt
		};
		await this.#host.storage.transaction(async (txn) => {
			const nextMap = await readMap(txn);
			nextMap[port.toString()] = spawned;
			await txn.put(STORAGE_KEY, nextMap);
			const nextMeta = await readMetaMap(txn);
			nextMeta[port.toString()] = {
				optionsHash: "v1:quick",
				runtimeIdentityID: runtime.id,
				sandboxLifetimeID: lifetime.id,
				tunnelRunId: run.runId
			};
			await txn.put(META_STORAGE_KEY, nextMeta);
		});
		try {
			await this.#host.currentRuntime.assertActive(runtime);
			await this.#host.currentLifetime.assertCurrent(lifetime);
		} catch (error) {
			throw translateTunnelInterruption(error, "storage_committed", true) ?? error;
		}
		return spawned;
	}
	/**
	* Provision a named tunnel end-to-end:
	*   1. resolve credentials + zone name
	*   2. reuse or create the Cloudflare tunnel resource
	*   3. upsert the proxied CNAME (or reuse a matching one)
	*   4. spawn cloudflared inside the container
	*   5. persist the record + meta
	*
	* Failure between (2) and (5) intentionally leaves the Cloudflare-side
	* resources in place so a retry can re-discover them via
	* `findTunnelByName` and the DNS reuse path. See
	* `.plans/09-named-tunnel-api.md § Retry-friendly failure model`.
	*/
	async #provisionNamedTunnel(port, name) {
		if (!this.#host.sandboxId) throw new Error("Named tunnels require host.sandboxId on the tunnels handler.");
		if (!this.#host.getNamedTunnelConfig) throw new Error("Named tunnels require host.getNamedTunnelConfig on the tunnels handler.");
		const config = await this.#host.getNamedTunnelConfig();
		const hostname = `${name}.${await this.#getZoneName({
			token: config.token,
			zoneId: config.zoneId
		})}`;
		const sandboxId = this.#host.sandboxId;
		const tunnelName = `sandbox-${sandboxId}-${name}`;
		let tunnelId;
		let tunnelToken;
		const existingTunnel = await findTunnelByName({
			token: config.token,
			accountId: config.accountId,
			tunnelName,
			expectedSandboxId: sandboxId,
			fetcher: this.#host.fetcher
		});
		if (existingTunnel) {
			tunnelId = existingTunnel.id;
			tunnelToken = await getTunnelToken({
				token: config.token,
				accountId: config.accountId,
				tunnelId,
				fetcher: this.#host.fetcher
			});
		} else {
			const created = await createTunnel({
				token: config.token,
				accountId: config.accountId,
				tunnelName,
				metadata: {
					sandboxId,
					createdBy: "sandbox-sdk",
					name,
					port
				},
				fetcher: this.#host.fetcher
			});
			tunnelId = created.id;
			tunnelToken = created.token;
		}
		const dnsResult = await upsertCNAME({
			token: config.token,
			zoneId: config.zoneId,
			hostname,
			cnameTarget: `${tunnelId}.cfargotunnel.com`,
			comment: `sandbox-${sandboxId}`,
			sandboxId,
			fetcher: this.#host.fetcher
		});
		await this.#host.client.tunnels.runNamedTunnel(tunnelId, tunnelToken, port);
		const info = {
			id: tunnelId,
			port,
			name,
			hostname,
			url: `https://${hostname}`,
			createdAt: (/* @__PURE__ */ new Date()).toISOString()
		};
		await this.#host.storage.transaction(async (txn) => {
			const nextMap = await readMap(txn);
			nextMap[port.toString()] = info;
			await txn.put(STORAGE_KEY, nextMap);
			const nextMeta = await readMetaMap(txn);
			nextMeta[port.toString()] = {
				optionsHash: computeOptionsHash({ name }),
				dnsRecordId: dnsResult.recordId,
				accountId: config.accountId,
				zoneId: config.zoneId
			};
			await txn.put(META_STORAGE_KEY, nextMeta);
		});
		return info;
	}
	async destroy(portOrInfo) {
		const port = typeof portOrInfo === "number" ? portOrInfo : portOrInfo.port;
		const startTime = Date.now();
		let outcome = "error";
		let caughtError;
		let tunnelId;
		try {
			await this.#withPortLock(port, async () => {
				const existing = (await readMap(this.#host.storage))[port.toString()];
				if (!existing) return;
				tunnelId = existing.id;
				const metaBefore = (await readMetaMap(this.#host.storage))[port.toString()];
				await this.#host.storage.transaction(async (txn) => {
					const current = await readMap(txn);
					delete current[port.toString()];
					await txn.put(STORAGE_KEY, current);
					const currentMeta = await readMetaMap(txn);
					delete currentMeta[port.toString()];
					await txn.put(META_STORAGE_KEY, currentMeta);
				});
				try {
					if (metaBefore?.tunnelRunId) await this.#host.client.tunnels.stopTunnelRun({
						tunnelId: existing.id,
						runId: metaBefore.tunnelRunId
					});
					else await this.#host.client.tunnels.destroyTunnel(existing.id);
				} catch (error) {
					if (isTunnelNotFoundError(error)) {} else if (metaBefore?.dnsRecordId) this.#host.logger.warn("tunnel.destroy: container tunnel cleanup failed", {
						port,
						tunnelId,
						error: error instanceof Error ? error.message : String(error)
					});
					else throw error;
				}
				if (!metaBefore?.dnsRecordId) return;
				if (!this.#host.getNamedTunnelConfig) return;
				let config;
				try {
					config = await this.#host.getNamedTunnelConfig();
				} catch (err) {
					this.#host.logger.warn("tunnel.destroy: skipping CF cleanup, credentials unavailable", {
						port,
						tunnelId,
						dnsRecordId: metaBefore.dnsRecordId,
						error: err instanceof Error ? err.message : String(err)
					});
					return;
				}
				const fetcher = this.#host.fetcher;
				const accountId = metaBefore.accountId ?? config.accountId;
				const zoneId = metaBefore.zoneId ?? config.zoneId;
				await Promise.allSettled([metaBefore.dnsRecordId ? deleteDNSRecord({
					token: config.token,
					zoneId,
					recordId: metaBefore.dnsRecordId,
					fetcher
				}).catch((err) => {
					this.#host.logger.warn("tunnel.destroy: dns delete failed", {
						port,
						tunnelId,
						recordId: metaBefore.dnsRecordId,
						zoneId,
						error: err instanceof Error ? err.message : String(err)
					});
				}) : Promise.resolve(), deleteTunnel({
					token: config.token,
					accountId,
					tunnelId: existing.id,
					fetcher
				}).catch((err) => {
					this.#host.logger.warn("tunnel.destroy: tunnel delete failed", {
						port,
						tunnelId,
						accountId,
						error: err instanceof Error ? err.message : String(err)
					});
				})]);
			});
			outcome = "success";
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.#host.logger, {
				event: "tunnel.destroy",
				outcome,
				port,
				tunnelId,
				durationMs: Date.now() - startTime,
				error: caughtError
			});
		}
	}
	async list() {
		const map = await readMap(this.#host.storage);
		return Object.values(map);
	}
};
/**
* Per-port serialization lock. Any operation that mutates the tunnel for
* a given port — get() on a cache miss, destroy(), the exit callback —
* queues behind the previous operation on the same port. Two
* consequences:
*
*   - get(8080) followed by destroy(8080) is well-ordered: the destroy
*     observes whatever the get just wrote, even though both yield to
*     external RPCs in the middle.
*   - Two concurrent get(8080) calls share the first call's record: the
*     second runs after the first writes storage and takes the hit branch
*     (so no double cloudflared spawn).
*
* The lock is a plain Promise chain keyed by port. `transaction()` on the
* storage write still matters for *cross-port* writes — a get(8080) and
* get(8081) running in parallel are independent here.
*/
function createPortLock() {
	const portLocks = /* @__PURE__ */ new Map();
	return (port, fn) => {
		const next = (portLocks.get(port) ?? Promise.resolve()).then(fn, fn);
		portLocks.set(port, next.catch(() => void 0));
		return next;
	};
}
function createTunnelsHandler(host) {
	const withPortLock = host.withPortLock ?? createPortLock();
	const tunnels = new TunnelsRpcTarget(host, withPortLock);
	const handleTunnelExit = async (id, port, exitCode, runId) => {
		const startTime = Date.now();
		let outcome = "error";
		let caughtError;
		try {
			await withPortLock(port, async () => {
				await host.storage.transaction(async (txn) => {
					const map = await readMap(txn);
					const existing = map[port.toString()];
					if (existing?.id !== id) return;
					const meta = await readMetaMap(txn);
					const metaEntry = meta[port.toString()];
					if (runId && metaEntry?.tunnelRunId && metaEntry.tunnelRunId !== runId) return;
					if (existing.name) {
						meta[port.toString()] = {
							...metaEntry,
							optionsHash: metaEntry?.optionsHash ?? `v1:named:${existing.name}`,
							needsRespawn: true
						};
						await txn.put(META_STORAGE_KEY, meta);
						return;
					}
					delete map[port.toString()];
					await txn.put(STORAGE_KEY, map);
					delete meta[port.toString()];
					await txn.put(META_STORAGE_KEY, meta);
				});
			});
			outcome = "success";
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(host.logger, {
				event: "tunnel.exit",
				outcome,
				port,
				tunnelId: id,
				exitCode: exitCode ?? void 0,
				durationMs: Date.now() - startTime,
				error: caughtError
			});
		}
	};
	/**
	* Iterate every stored tunnel and call `tunnels.destroy(port)` on it,
	* sequentially. Each `destroy()` already swallows container-side
	* TUNNEL_NOT_FOUND and best-effort-logs Cloudflare-side failures; we
	* wrap the call in catch-and-log here too so a transport-level error
	* on one port can't poison the rest of the teardown.
	*
	* Each port is processed sequentially: this caps the *number of
	* concurrent ports* in flight at one. Note that an individual
	* destroy() still fans the DNS-delete and tunnel-delete out via
	* `Promise.allSettled` internally — so "sequential" here means
	* "one port at a time", not "one Cloudflare API call at a time".
	* The handful of ports we expect in the common case makes the
	* trade-off cheap.
	*/
	const destroyAll = async () => {
		const map = await readMap(host.storage);
		const ports = Object.keys(map).map((p) => Number(p));
		for (const port of ports) try {
			await tunnels.destroy(port);
		} catch (err) {
			host.logger.warn("tunnels.destroyAll: destroy(port) failed", {
				port,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	};
	return {
		tunnels,
		handleTunnelExit,
		destroyAll
	};
}
/**
* SDK version - automatically synchronized with package.json by Changesets
* This file is auto-updated by .github/changeset-version.ts during releases
* DO NOT EDIT MANUALLY - Changes will be overwritten on the next version bump
*/
var SDK_VERSION = "0.12.14";
var PORT_TOKENS_STORAGE_KEY = "portTokens";
var ACTIVE_PREVIEW_PORTS_STORAGE_KEY = "activePreviewPorts";
var CONTAINER_PROXY_CLASS_NAME = "ContainerProxy";
var S3_CREDENTIAL_PROXY_HOST = "s3-credential-proxy.internal";
var S3_CREDENTIAL_PROXY_DIAGNOSTIC_HOST = "s3-credential-proxy.sandbox.test";
var SDK_OUTBOUND_HANDLERS = {
	r2EgressMount: r2EgressHandler,
	s3CredentialProxyMount: s3CredentialProxyHandler
};
var ContainerProxyOutboundTarget = class extends Container {};
Object.defineProperty(ContainerProxyOutboundTarget, "name", { value: CONTAINER_PROXY_CLASS_NAME });
ContainerProxyOutboundTarget.outboundHandlers = SDK_OUTBOUND_HANDLERS;
function noRestoredMountRoutes() {
	return {
		r2Buckets: {},
		credentialProxyMounts: {}
	};
}
/**
* Read the bucket mount routes that the base Container restored from storage
* in its constructor. `outboundByHostOverrides` is private in its types.
*/
function readRestoredMountRoutes(container) {
	const overrides = container.outboundByHostOverrides ?? {};
	const r2 = overrides["r2.internal"];
	const credentialProxy = overrides[S3_CREDENTIAL_PROXY_HOST];
	return {
		r2Buckets: r2?.method === "r2EgressMount" ? { ...r2.params?.buckets } : {},
		credentialProxyMounts: credentialProxy?.method === "s3CredentialProxyMount" ? { ...credentialProxy.params?.mounts } : {}
	};
}
function isFetcher(value) {
	return typeof value === "object" && value !== null && "fetch" in value && typeof value.fetch === "function";
}
var sandboxConfigurationCache = /* @__PURE__ */ new WeakMap();
var R2_DEFAULT_S3FS_OPTIONS = {
	stat_cache_expire: "60",
	enable_noobj_cache: true,
	multipart_size: "5"
};
var R2_DEFAULT_S3FS_OPTION_ENTRIES = Object.entries(R2_DEFAULT_S3FS_OPTIONS).map(([key, value]) => value === true ? key : `${key}=${value}`);
var S3FS_DISABLE_EXPECT_HEADER_CONFIG = " Expect:\n";
var BACKUP_DEFAULT_TTL_SECONDS = 259200;
/**
* Instance-get budget (ms) for the RPC transport's explicit container-start
* hook, independent of the user-facing `containerTimeouts.instanceGetTimeoutMS`
* (which still governs the HTTP path's `containerFetch`).
*
* Shorter than the SDK's user-facing 30s default, but long enough to match
* the Containers platform's own 8s instance-get default. This keeps one RPC
* start attempt from burning the full 30s under capacity pressure while still
* letting ordinary 4-8s cold provisions succeed on the first attempt instead
* of always paying the first backoff delay. The RPC control connection's own
* retry loop (`fetchWithResponseRetry`, ~2 min budget with exponential
* backoff) still owns cross-attempt retries. Once an instance exists,
* `portReadyTimeoutMS` still governs app boot on the next attempt (the base
* fast-path returns immediately when the container is already running).
*/
var RPC_START_INSTANCE_GET_TIMEOUT_MS = 8e3;
var BACKUP_MAX_NAME_LENGTH = 256;
var BACKUP_CONTAINER_DIR = "/var/backups";
var BACKUP_STORAGE_PREFIX = "backups";
var BACKUP_ARCHIVE_OBJECT_NAME = "data.sqsh";
var BACKUP_METADATA_OBJECT_NAME = "meta.json";
var BACKUP_DEFAULT_COMPRESSION = "lz4";
var BACKUP_DEFAULT_COMPRESS_THREADS = 8;
var BACKUP_MULTIPART_MIN_SIZE = 10485760;
var BACKUP_MULTIPART_TARGET_PARTS = 16;
var BACKUP_MULTIPART_MIN_PART_SIZE = 5242880;
var BACKUP_MULTIPART_MAX_PARTS = 64;
var BACKUP_DOWNLOAD_PARALLEL_PARTS = 8;
var BACKUP_DOWNLOAD_PARALLEL_MIN_SIZE = 10485760;
var BACKUP_DOWNLOAD_MAX_PARTS = 64;
/**
* Calculate the optimal number of parts for multipart upload/download
* based on archive size. Larger archives benefit from more parallelism.
*/
function calculatePartCount(sizeBytes, defaultParts, maxParts) {
	if (sizeBytes < 104857600) return defaultParts;
	if (sizeBytes < 1073741824) return Math.min(32, defaultParts * 2);
	return maxParts;
}
/**
* Tagged template literal that shell-escapes every interpolated value.
* Use for composing in-container scripts where the template body is
* trusted shell and the interpolations are untrusted strings.
*/
function sh(strings, ...values) {
	let out = strings[0];
	for (let i = 0; i < values.length; i++) out += shellEscape(String(values[i])) + strings[i + 1];
	return out;
}
/**
* Hex string of `bytes` random bytes (length = bytes * 2). Used for short
* non-cryptographic identifiers — e.g. tempfile suffixes.
*/
function randomHex(bytes) {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}
/**
* Parse an array of `key=value` / bare-flag s3fs options into a Record.
* Bare flags become `{ flag: true }`. Later entries overwrite earlier ones.
*/
function parseS3fsOptions(entries) {
	const result = {};
	for (const entry of entries) {
		const eq = entry.indexOf("=");
		if (eq === -1) result[entry] = true;
		else result[entry.slice(0, eq)] = entry.slice(eq + 1);
	}
	return result;
}
/**
* Serialise an s3fs options Record into the comma-separated `-o` argument.
* Boolean true emits the bare flag; false drops it.
*/
function serializeS3fsOptions(options) {
	return Object.entries(options).filter(([, v]) => v !== false).map(([k, v]) => v === true ? k : `${k}=${v}`).join(",");
}
function getNamespaceConfigurationCache(namespace) {
	const existing = sandboxConfigurationCache.get(namespace);
	if (existing) return existing;
	const created = /* @__PURE__ */ new Map();
	sandboxConfigurationCache.set(namespace, created);
	return created;
}
function sameContainerTimeouts(left, right) {
	return left?.instanceGetTimeoutMS === right?.instanceGetTimeoutMS && left?.portReadyTimeoutMS === right?.portReadyTimeoutMS && left?.waitIntervalMS === right?.waitIntervalMS;
}
function sameLabels(left, right) {
	if (left === right) return true;
	if (!left || !right) return false;
	const leftEntries = Object.entries(left);
	const rightEntries = Object.entries(right);
	if (leftEntries.length !== rightEntries.length) return false;
	for (const [key, value] of leftEntries) if (right[key] !== value) return false;
	return true;
}
function cloneLabels(labels) {
	return { ...labels };
}
function buildSandboxConfiguration(effectiveId, options, cached) {
	const configuration = {};
	if (cached?.sandboxName !== effectiveId || cached.normalizeId !== options?.normalizeId) configuration.sandboxName = {
		name: effectiveId,
		normalizeId: options?.normalizeId
	};
	if (options?.sleepAfter !== void 0 && cached?.sleepAfter !== options.sleepAfter) configuration.sleepAfter = options.sleepAfter;
	if (options?.keepAlive !== void 0 && cached?.keepAlive !== options.keepAlive) configuration.keepAlive = options.keepAlive;
	if (options?.containerTimeouts && !sameContainerTimeouts(cached?.containerTimeouts, options.containerTimeouts)) configuration.containerTimeouts = options.containerTimeouts;
	if (options?.transport !== void 0 && cached?.transport !== options.transport) configuration.transport = options.transport;
	if (options?.labels !== void 0 && !sameLabels(cached?.labels, options.labels)) configuration.labels = cloneLabels(options.labels);
	return configuration;
}
function hasSandboxConfiguration(configuration) {
	return configuration.sandboxName !== void 0 || configuration.sleepAfter !== void 0 || configuration.keepAlive !== void 0 || configuration.containerTimeouts !== void 0 || configuration.transport !== void 0 || configuration.labels !== void 0;
}
function mergeSandboxConfiguration(cached, configuration) {
	return {
		...cached,
		...configuration.sandboxName && {
			sandboxName: configuration.sandboxName.name,
			normalizeId: configuration.sandboxName.normalizeId
		},
		...configuration.sleepAfter !== void 0 && { sleepAfter: configuration.sleepAfter },
		...configuration.keepAlive !== void 0 && { keepAlive: configuration.keepAlive },
		...configuration.containerTimeouts !== void 0 && { containerTimeouts: configuration.containerTimeouts },
		...configuration.transport !== void 0 && { transport: configuration.transport },
		...configuration.labels !== void 0 && { labels: cloneLabels(configuration.labels) }
	};
}
function applySandboxConfiguration(stub, configuration) {
	if (stub.configure) return stub.configure(configuration);
	const operations = [];
	if (configuration.sandboxName) operations.push(stub.setSandboxName?.(configuration.sandboxName.name, configuration.sandboxName.normalizeId) ?? Promise.resolve());
	if (configuration.sleepAfter !== void 0) operations.push(stub.setSleepAfter?.(configuration.sleepAfter) ?? Promise.resolve());
	if (configuration.keepAlive !== void 0) operations.push(stub.setKeepAlive?.(configuration.keepAlive) ?? Promise.resolve());
	if (configuration.containerTimeouts !== void 0) operations.push(stub.setContainerTimeouts?.(configuration.containerTimeouts) ?? Promise.resolve());
	if (configuration.transport !== void 0) operations.push(stub.setTransport?.(configuration.transport) ?? Promise.resolve());
	if (configuration.labels !== void 0) operations.push(stub.setLabels?.(configuration.labels) ?? Promise.resolve());
	return Promise.all(operations).then(() => void 0);
}
function createPlatformInterruptedError(error, operation) {
	if (!isPlatformTransientError(error)) return null;
	const context = {
		reason: "runtime_replaced",
		operation,
		phase: "durable_object_call",
		admitted: "unknown",
		retryable: false
	};
	return new OperationInterruptedError({
		code: ErrorCode.OPERATION_INTERRUPTED,
		message: `Sandbox operation ${operation} was interrupted while the platform was updating the sandbox runtime`,
		context,
		httpStatus: getHttpStatus(ErrorCode.OPERATION_INTERRUPTED),
		suggestion: getSuggestion(ErrorCode.OPERATION_INTERRUPTED, context),
		timestamp: (/* @__PURE__ */ new Date()).toISOString()
	}, { cause: error });
}
function translatePlatformInterruption(error, operation) {
	throw createPlatformInterruptedError(error, operation) ?? error;
}
function withSandboxOperationContext(operation, fn) {
	return (...args) => {
		try {
			const result = fn(...args);
			if (result != null && typeof result.then === "function") return result.catch((error) => translatePlatformInterruption(error, operation));
			return result;
		} catch (error) {
			translatePlatformInterruption(error, operation);
		}
	};
}
function getSandbox(ns, id, options) {
	const sanitizedId = sanitizeSandboxId(id);
	const effectiveId = options?.normalizeId ? sanitizedId.toLowerCase() : sanitizedId;
	const hasUppercase = /[A-Z]/.test(sanitizedId);
	if (!options?.normalizeId && hasUppercase) createLogger({ component: "sandbox-do" }).warn(`Sandbox ID "${sanitizedId}" contains uppercase letters, which causes issues with preview URLs (hostnames are case-insensitive). normalizeId will default to true in a future version to prevent this. Use lowercase IDs or pass { normalizeId: true } to prepare.`);
	const stub = getContainer(ns, effectiveId);
	const namespaceCache = getNamespaceConfigurationCache(ns);
	const cachedConfiguration = namespaceCache.get(effectiveId);
	const configuration = buildSandboxConfiguration(effectiveId, options, cachedConfiguration);
	if (hasSandboxConfiguration(configuration)) {
		const nextConfiguration = mergeSandboxConfiguration(cachedConfiguration, configuration);
		namespaceCache.set(effectiveId, nextConfiguration);
		applySandboxConfiguration(stub, configuration).catch(() => {
			if (cachedConfiguration) {
				namespaceCache.set(effectiveId, cachedConfiguration);
				return;
			}
			namespaceCache.delete(effectiveId);
		});
	}
	const defaultSessionId = `sandbox-${effectiveId}`;
	const useDefaultSession = options?.enableDefaultSession !== false;
	const enhancedMethods = {
		fetch: (request) => stub.fetch(request),
		exec: (command, execOptions) => useDefaultSession ? stub.exec(command, execOptions) : stub.execWithSessionToken(command, DISABLE_SESSION_TOKEN, execOptions),
		startProcess: (command, processOptions) => useDefaultSession || processOptions?.sessionId !== void 0 ? stub.startProcess(command, processOptions) : stub.startProcess(command, {
			...processOptions,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		listProcesses: (sessionId) => useDefaultSession || sessionId !== void 0 ? stub.listProcesses(sessionId) : stub.listProcesses(DISABLE_SESSION_TOKEN),
		getProcess: (id$1, sessionId) => useDefaultSession || sessionId !== void 0 ? stub.getProcess(id$1, sessionId) : stub.getProcess(id$1, DISABLE_SESSION_TOKEN),
		execStream: (command, streamOptions) => {
			if (useDefaultSession || streamOptions?.sessionId !== void 0) return stub.execStream(command, streamOptions);
			return stub.execStreamWithSessionToken(command, DISABLE_SESSION_TOKEN, streamOptions);
		},
		writeFile: (path$1, content, fileOptions = {}) => useDefaultSession || fileOptions.sessionId !== void 0 ? stub.writeFile(path$1, content, fileOptions) : stub.writeFile(path$1, content, {
			...fileOptions,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		readFile: (path$1, fileOptions = {}) => {
			const options$1 = useDefaultSession || fileOptions.sessionId !== void 0 ? fileOptions : {
				...fileOptions,
				sessionId: DISABLE_SESSION_TOKEN
			};
			if (options$1.encoding === "none") return stub.readFile(path$1, options$1);
			return stub.readFile(path$1, options$1);
		},
		readFileStream: (path$1, fileOptions = {}) => useDefaultSession || fileOptions.sessionId !== void 0 ? stub.readFileStream(path$1, fileOptions) : stub.readFileStream(path$1, { sessionId: DISABLE_SESSION_TOKEN }),
		mkdir: (path$1, mkdirOptions = {}) => useDefaultSession || mkdirOptions.sessionId !== void 0 ? stub.mkdir(path$1, mkdirOptions) : stub.mkdir(path$1, {
			...mkdirOptions,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		deleteFile: (path$1) => useDefaultSession ? stub.deleteFile(path$1) : stub.deleteFile(path$1, DISABLE_SESSION_TOKEN),
		renameFile: (oldPath, newPath) => useDefaultSession ? stub.renameFile(oldPath, newPath) : stub.renameFile(oldPath, newPath, DISABLE_SESSION_TOKEN),
		moveFile: (sourcePath, destinationPath) => useDefaultSession ? stub.moveFile(sourcePath, destinationPath) : stub.moveFile(sourcePath, destinationPath, DISABLE_SESSION_TOKEN),
		listFiles: (path$1, listOptions) => useDefaultSession || listOptions?.sessionId !== void 0 ? stub.listFiles(path$1, listOptions) : stub.listFiles(path$1, {
			...listOptions,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		exists: (path$1, sessionId) => useDefaultSession || sessionId !== void 0 ? stub.exists(path$1, sessionId) : stub.exists(path$1, DISABLE_SESSION_TOKEN),
		gitCheckout: (repoUrl, gitOptions) => useDefaultSession || gitOptions?.sessionId !== void 0 ? stub.gitCheckout(repoUrl, gitOptions) : stub.gitCheckout(repoUrl, {
			...gitOptions,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		createSession: async (opts) => {
			return enhanceSession(stub, await stub.createSession(opts));
		},
		getSession: async (sessionId) => {
			return enhanceSession(stub, await stub.getSession(sessionId));
		},
		watch: (path$1, options$1 = {}) => useDefaultSession || options$1.sessionId !== void 0 ? stub.watch(path$1, options$1) : stub.watch(path$1, {
			...options$1,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		checkChanges: (path$1, options$1 = {}) => useDefaultSession || options$1.sessionId !== void 0 ? stub.checkChanges(path$1, options$1) : stub.checkChanges(path$1, {
			...options$1,
			sessionId: DISABLE_SESSION_TOKEN
		}),
		terminal: (request, opts) => proxyTerminal(stub, defaultSessionId, request, opts),
		wsConnect: connect(stub),
		tunnels: new Proxy({}, { get: (_, method) => {
			if (typeof method !== "string" || method === "then") return void 0;
			return withSandboxOperationContext(`sandbox.tunnels.${method}`, (...args) => stub.callTunnels(method, args));
		} })
	};
	return new Proxy(stub, { get(target, prop) {
		if (typeof prop === "string" && prop in enhancedMethods) {
			const method = enhancedMethods[prop];
			if (typeof method === "function") return withSandboxOperationContext(`sandbox.${prop}`, method);
			return method;
		}
		return target[prop];
	} });
}
function enhanceSession(stub, rpcSession) {
	return {
		...rpcSession,
		terminal: (request, opts) => proxyTerminal(stub, rpcSession.id, request, opts)
	};
}
function connect(stub) {
	return async (request, port) => {
		if (!validatePort(port)) throw new SandboxSecurityError(`Invalid port number: ${port}. Must be 1024-65535, excluding 3000 (sandbox control plane).`);
		const portSwitchedRequest = switchPort(request, port);
		return await stub.fetch(portSwitchedRequest);
	};
}
var Sandbox = class Sandbox extends Container {
	defaultPort = 3e3;
	sleepAfter = "10m";
	client;
	codeInterpreter;
	sandboxName = null;
	tunnelsHandler = null;
	tunnelExitHandler = null;
	destroyAllTunnels = null;
	tunnelPortLock = createPortLock();
	controlCallback;
	normalizeId = false;
	defaultSession = null;
	containerGeneration = 0;
	defaultSessionInit = null;
	envVars = {};
	logger;
	keepAliveEnabled = false;
	activeMounts = /* @__PURE__ */ new Map();
	restoredMountRoutes = noRestoredMountRoutes();
	staleMountRoutes = {
		r2: false,
		credentialProxy: false
	};
	mountOperationQueue = Promise.resolve();
	currentRuntime;
	currentLifetime;
	transport = "http";
	/**
	* True once transport has been written to storage at least once (either
	* via setTransport or restored on cold start). Gates the idempotency
	* check so a first explicit call persists even when the requested value
	* already equals the env-derived in-memory default.
	*/
	hasStoredTransport = false;
	backupBucket = null;
	/**
	* Serializes backup operations to prevent concurrent create/restore on the same sandbox.
	*
	* This is in-memory state — it resets if the Durable Object is evicted and
	* re-instantiated (e.g. after sleep). This is acceptable because the container
	* filesystem is also lost on eviction, so there is no archive to race on.
	*/
	backupInProgress = Promise.resolve();
	/**
	* R2 presigned URL credentials for direct container-to-R2 transfers.
	* All four fields plus the R2 binding must be configured for backup to work.
	*/
	r2AccessKeyId = null;
	r2SecretAccessKey = null;
	r2AccountId = null;
	backupBucketName = null;
	backupBucketEndpoint = null;
	r2Client = null;
	/**
	* Lazily-resolved Cloudflare account id for named-tunnel provisioning.
	* Resolved on first access via `tunnels/credentials.ts` and cached for
	* the lifetime of this DO instance. See the credentials helper for
	* the precedence chain.
	*/
	tunnelAccountIdPromise = null;
	/**
	* Lazily-resolved Cloudflare zone id for named-tunnel provisioning.
	* Falls back to the single zone the token can see under the resolved
	* account id when `CLOUDFLARE_ZONE_ID` is not set. Cached for the
	* lifetime of this DO instance.
	*/
	tunnelZoneIdPromise = null;
	/**
	* Default container startup timeouts (conservative for production)
	* Based on Cloudflare docs: "Containers take several minutes to provision"
	*/
	DEFAULT_CONTAINER_TIMEOUTS = {
		instanceGetTimeoutMS: 3e4,
		portReadyTimeoutMS: 9e4,
		waitIntervalMS: 300
	};
	/**
	* Active container timeout configuration
	* Can be set via options, env vars, or defaults
	*/
	containerTimeouts = { ...this.DEFAULT_CONTAINER_TIMEOUTS };
	/**
	* True once containerTimeouts has been written to storage at least once
	* (either via setContainerTimeouts or restored on cold start). Gates the
	* idempotency check in setContainerTimeouts so a first explicit call
	* persists even when the requested values already equal the in-memory
	* defaults, distinguishing "user intent recorded" from "running on
	* env/SDK defaults".
	*/
	hasStoredContainerTimeouts = false;
	/**
	* Dispatch method for tunnel operations.
	* Called by the client-side proxy created in getSandbox() to provide
	* the `sandbox.tunnels` API without relying on RPC pipelining
	* through property getters which is broken when using vite-plugin.
	*/
	async callTunnels(method, args) {
		if (![
			"get",
			"list",
			"destroy"
		].includes(method)) throw new Error(`Unknown tunnels method: ${method}`);
		const client = this.tunnels;
		const fn = client[method];
		if (typeof fn !== "function") throw new Error(`sandbox.tunnels missing method: ${method}`);
		return fn.apply(client, args);
	}
	/**
	* Compute the transport retry budget from current container timeouts.
	*
	* The budget covers the full container startup window (instance provisioning
	* + port readiness) plus a 30s margin for the maximum single backoff delay
	* (capped at 30s in BaseTransport). The 120s floor preserves the previous
	* default for short timeout configurations.
	*/
	computeRetryTimeoutMs() {
		const startupBudgetMs = this.containerTimeouts.instanceGetTimeoutMS + this.containerTimeouts.portReadyTimeoutMS;
		return Math.max(12e4, startupBudgetMs + 3e4);
	}
	/**
	* Create the route-based compatibility client with current HTTP/WebSocket
	* transport settings.
	*/
	createSandboxClient() {
		return new SandboxClient({
			logger: this.logger,
			port: 3e3,
			stub: this,
			retryTimeoutMs: this.computeRetryTimeoutMs(),
			defaultHeaders: { "X-Sandbox-Id": this.ctx.id.toString() },
			...this.transport === "websocket" && {
				transportMode: "websocket",
				wsUrl: "ws://localhost:3000/ws"
			}
		});
	}
	/**
	* Create the appropriate client for the configured control path.
	*
	* `rpc` currently selects the primary container-control client. `http` and
	* `websocket` select the route-based compatibility client.
	*/
	createClientForTransport(transport) {
		if (transport === "rpc") {
			const self = this;
			return new ContainerControlClient({
				stub: this,
				port: 3e3,
				logger: this.logger,
				retryTimeoutMs: this.computeRetryTimeoutMs(),
				getSandboxInfo: () => ({
					id: this.ctx.id.toString(),
					name: this.sandboxName ?? void 0
				}),
				startContainer: () => this.startContainerForRPC(),
				localMain: this.controlCallback,
				onActivity: () => {
					this.renewActivityTimeout();
				},
				onSessionBusy: () => {
					self.inflightRequests++;
				},
				onSessionIdle: () => {
					self.inflightRequests = Math.max(0, self.inflightRequests - 1);
					if (self.inflightRequests === 0) this.renewActivityTimeout();
				}
			});
		}
		return this.createSandboxClient();
	}
	constructor(ctx, env$1) {
		if (ctx.exports?.ContainerProxy) {
			const registry = new.target;
			registry.outboundHandlers = {
				...registry.outboundHandlers,
				...SDK_OUTBOUND_HANDLERS
			};
		}
		super(ctx, env$1);
		this.restoredMountRoutes = readRestoredMountRoutes(this);
		const envObj = env$1;
		["SANDBOX_LOG_LEVEL", "SANDBOX_LOG_FORMAT"].forEach((key) => {
			if (envObj?.[key]) this.envVars[key] = String(envObj[key]);
		});
		this.containerTimeouts = this.getDefaultTimeouts(envObj);
		this.logger = createLogger({
			component: "sandbox-do",
			sandboxId: this.ctx.id.toString()
		});
		this.currentRuntime = new CurrentRuntimeIdentity(this.ctx.storage, () => this.getState(), () => this.ctx.container?.running === true);
		this.currentLifetime = new CurrentSandboxLifetime(this.ctx.storage);
		const transportEnv = envObj?.SANDBOX_TRANSPORT;
		if (transportEnv === "websocket" || transportEnv === "rpc") this.transport = transportEnv;
		else if (transportEnv != null && transportEnv !== "http") this.logger.warn(`Invalid SANDBOX_TRANSPORT value: "${transportEnv}". Must be "http", "websocket", or "rpc". Defaulting to "http".`);
		this.logger.info(`Using ${this.transport} transport`);
		const backupBucket = envObj?.BACKUP_BUCKET;
		if (isR2Bucket(backupBucket)) this.backupBucket = backupBucket;
		this.r2AccountId = getEnvString(envObj, "CLOUDFLARE_R2_ACCOUNT_ID") ?? getEnvString(envObj, "CLOUDFLARE_ACCOUNT_ID") ?? null;
		this.r2AccessKeyId = getEnvString(envObj, "R2_ACCESS_KEY_ID") ?? null;
		this.r2SecretAccessKey = getEnvString(envObj, "R2_SECRET_ACCESS_KEY") ?? null;
		this.backupBucketName = getEnvString(envObj, "BACKUP_BUCKET_NAME") ?? null;
		const rawEndpoint = getEnvString(envObj, "BACKUP_BUCKET_ENDPOINT") ?? null;
		if (rawEndpoint !== null) {
			let parsed;
			try {
				parsed = new URL(rawEndpoint);
			} catch {
				const msg = `BACKUP_BUCKET_ENDPOINT is not a valid URL: "${rawEndpoint}". Expected format: https://<account_id>.eu.r2.cloudflarestorage.com`;
				throw new InvalidBackupConfigError({
					message: msg,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: msg },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			if (parsed.protocol !== "https:") {
				const msg = `BACKUP_BUCKET_ENDPOINT must use https://, got "${parsed.protocol.slice(0, -1)}://"`;
				throw new InvalidBackupConfigError({
					message: msg,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: msg },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			if (parsed.pathname !== "/") {
				const msg = `BACKUP_BUCKET_ENDPOINT must not include a path (got "${parsed.pathname}"). Provide only the origin, e.g. https://<account_id>.eu.r2.cloudflarestorage.com`;
				throw new InvalidBackupConfigError({
					message: msg,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: msg },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			if (parsed.search !== "" || parsed.hash !== "") {
				const msg = "BACKUP_BUCKET_ENDPOINT must not include query parameters or fragments. Provide only the origin, e.g. https://<account_id>.eu.r2.cloudflarestorage.com";
				throw new InvalidBackupConfigError({
					message: msg,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: msg },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			this.backupBucketEndpoint = parsed.origin;
		} else this.backupBucketEndpoint = null;
		if (this.r2AccessKeyId && this.r2SecretAccessKey) this.r2Client = new AwsClient({
			accessKeyId: this.r2AccessKeyId,
			secretAccessKey: this.r2SecretAccessKey
		});
		this.controlCallback = new SandboxControlCallbackImpl(() => this.tunnelExitHandler, this.logger);
		this.client = this.createClientForTransport(this.transport);
		this.codeInterpreter = new CodeInterpreter(() => this.client.interpreter);
		this.ctx.blockConcurrencyWhile(async () => {
			this.sandboxName = await this.ctx.storage.get("sandboxName") ?? null;
			this.normalizeId = await this.ctx.storage.get("normalizeId") ?? false;
			this.defaultSession = await this.ctx.storage.get("defaultSession") ?? null;
			this.keepAliveEnabled = await this.ctx.storage.get("keepAliveEnabled") ?? false;
			const storedTimeouts = await this.ctx.storage.get("containerTimeouts");
			if (storedTimeouts) {
				this.containerTimeouts = {
					...this.containerTimeouts,
					...storedTimeouts
				};
				this.hasStoredContainerTimeouts = true;
				this.client.setRetryTimeoutMs(this.computeRetryTimeoutMs());
			}
			const storedSleepAfter = await this.ctx.storage.get("sleepAfter");
			if (storedSleepAfter !== void 0) {
				this.sleepAfter = storedSleepAfter;
				this.renewActivityTimeout();
			}
			const storedTransport = await this.ctx.storage.get("transport");
			if (storedTransport && storedTransport !== this.transport) {
				this.transport = storedTransport;
				const previousClient = this.client;
				this.client = this.createClientForTransport(storedTransport);
				this.codeInterpreter = new CodeInterpreter(() => this.client.interpreter);
				this.tunnelsHandler = null;
				this.tunnelExitHandler = null;
				this.destroyAllTunnels = null;
				previousClient.disconnect(this.buildDisconnectCause("runtime_replaced", "The sandbox transport was switched while the operation was pending."));
			}
			if (storedTransport) this.hasStoredTransport = true;
			const storedLabels = await this.ctx.storage.get("labels");
			if (storedLabels !== void 0 && storedLabels !== null) this.labels = cloneLabels(storedLabels);
			if (this.interceptHttps) this.envVars = {
				...this.envVars,
				SANDBOX_INTERCEPT_HTTPS: "1"
			};
		});
	}
	async setSandboxName(name, normalizeId) {
		if (this.sandboxName !== null) return;
		const effectiveNormalizeId = normalizeId ?? false;
		await Promise.all([this.ctx.storage.put("sandboxName", name), this.ctx.storage.put("normalizeId", effectiveNormalizeId)]);
		this.sandboxName = name;
		this.normalizeId = effectiveNormalizeId;
	}
	async configure(configuration) {
		if (configuration.sandboxName) await this.setSandboxName(configuration.sandboxName.name, configuration.sandboxName.normalizeId);
		if (configuration.sleepAfter !== void 0) await this.setSleepAfter(configuration.sleepAfter);
		if (configuration.keepAlive !== void 0) await this.setKeepAlive(configuration.keepAlive);
		if (configuration.containerTimeouts !== void 0) await this.setContainerTimeouts(configuration.containerTimeouts);
		if (configuration.transport !== void 0) await this.setTransport(configuration.transport);
		if (configuration.labels !== void 0) await this.setLabels(configuration.labels);
	}
	async setSleepAfter(sleepAfter) {
		if (this.sleepAfter === sleepAfter) return;
		await this.ctx.storage.put("sleepAfter", sleepAfter);
		this.sleepAfter = sleepAfter;
		this.renewActivityTimeout();
	}
	async setKeepAlive(keepAlive) {
		if (this.keepAliveEnabled === keepAlive) return;
		await this.ctx.storage.put("keepAliveEnabled", keepAlive);
		this.keepAliveEnabled = keepAlive;
		if (!keepAlive) this.renewActivityTimeout();
	}
	async setEnvVars(envVars) {
		const { toSet, toUnset } = partitionEnvVars(envVars);
		for (const key of toUnset) delete this.envVars[key];
		this.envVars = {
			...this.envVars,
			...toSet
		};
		if (this.defaultSession) {
			for (const key of toUnset) {
				const unsetCommand = `unset ${key}`;
				const result = await this.client.commands.execute(unsetCommand, this.defaultSession, { origin: "internal" });
				if (result.exitCode !== 0) throw new Error(`Failed to unset ${key}: ${result.stderr || "Unknown error"}`);
			}
			for (const [key, value] of Object.entries(toSet)) {
				const exportCommand = `export ${key}=${shellEscape(value)}`;
				const result = await this.client.commands.execute(exportCommand, this.defaultSession, { origin: "internal" });
				if (result.exitCode !== 0) throw new Error(`Failed to set ${key}: ${result.stderr || "Unknown error"}`);
			}
		}
	}
	async setContainerTimeouts(timeouts) {
		const validated = { ...this.containerTimeouts };
		if (timeouts.instanceGetTimeoutMS !== void 0) validated.instanceGetTimeoutMS = this.validateTimeout(timeouts.instanceGetTimeoutMS, "instanceGetTimeoutMS", 5e3, 3e5);
		if (timeouts.portReadyTimeoutMS !== void 0) validated.portReadyTimeoutMS = this.validateTimeout(timeouts.portReadyTimeoutMS, "portReadyTimeoutMS", 1e4, 6e5);
		if (timeouts.waitIntervalMS !== void 0) validated.waitIntervalMS = this.validateTimeout(timeouts.waitIntervalMS, "waitIntervalMS", 100, 5e3);
		if (this.hasStoredContainerTimeouts && validated.instanceGetTimeoutMS === this.containerTimeouts.instanceGetTimeoutMS && validated.portReadyTimeoutMS === this.containerTimeouts.portReadyTimeoutMS && validated.waitIntervalMS === this.containerTimeouts.waitIntervalMS) return;
		await this.ctx.storage.put("containerTimeouts", validated);
		this.containerTimeouts = validated;
		this.hasStoredContainerTimeouts = true;
		this.client.setRetryTimeoutMs(this.computeRetryTimeoutMs());
		this.logger.debug("Container timeouts updated", this.containerTimeouts);
	}
	async setTransport(transport) {
		if (transport !== "http" && transport !== "websocket" && transport !== "rpc") {
			this.logger.warn(`Invalid transport value: "${transport}". Must be "http", "websocket", or "rpc". Ignoring.`);
			return;
		}
		if (this.hasStoredTransport && this.transport === transport) return;
		await this.ctx.storage.put("transport", transport);
		const previousClient = this.client;
		this.transport = transport;
		this.hasStoredTransport = true;
		this.client = this.createClientForTransport(transport);
		this.codeInterpreter = new CodeInterpreter(() => this.client.interpreter);
		this.tunnelsHandler = null;
		this.tunnelExitHandler = null;
		this.destroyAllTunnels = null;
		previousClient.disconnect(this.buildDisconnectCause("runtime_replaced", "The sandbox transport was switched while the operation was pending."));
		this.renewActivityTimeout();
		this.logger.debug("Transport updated", { transport });
	}
	async setLabels(labels) {
		const nextLabels = cloneLabels(labels);
		if (sameLabels(this.labels, nextLabels)) return;
		await this.ctx.storage.put("labels", nextLabels);
		this.labels = nextLabels;
		if (this.ctx.container?.running === true) this.logger.warn("Container labels updated while container is running; new labels apply on the next container start");
	}
	validateTimeout(value, name, min, max) {
		if (typeof value !== "number" || Number.isNaN(value) || !Number.isFinite(value)) throw new Error(`${name} must be a valid finite number, got ${value}`);
		if (value < min || value > max) throw new Error(`${name} must be between ${min}-${max}ms, got ${value}ms`);
		return value;
	}
	getDefaultTimeouts(env$1) {
		const parseAndValidate = (envVar, name, min, max) => {
			const defaultValue = this.DEFAULT_CONTAINER_TIMEOUTS[name];
			if (envVar === void 0) return defaultValue;
			const parsed = parseInt(envVar, 10);
			if (Number.isNaN(parsed)) {
				this.logger.warn(`Invalid ${name}: "${envVar}" is not a number. Using default: ${defaultValue}ms`);
				return defaultValue;
			}
			if (parsed < min || parsed > max) {
				this.logger.warn(`Invalid ${name}: ${parsed}ms. Must be ${min}-${max}ms. Using default: ${defaultValue}ms`);
				return defaultValue;
			}
			return parsed;
		};
		return {
			instanceGetTimeoutMS: parseAndValidate(getEnvString(env$1, "SANDBOX_INSTANCE_TIMEOUT_MS"), "instanceGetTimeoutMS", 5e3, 3e5),
			portReadyTimeoutMS: parseAndValidate(getEnvString(env$1, "SANDBOX_PORT_TIMEOUT_MS"), "portReadyTimeoutMS", 1e4, 6e5),
			waitIntervalMS: parseAndValidate(getEnvString(env$1, "SANDBOX_POLL_INTERVAL_MS"), "waitIntervalMS", 100, 5e3)
		};
	}
	/**
	* Mount an S3-compatible bucket as a local directory.
	*
	* Requires explicit endpoint URL for production. Credentials are auto-detected from environment
	* variables or can be provided explicitly.
	*
	* @param bucket - Bucket name (or R2 binding name when localBucket is true)
	* @param mountPath - Absolute path in container to mount at
	* @param options - Mount configuration
	* @throws MissingCredentialsError if no credentials found in environment
	* @throws S3FSMountError if S3FS mount command fails
	* @throws InvalidMountConfigError if bucket name, mount path, or endpoint is invalid
	*/
	async mountBucket(bucket, mountPath, options) {
		return this.runMountOperation(async () => {
			await this.mountBucketUnlocked(bucket, mountPath, options);
		});
	}
	async runMountOperation(operation) {
		const previous = this.mountOperationQueue;
		let release;
		this.mountOperationQueue = new Promise((resolve) => {
			release = resolve;
		});
		await previous.catch(() => {});
		try {
			await operation();
		} finally {
			release();
		}
	}
	async mountBucketUnlocked(bucket, mountPath, options) {
		if (options.prefix !== void 0) validatePrefix(options.prefix);
		if ("localBucket" in options && options.localBucket) {
			await this.mountBucketLocal(bucket, mountPath, options);
			return;
		}
		const remoteOptions = options;
		if (remoteOptions.endpoint === void 0) {
			const binding = this.env[bucket];
			if (isR2Bucket(binding)) {
				await this.mountBucketR2Egress(bucket, mountPath, options);
				return;
			}
			throw new InvalidMountConfigError(`R2 binding "${bucket}" not found in Worker env. Ensure the binding name matches the bucket binding configured in wrangler.jsonc.`);
		}
		await this.mountBucketFuse(bucket, mountPath, remoteOptions);
	}
	/**
	* Local dev mount: bidirectional sync via R2 binding + file/watch APIs
	*/
	async mountBucketLocal(bucket, mountPath, options) {
		const mountStartTime = Date.now();
		let mountOutcome = "error";
		let mountError;
		try {
			const r2Binding = this.env[bucket];
			if (!r2Binding || !isR2Bucket(r2Binding)) throw new InvalidMountConfigError(`R2 binding "${bucket}" not found in env or is not an R2Bucket. Make sure the binding name matches your wrangler.jsonc R2 binding.`);
			if (!mountPath || !mountPath.startsWith("/")) throw new InvalidMountConfigError(`Invalid mount path: "${mountPath}". Must be an absolute path starting with /`);
			if (this.activeMounts.has(mountPath)) throw new InvalidMountConfigError(`Mount path already in use: ${mountPath}`);
			const sessionId = await this.ensureDefaultSession();
			const syncManager = new LocalMountSyncManager({
				bucket: r2Binding,
				mountPath,
				prefix: options.prefix,
				readOnly: options.readOnly ?? false,
				client: this.client,
				sessionId,
				logger: this.logger
			});
			const mountInfo = {
				mountId: crypto.randomUUID(),
				mountType: "local-sync",
				bucket,
				mountPath,
				syncManager,
				mounted: false
			};
			this.activeMounts.set(mountPath, mountInfo);
			try {
				await syncManager.start();
				mountInfo.mounted = true;
			} catch (error) {
				await syncManager.stop();
				this.activeMounts.delete(mountPath);
				throw error;
			}
			mountOutcome = "success";
		} catch (error) {
			mountError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "bucket.mount",
				outcome: mountOutcome,
				durationMs: Date.now() - mountStartTime,
				bucket,
				mountPath,
				provider: "local-sync",
				prefix: options.prefix,
				error: mountError
			});
		}
	}
	getR2EgressParams() {
		const buckets = {};
		for (const [, m] of this.activeMounts) if (m.mountType === "r2-egress") buckets[m.bucket] = {
			prefix: m.prefix,
			readOnly: m.readOnly
		};
		return { buckets };
	}
	validateProtectedS3fsOptions(options, mountLabel, extraProtected = []) {
		if (!options) return;
		const protectedOptions = /* @__PURE__ */ new Set([
			"passwd_file",
			"url",
			...extraProtected
		]);
		for (const option of options) {
			const [key] = option.split("=");
			if (protectedOptions.has(key)) throw new InvalidMountConfigError(`s3fs option "${key}" cannot be overridden for ${mountLabel} mounts`);
		}
	}
	getS3CredentialProxyParams(options) {
		const mounts = {};
		for (const [, m] of this.activeMounts) if (m.mountType === "fuse" && m.credentialProxy) {
			if (m.mountId === options?.excludeMountId) continue;
			mounts[m.mountId] = {
				endpoint: m.credentialProxy.endpoint,
				bucket: m.credentialProxy.bucket,
				...m.credentialProxy.prefix !== void 0 ? { prefix: m.credentialProxy.prefix } : {},
				credentials: m.credentialProxy.credentials,
				readOnly: m.credentialProxy.readOnly,
				provider: m.credentialProxy.provider,
				authStrategy: m.credentialProxy.authStrategy
			};
		}
		return { mounts };
	}
	resolveCredentialProxyAuthStrategy(provider) {
		return provider === "gcs" ? "gcs" : "s3-sigv4";
	}
	/**
	* Credential-less R2 mount: egress interception routes s3fs requests to the
	* R2 binding. No S3 credentials are needed in the container or Worker env.
	*/
	async mountBucketR2Egress(bucket, mountPath, options) {
		const mountStartTime = Date.now();
		const prefix = options.prefix;
		let mountOutcome = "error";
		let mountError;
		try {
			validateBucketBindingName(bucket, mountPath);
			this.validateMountPath(mountPath);
			this.validateProtectedS3fsOptions(options.s3fsOptions, "R2 binding");
			const restoredRoute = this.restoredMountRoutes.r2Buckets[bucket];
			if (restoredRoute && (restoredRoute.prefix !== prefix || (restoredRoute.readOnly ?? false) !== (options.readOnly ?? false))) throw new InvalidMountConfigError(`R2 binding "${bucket}" is already mounted with a different prefix or readOnly setting. Mount the same binding only once, or use the same settings for additional mounts.`);
			for (const [existingMountPath, mountInfo$1] of this.activeMounts) {
				if (mountInfo$1.mountType === "r2-egress" && mountInfo$1.bucket === bucket && mountInfo$1.prefix !== prefix) throw new InvalidMountConfigError(`R2 binding "${bucket}" is already mounted at ${existingMountPath} with a different prefix. Mount the same binding only once, or use the same prefix for additional mounts.`);
				if (mountInfo$1.mountType === "r2-egress" && mountInfo$1.bucket === bucket && mountInfo$1.readOnly !== (options.readOnly ?? false)) throw new InvalidMountConfigError(`R2 binding "${bucket}" is already mounted at ${existingMountPath} with a different readOnly setting. Mount the same binding only once, or use the same readOnly value for additional mounts.`);
			}
			const passwordFilePath = this.generatePasswordFilePath();
			const additionalHeaderFilePath = this.generateS3FSAdditionalHeaderFilePath();
			const mountInfo = {
				mountId: crypto.randomUUID(),
				mountType: "r2-egress",
				bucket,
				mountPath,
				passwordFilePath,
				additionalHeaderFilePath,
				mounted: false,
				prefix,
				readOnly: options.readOnly ?? false
			};
			this.activeMounts.set(mountPath, mountInfo);
			try {
				await this.createPasswordFile(passwordFilePath, bucket, {
					accessKeyId: "x",
					secretAccessKey: "x"
				});
				await this.createDisableExpectHeaderFile(additionalHeaderFilePath);
				await this.configureR2EgressOutbound(this.getR2EgressParams());
				await this.execInternal(`mkdir -p ${shellEscape(mountPath)}`);
				const s3fsSource = bucket;
				const optionsStr = shellEscape(serializeS3fsOptions({
					passwd_file: passwordFilePath,
					...R2_DEFAULT_S3FS_OPTIONS,
					...parseS3fsOptions(resolveS3fsOptions("r2", options.s3fsOptions)),
					use_path_request_style: true,
					url: "http://r2.internal",
					ahbe_conf: additionalHeaderFilePath,
					...options.readOnly ? { ro: true } : {}
				}));
				const mountCmd = `s3fs ${shellEscape(s3fsSource)} ${shellEscape(mountPath)} -o ${optionsStr}`;
				this.logger.debug("r2-egress: running s3fs", { mountCmd });
				const result = await this.execInternal(mountCmd);
				this.logger.debug("r2-egress: s3fs exited", {
					exitCode: result.exitCode,
					stdout: result.stdout,
					stderr: result.stderr
				});
				if (result.exitCode !== 0) throw new S3FSMountError(`S3FS mount failed: ${result.stderr || result.stdout || "Unknown error"}`);
				const mountpointCheck = await this.execInternal(`mountpoint -q ${shellEscape(mountPath)} && echo 'FUSE_MOUNTED' || echo 'NOT_FUSE_MOUNTED'`);
				this.logger.debug("r2-egress: mountpoint check", {
					stdout: mountpointCheck.stdout.trim(),
					exitCode: mountpointCheck.exitCode
				});
				if (mountpointCheck.stdout.trim() !== "FUSE_MOUNTED") throw new S3FSMountError(`s3fs exited 0 but mount was not established at ${mountPath}`);
			} catch (error) {
				await this.releaseFailedR2EgressMount(mountInfo);
				throw error;
			}
			mountInfo.mounted = true;
			mountOutcome = "success";
		} catch (error) {
			mountError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "bucket.mount",
				outcome: mountOutcome,
				durationMs: Date.now() - mountStartTime,
				bucket,
				mountPath,
				provider: "r2",
				prefix,
				error: mountError
			});
		}
	}
	/**
	* Undo a failed R2 binding mount: drop its reservation and support files,
	* then rebuild the `r2.internal` routes from the remaining mounts.
	*/
	async releaseFailedR2EgressMount(mountInfo) {
		this.activeMounts.delete(mountInfo.mountPath);
		await this.deletePasswordFile(mountInfo.passwordFilePath);
		if (mountInfo.additionalHeaderFilePath) await this.deleteAdditionalHeaderFile(mountInfo.additionalHeaderFilePath);
		await this.configureR2EgressOutbound(this.getR2EgressParams()).catch(() => {});
	}
	/**
	* Production mount: S3FS-FUSE inside the container
	*/
	async mountBucketFuse(bucket, mountPath, options) {
		const mountStartTime = Date.now();
		const prefix = options.prefix;
		let mountOutcome = "error";
		let mountError;
		let provider = null;
		try {
			this.validateMountOptions(bucket, mountPath, {
				...options,
				prefix
			});
			const s3fsSource = buildS3fsSource(bucket, prefix);
			provider = options.provider || detectProviderFromUrl(options.endpoint);
			this.logger.debug(`Detected provider: ${provider || "unknown"}`, {
				explicitProvider: options.provider,
				prefix
			});
			const envObj = this.env;
			const credentials = detectCredentials(options, {
				AWS_ACCESS_KEY_ID: getEnvString(envObj, "AWS_ACCESS_KEY_ID"),
				AWS_SECRET_ACCESS_KEY: getEnvString(envObj, "AWS_SECRET_ACCESS_KEY"),
				R2_ACCESS_KEY_ID: this.r2AccessKeyId || void 0,
				R2_SECRET_ACCESS_KEY: this.r2SecretAccessKey || void 0,
				...this.envVars
			});
			const credentialProxyEnabled = options.credentialProxy === true;
			if (credentialProxyEnabled) this.validateProtectedS3fsOptions(options.s3fsOptions, "credential proxy", ["ahbe_conf", "use_path_request_style"]);
			const passwordFilePath = this.generatePasswordFilePath();
			const additionalHeaderFilePath = credentialProxyEnabled ? this.generateS3FSAdditionalHeaderFilePath() : void 0;
			const mountId = crypto.randomUUID();
			const mountInfo = {
				mountId,
				mountType: "fuse",
				bucket: s3fsSource,
				mountPath,
				endpoint: options.endpoint,
				provider,
				passwordFilePath,
				...additionalHeaderFilePath ? { additionalHeaderFilePath } : {},
				mounted: false,
				...credentialProxyEnabled ? { credentialProxy: {
					endpoint: options.endpoint,
					bucket,
					...prefix !== void 0 ? { prefix } : {},
					credentials,
					readOnly: options.readOnly ?? false,
					provider,
					authStrategy: this.resolveCredentialProxyAuthStrategy(provider)
				} } : {}
			};
			this.activeMounts.set(mountPath, mountInfo);
			let dirExisted = true;
			try {
				await this.createPasswordFile(passwordFilePath, bucket, credentialProxyEnabled ? {
					accessKeyId: "x",
					secretAccessKey: "x"
				} : credentials);
				if (credentialProxyEnabled) {
					if (additionalHeaderFilePath) await this.createDisableExpectHeaderFile(additionalHeaderFilePath);
					await this.configureS3CredentialProxyOutbound(this.getS3CredentialProxyParams());
				}
				dirExisted = (await this.execInternal(`test -d ${shellEscape(mountPath)}`)).exitCode === 0;
				await this.execInternal(`mkdir -p ${shellEscape(mountPath)}`);
				const effectiveOptions = credentialProxyEnabled ? {
					...options,
					endpoint: `http://${S3_CREDENTIAL_PROXY_HOST}/${mountId}`,
					s3fsOptions: [
						...provider === "r2" ? R2_DEFAULT_S3FS_OPTION_ENTRIES : [],
						...options.s3fsOptions ?? [],
						...additionalHeaderFilePath ? [`ahbe_conf=${additionalHeaderFilePath}`] : [],
						"use_path_request_style"
					]
				} : options;
				await this.executeS3FSMount(s3fsSource, mountPath, effectiveOptions, provider, passwordFilePath);
			} catch (error) {
				await this.releaseFailedFuseMount(mountInfo, !dirExisted);
				throw error;
			}
			mountInfo.mounted = true;
			mountOutcome = "success";
		} catch (error) {
			mountError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "bucket.mount",
				outcome: mountOutcome,
				durationMs: Date.now() - mountStartTime,
				bucket,
				mountPath,
				provider: provider || "unknown",
				prefix,
				error: mountError
			});
		}
	}
	/**
	* Undo a failed FUSE mount: unmount anything s3fs established, then drop
	* its support files, the directory if this mount created it, and its
	* reservation.
	*/
	async releaseFailedFuseMount(mountInfo, removeMountDirectory) {
		const { mountPath } = mountInfo;
		try {
			await this.execInternal(`mountpoint -q ${shellEscape(mountPath)} && fusermount -u ${shellEscape(mountPath)}`);
		} catch {}
		await this.deletePasswordFile(mountInfo.passwordFilePath);
		if (mountInfo.additionalHeaderFilePath) await this.deleteAdditionalHeaderFile(mountInfo.additionalHeaderFilePath);
		if (removeMountDirectory) try {
			await this.execInternal(`rmdir ${shellEscape(mountPath)} 2>/dev/null`);
		} catch {}
		if (mountInfo.credentialProxy) {
			try {
				await this.configureS3CredentialProxyOutbound(this.getS3CredentialProxyParams({ excludeMountId: mountInfo.mountId }));
			} catch (cleanupError) {
				this.logger.warn("credential proxy cleanup failed", {
					mountPath,
					error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
				});
			}
			evictSigV4ClientCacheEntry(mountInfo.mountId);
			evictDirectoryMarkerCacheForMount(mountInfo.mountId);
		}
		this.activeMounts.delete(mountPath);
	}
	/**
	* Manually unmount a bucket filesystem
	*
	* @param mountPath - Absolute path where the bucket is mounted
	* @throws InvalidMountConfigError if mount path doesn't exist or isn't mounted
	*/
	async unmountBucket(mountPath) {
		return this.runMountOperation(async () => {
			await this.unmountBucketUnlocked(mountPath);
		});
	}
	async unmountBucketUnlocked(mountPath) {
		const unmountStartTime = Date.now();
		let unmountOutcome = "error";
		let unmountError;
		const mountInfo = this.activeMounts.get(mountPath);
		try {
			if (!mountInfo) throw new InvalidMountConfigError(`No active mount found at path: ${mountPath}`);
			if (mountInfo.mountType === "local-sync") {
				await mountInfo.syncManager.stop();
				mountInfo.mounted = false;
				this.activeMounts.delete(mountPath);
			} else if (mountInfo.mountType === "fuse" && mountInfo.credentialProxy && !mountInfo.mounted) {
				try {
					await this.configureS3CredentialProxyOutbound(this.getS3CredentialProxyParams({ excludeMountId: mountInfo.mountId }));
				} catch (cleanupError) {
					this.logger.warn("credential proxy outbound reconfiguration failed on unmount", {
						mountPath,
						error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
					});
				}
				this.activeMounts.delete(mountPath);
				evictSigV4ClientCacheEntry(mountInfo.mountId);
				evictDirectoryMarkerCacheForMount(mountInfo.mountId);
			} else {
				let unmounted = false;
				try {
					const result = await this.execInternal(`fusermount -u ${shellEscape(mountPath)}`);
					if (result.exitCode !== 0) {
						const stderr = result.stderr || "unknown error";
						throw new BucketUnmountError(`fusermount -u failed (exit ${result.exitCode}): ${stderr}`);
					}
					unmounted = true;
					mountInfo.mounted = false;
					if (mountInfo.mountType === "r2-egress") {
						const remainingBuckets = {};
						for (const [, activeMount] of this.activeMounts) if (activeMount.mountType === "r2-egress" && activeMount.mountId !== mountInfo.mountId) remainingBuckets[activeMount.bucket] = {
							prefix: activeMount.prefix,
							readOnly: activeMount.readOnly
						};
						try {
							await this.configureR2EgressOutbound({ buckets: remainingBuckets });
						} catch (cleanupError) {
							this.logger.warn("r2 egress outbound reconfiguration failed on unmount", {
								mountPath,
								error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
							});
						}
						this.activeMounts.delete(mountPath);
					} else if (mountInfo.mountType === "fuse" && mountInfo.credentialProxy) {
						try {
							await this.configureS3CredentialProxyOutbound(this.getS3CredentialProxyParams({ excludeMountId: mountInfo.mountId }));
						} catch (cleanupError) {
							this.logger.warn("credential proxy outbound reconfiguration failed on unmount", {
								mountPath,
								error: cleanupError instanceof Error ? cleanupError.message : String(cleanupError)
							});
						}
						this.activeMounts.delete(mountPath);
						evictSigV4ClientCacheEntry(mountInfo.mountId);
						evictDirectoryMarkerCacheForMount(mountInfo.mountId);
					} else this.activeMounts.delete(mountPath);
					try {
						const cleanup = await this.execInternal(`mountpoint -q ${shellEscape(mountPath)} || rmdir ${shellEscape(mountPath)}`);
						if (cleanup.exitCode !== 0) this.logger.warn("mount directory removal failed", {
							mountPath,
							exitCode: cleanup.exitCode,
							stderr: cleanup.stderr
						});
					} catch (err) {
						this.logger.warn("mount directory removal failed", {
							mountPath,
							error: err instanceof Error ? err.message : String(err)
						});
					}
				} finally {
					if (unmounted) {
						await this.deletePasswordFile(mountInfo.passwordFilePath);
						if (mountInfo.additionalHeaderFilePath) await this.deleteAdditionalHeaderFile(mountInfo.additionalHeaderFilePath);
					}
				}
			}
			unmountOutcome = "success";
		} catch (error) {
			unmountError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "bucket.unmount",
				outcome: unmountOutcome,
				durationMs: Date.now() - unmountStartTime,
				mountPath,
				bucket: mountInfo?.bucket,
				error: unmountError
			});
		}
	}
	/**
	* Shared validation for mount path (absolute, not already in use).
	*/
	validateMountPath(mountPath) {
		if (!mountPath.startsWith("/")) throw new InvalidMountConfigError(`Mount path must be absolute (start with /): "${mountPath}"`);
		if (this.activeMounts.has(mountPath)) throw new InvalidMountConfigError(`Mount path "${mountPath}" is already in use by bucket "${this.activeMounts.get(mountPath)?.bucket}". Unmount the existing bucket first or use a different mount path.`);
	}
	/**
	* Validate mount options for remote (FUSE) mounts
	*/
	validateMountOptions(bucket, mountPath, options) {
		try {
			new URL(options.endpoint);
		} catch (error) {
			throw new InvalidMountConfigError(`Invalid endpoint URL: "${options.endpoint}". Must be a valid HTTP(S) URL.`);
		}
		validateBucketName(bucket, mountPath);
		this.validateMountPath(mountPath);
	}
	/**
	* Generate unique password file path for s3fs credentials
	*/
	generatePasswordFilePath() {
		return `/tmp/.passwd-s3fs-${crypto.randomUUID()}`;
	}
	/**
	* Generate unique ahbe_conf file path for s3fs additional header config
	*/
	generateS3FSAdditionalHeaderFilePath() {
		return `/tmp/.s3fs-ahbe-${crypto.randomUUID()}.conf`;
	}
	/**
	* Create s3fs ahbe_conf file that suppresses the Expect: 100-continue header.
	*/
	async createDisableExpectHeaderFile(headerFilePath) {
		await this.writeOwnerOnlyFile(headerFilePath, S3FS_DISABLE_EXPECT_HEADER_CONFIG);
	}
	/**
	* Create password file with s3fs credentials
	* Format: bucket:accessKeyId:secretAccessKey
	*/
	async createPasswordFile(passwordFilePath, bucket, credentials) {
		const content = `${bucket}:${credentials.accessKeyId}:${credentials.secretAccessKey}`;
		await this.writeOwnerOnlyFile(passwordFilePath, content);
	}
	/**
	* s3fs refuses support files that other users can read. Create them with
	* mode 0600 so the password file is never readable while it is being
	* written. The chmod covers container images that ignore `ownerOnly`.
	*/
	async writeOwnerOnlyFile(path$1, content) {
		await this.client.files.writeFile(path$1, content, DISABLE_SESSION_TOKEN, { ownerOnly: true });
		await this.execInternal(`chmod 0600 ${shellEscape(path$1)}`);
	}
	/**
	* Delete password file
	*/
	async deletePasswordFile(passwordFilePath) {
		try {
			await this.execInternal(`rm -f ${shellEscape(passwordFilePath)}`);
		} catch (error) {
			this.logger.warn("password file cleanup failed", {
				passwordFilePath,
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}
	async deleteAdditionalHeaderFile(headerFilePath) {
		try {
			await this.execInternal(`rm -f ${shellEscape(headerFilePath)}`);
		} catch (error) {
			this.logger.warn("s3fs additional header file cleanup failed", {
				headerFilePath,
				error: error instanceof Error ? error.message : String(error)
			});
		}
	}
	/**
	* Execute S3FS mount command
	*/
	async executeS3FSMount(bucket, mountPath, options, provider, passwordFilePath, sessionId) {
		const s3fsOptions = {
			logfile: `/tmp/.s3fs-log-${randomHex(4)}`,
			...parseS3fsOptions(resolveS3fsOptions(provider)),
			...parseS3fsOptions(options.s3fsOptions ?? []),
			passwd_file: passwordFilePath,
			url: options.endpoint,
			...options.readOnly ? { ro: true } : {}
		};
		const logFile = s3fsOptions.logfile;
		const script = sh`(
      s3fs ${bucket} ${mountPath} -o ${serializeS3fsOptions(s3fsOptions)} >${logFile} 2>&1
      rc=$?
      if [ "$rc" -ne 0 ]; then tail -n 20 ${logFile} 2>/dev/null || true; exit 2; fi
      for _ in $(seq 1 60); do
        if mountpoint -q ${mountPath}; then exit 0; fi
        sleep 0.1
      done
      tail -n 20 ${logFile} 2>/dev/null || true
      exit 3
    )`;
		const result = await (sessionId ? (cmd) => this.execWithSession(cmd, sessionId, { origin: "internal" }) : (cmd) => this.execInternal(cmd))(script);
		if (result.exitCode === 0) return;
		const detail = result.stdout?.trim() || result.stderr?.trim() || "";
		if (result.exitCode === 2) throw new S3FSMountError(`S3FS mount failed: ${detail || "Unknown error"}`);
		throw new S3FSMountError(`S3FS mount failed: FUSE filesystem never appeared at ${mountPath}. ${detail ? `s3fs log: ${detail}` : "No s3fs log output captured. The s3fs daemon may have exited before writing logs."}`);
	}
	async unmountTrackedFuseMount(mountPath, mountInfo) {
		if (!mountInfo.mounted) return;
		this.logger.debug(`Unmounting bucket ${mountInfo.bucket} from ${mountPath}`);
		const result = await this.execInternal(`fusermount -u ${shellEscape(mountPath)}`);
		if (result.exitCode !== 0) throw new Error(`fusermount -u failed (exit ${result.exitCode}): ${result.stderr || "unknown error"}`);
		mountInfo.mounted = false;
	}
	/**
	* In-flight `destroy()` promise. While set, concurrent callers coalesce
	* onto the same teardown instead of triggering a second one. Cleared when
	* the underlying work settles, so a later call that genuinely needs to
	* recreate a destroyed sandbox still runs.
	*
	* If the underlying teardown hangs (e.g. `super.destroy()` never resolves
	* because the Containers control plane is unresponsive), every coalesced
	* caller hangs on the same promise until the Durable Object is evicted.
	* This is deliberate: a second concurrent teardown would not make a stuck
	* control plane unstuck, and spawning one would defeat the point of
	* coalescing. Callers that need bounded waits must apply their own
	* timeout around `destroy()`.
	*/
	inflightDestroy = null;
	/**
	* Cleanup and destroy the sandbox container.
	*
	* Concurrent calls coalesce: if a previous `destroy()` is still in flight,
	* subsequent calls await the same underlying work instead of starting a
	* second teardown. A canonical `sandbox.destroy.coalesced` event is logged
	* per coalesced call so repeated destroy traffic is observable.
	*/
	async destroy() {
		if (this.inflightDestroy) {
			logCanonicalEvent(this.logger, {
				event: "sandbox.destroy.coalesced",
				outcome: "success",
				durationMs: 0
			});
			return this.inflightDestroy;
		}
		const work = this.doDestroy();
		this.inflightDestroy = work;
		try {
			await work;
		} finally {
			if (this.inflightDestroy === work) this.inflightDestroy = null;
		}
	}
	async doDestroy() {
		const startTime = Date.now();
		let mountsProcessed = 0;
		let mountFailures = 0;
		let outcome = "error";
		let caughtError;
		try {
			await this.ctx.storage.delete(PORT_TOKENS_STORAGE_KEY);
			await this.clearActivePreviewPorts();
			await this.currentLifetime.rotate();
			await this.currentRuntime.clear();
			for (const [mountPath, mountInfo] of this.activeMounts.entries()) {
				mountsProcessed++;
				if (mountInfo.mountType === "local-sync") try {
					await mountInfo.syncManager.stop();
					mountInfo.mounted = false;
				} catch (error) {
					mountFailures++;
					const errorMsg = error instanceof Error ? error.message : String(error);
					this.logger.warn(`Failed to stop local sync for ${mountPath}: ${errorMsg}`);
				}
				else {
					try {
						await this.unmountTrackedFuseMount(mountPath, mountInfo);
					} catch (error) {
						mountFailures++;
						const errorMsg = error instanceof Error ? error.message : String(error);
						this.logger.warn(`Failed to unmount bucket ${mountInfo.bucket} from ${mountPath}: ${errorMsg}`);
					}
					await this.deletePasswordFile(mountInfo.passwordFilePath);
					if (mountInfo.additionalHeaderFilePath) await this.deleteAdditionalHeaderFile(mountInfo.additionalHeaderFilePath);
				}
			}
			try {
				this.ensureTunnelsBuilt();
				await this.destroyAllTunnels?.();
			} catch (error) {
				this.logger.warn("Failed to tear down tunnels during destroy()", { error: error instanceof Error ? error.message : String(error) });
			}
			await this.ctx.storage.delete("tunnels");
			await this.ctx.storage.delete("tunnels:meta");
			this.client.disconnect(this.buildDisconnectCause("sandbox_lifetime_changed", "The sandbox was destroyed while the operation was pending."));
			outcome = "success";
			try {
				await super.destroy();
			} catch (error) {
				if (!this.isNoInstanceError(error)) throw error;
				this.logger.debug("super.destroy() reported no container instance; treating as no-op");
			}
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "sandbox.destroy",
				outcome,
				durationMs: Date.now() - startTime,
				mountsProcessed,
				mountFailures,
				error: caughtError
			});
		}
	}
	async onStart() {
		this.logger.debug("Sandbox started");
		await this.currentRuntime.markStarted();
		await this.removeStaleMountRoutes();
		this.checkVersionCompatibility().catch((error) => {
			this.logger.error("Version compatibility check failed", error instanceof Error ? error : new Error(String(error)));
		});
		try {
			await pruneTunnelsForRestart(this.ctx.storage);
		} catch (error) {
			this.logger.error("Failed to reconcile tunnel storage after container start", error instanceof Error ? error : new Error(String(error)));
		}
	}
	async stop(signal) {
		await this.currentRuntime.clear();
		await this.clearActivePreviewPorts();
		await super.stop(signal);
	}
	/**
	* Read the `portTokens` map from DO storage, normalizing the legacy
	* string-valued format (just a token) to the current object format
	* ({ token, name? }). The legacy format predates port-name persistence and
	* can appear on any DO whose storage was written before that change.
	*/
	async readPortTokens(storage = this.ctx.storage) {
		const raw = await storage.get(PORT_TOKENS_STORAGE_KEY) ?? {};
		const normalized = {};
		for (const [port, value] of Object.entries(raw)) normalized[port] = typeof value === "string" ? { token: value } : value;
		return normalized;
	}
	async readActivePreviewPorts(storage = this.ctx.storage) {
		return await storage.get(ACTIVE_PREVIEW_PORTS_STORAGE_KEY) ?? {};
	}
	async writeActivePreviewPorts(activations, storage = this.ctx.storage) {
		if (Object.keys(activations).length === 0) {
			await storage.delete(ACTIVE_PREVIEW_PORTS_STORAGE_KEY);
			return;
		}
		await storage.put(ACTIVE_PREVIEW_PORTS_STORAGE_KEY, activations);
	}
	async readPreviewState(storage = this.ctx.storage) {
		const [tokens, activations] = await Promise.all([this.readPortTokens(storage), this.readActivePreviewPorts(storage)]);
		return {
			tokens,
			activations
		};
	}
	async clearActivePreviewPorts() {
		await this.ctx.storage.delete(ACTIVE_PREVIEW_PORTS_STORAGE_KEY);
	}
	/**
	* Check if the container version matches the SDK version
	* Logs a warning if there's a mismatch
	*/
	async checkVersionCompatibility() {
		const sdkVersion = SDK_VERSION;
		let containerVersion;
		let outcome;
		try {
			containerVersion = await this.client.utils.getVersion();
			if (containerVersion === "unknown") outcome = "container_version_unknown";
			else if (containerVersion !== sdkVersion) outcome = "version_mismatch";
			else outcome = "compatible";
		} catch (error) {
			outcome = "check_failed";
			containerVersion = void 0;
		}
		const successLevel = outcome === "compatible" ? "debug" : outcome === "container_version_unknown" ? "info" : "warn";
		logCanonicalEvent(this.logger, {
			event: "version.check",
			outcome: "success",
			durationMs: 0,
			sdkVersion,
			containerVersion: containerVersion ?? "unknown",
			versionOutcome: outcome
		}, { successLevel });
	}
	async onStop(params) {
		this.logger.debug("Sandbox stopped", {
			exitCode: params?.exitCode,
			reason: params?.reason
		});
		this.containerGeneration++;
		this.defaultSession = null;
		this.defaultSessionInit = null;
		const disconnectClient = this.transport !== "rpc" || this.client.isWebSocketConnected();
		await this.currentRuntime.clear();
		await this.clearActivePreviewPorts();
		try {
			await pruneTunnelsForRestart(this.ctx.storage);
		} catch (error) {
			this.logger.error("Failed to reconcile tunnel storage after container stop", error instanceof Error ? error : new Error(String(error)));
		}
		if (disconnectClient) this.client.disconnect(this.buildDisconnectCause("runtime_replaced", "The sandbox container stopped while the operation was pending.", params));
		await this.releaseRestoredMountRoutes();
		let hadR2EgressMount = false;
		let hadCredentialProxyMount = false;
		for (const [, m] of this.activeMounts) if (m.mountType === "local-sync") await m.syncManager.stop().catch(() => {});
		else if (m.mountType === "r2-egress") hadR2EgressMount = true;
		else if (m.mountType === "fuse" && m.credentialProxy) {
			hadCredentialProxyMount = true;
			evictSigV4ClientCacheEntry(m.mountId);
			evictDirectoryMarkerCacheForMount(m.mountId);
		}
		if (hadR2EgressMount) await this.configureR2EgressOutbound({ buckets: {} }).catch(() => {});
		if (hadCredentialProxyMount) await this.configureS3CredentialProxyOutbound({ mounts: {} }).catch(() => {});
		this.activeMounts.clear();
		await this.ctx.storage.delete("defaultSession");
	}
	onError(error) {
		this.logger.error("Sandbox error", error instanceof Error ? error : new Error(String(error)));
	}
	/**
	* Override Container.containerFetch to use production-friendly timeouts
	* Automatically starts container with longer timeouts if not running
	*/
	async containerFetch(requestOrUrl, portOrInit, portParam) {
		const { request, port } = this.parseContainerFetchArgs(requestOrUrl, portOrInit, portParam);
		const state = await this.getState();
		const containerRunning = this.ctx.container?.running;
		const staleStateDetected = state.status === "healthy" && containerRunning === false;
		if (state.status !== "healthy" || containerRunning === false) try {
			await this.startAndWaitForPorts({
				ports: port,
				cancellationOptions: {
					instanceGetTimeoutMS: this.containerTimeouts.instanceGetTimeoutMS,
					portReadyTimeoutMS: this.containerTimeouts.portReadyTimeoutMS,
					waitInterval: this.containerTimeouts.waitIntervalMS,
					abort: request.signal
				}
			});
		} catch (e) {
			const admissionReason = matchContainerUnavailable(e);
			if (admissionReason) {
				const originalMessage = e instanceof Error ? e.message : String(e);
				const context = {
					reason: admissionReason,
					retryable: true,
					originalMessage
				};
				const errorBody$1 = {
					code: ErrorCode.CONTAINER_UNAVAILABLE,
					message: originalMessage,
					context,
					httpStatus: 503,
					timestamp: (/* @__PURE__ */ new Date()).toISOString(),
					suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, context)
				};
				return new Response(JSON.stringify(errorBody$1), {
					status: 503,
					headers: {
						"Content-Type": "application/json",
						"Retry-After": "10"
					}
				});
			}
			if (this.isPermanentStartupError(e)) {
				this.logger.error("Permanent container startup error, returning 500", e instanceof Error ? e : new Error(String(e)));
				const errorBody$1 = {
					code: ErrorCode.INTERNAL_ERROR,
					message: "Container failed to start due to a permanent error. Check your container configuration.",
					context: {
						phase: "startup",
						error: e instanceof Error ? e.message : String(e)
					},
					httpStatus: 500,
					timestamp: (/* @__PURE__ */ new Date()).toISOString(),
					suggestion: "This error will not resolve with retries. Check container logs, image name, and resource limits."
				};
				return new Response(JSON.stringify(errorBody$1), {
					status: 500,
					headers: { "Content-Type": "application/json" }
				});
			}
			if (this.isTransientStartupError(e)) {
				if (staleStateDetected) {
					this.logger.warn("container.startup", {
						outcome: "stale_state_abort",
						staleStateDetected: true,
						error: e instanceof Error ? e.message : String(e)
					});
					this.ctx.abort();
				} else this.logger.debug("container.startup", {
					outcome: "transient_error",
					staleStateDetected,
					error: e instanceof Error ? e.message : String(e)
				});
				const errorBody$1 = {
					code: ErrorCode.INTERNAL_ERROR,
					message: "Container is starting. Please retry in a moment.",
					context: {
						phase: "startup",
						error: e instanceof Error ? e.message : String(e)
					},
					httpStatus: 503,
					timestamp: (/* @__PURE__ */ new Date()).toISOString(),
					suggestion: "The container is booting. The SDK will retry automatically."
				};
				return new Response(JSON.stringify(errorBody$1), {
					status: 503,
					headers: {
						"Content-Type": "application/json",
						"Retry-After": "3"
					}
				});
			}
			this.logger.warn("container.startup", {
				outcome: "unrecognized_error",
				staleStateDetected,
				error: e instanceof Error ? e.message : String(e)
			});
			const errorBody = {
				code: ErrorCode.INTERNAL_ERROR,
				message: "Container is starting. Please retry in a moment.",
				context: {
					phase: "startup",
					error: e instanceof Error ? e.message : String(e)
				},
				httpStatus: 503,
				timestamp: (/* @__PURE__ */ new Date()).toISOString(),
				suggestion: "The SDK will retry automatically. If this persists, the container may need redeployment."
			};
			return new Response(JSON.stringify(errorBody), {
				status: 503,
				headers: {
					"Content-Type": "application/json",
					"Retry-After": "5"
				}
			});
		}
		return await super.containerFetch(requestOrUrl, portOrInit, portParam);
	}
	/**
	* Helper: Check if error is "no container instance available"
	* This indicates the container VM is still being provisioned.
	*/
	isNoInstanceError(error) {
		return matchContainerUnavailable(error) !== null;
	}
	/**
	* Explicit container-start hook for the RPC transport.
	*
	* The control connection calls this hook every time it connects, including
	* when it reconnects after an idle disconnect. A running, healthy container
	* is left alone, as in {@link containerFetch}: the base class runs
	* `onStart()` on every `startAndWaitForPorts()`, and `onStart()` treats the
	* container as new, recording a new runtime identity and dropping quick
	* tunnels from storage.
	*
	* Runs `startAndWaitForPorts` under a short instance-get budget
	* ({@link RPC_START_INSTANCE_GET_TIMEOUT_MS}) so a single attempt fails fast
	* under capacity pressure — the base class throws the classifiable
	* `NO_CONTAINER_INSTANCE_ERROR` once that budget is exhausted, and the RPC
	* control connection's own retry loop (with backoff) owns cross-attempt
	* retries. Port readiness still uses the full `portReadyTimeoutMS` so a
	* genuinely-booting app isn't cut short once an instance exists.
	*
	* Always throws a typed `SandboxError` on failure so the control connection
	* never surfaces a raw capnweb/transport string to the caller:
	*   - container-admission/capacity failures → retryable
	*     `ContainerUnavailableError` (preserving the platform message so the
	*     connection's `shouldRetryError` still recognizes and retries it);
	*   - anything else (platform-transient DO reset, network loss, unexpected
	*     startup failure) → `INTERNAL_ERROR`-coded SandboxError carrying the
	*     original message.
	*/
	async startContainerForRPC() {
		try {
			if ((await this.getState()).status === "healthy" && this.ctx.container?.running !== false) return;
			await this.startAndWaitForPorts({
				ports: 3e3,
				cancellationOptions: {
					instanceGetTimeoutMS: RPC_START_INSTANCE_GET_TIMEOUT_MS,
					portReadyTimeoutMS: this.containerTimeouts.portReadyTimeoutMS,
					waitInterval: this.containerTimeouts.waitIntervalMS
				}
			});
		} catch (error) {
			throw this.toContainerStartError(error);
		}
	}
	/**
	* Convert a container-start failure into a typed SandboxError. Preserves an
	* existing SandboxError as-is; maps platform admission/capacity failures to
	* a retryable ContainerUnavailableError; and wraps everything else as an
	* INTERNAL_ERROR carrying the original message (never a raw transport
	* string).
	*/
	toContainerStartError(error) {
		if (error instanceof SandboxError) return error;
		const originalMessage = error instanceof Error ? error.message : String(error);
		const admissionReason = matchContainerUnavailable(error);
		if (admissionReason) {
			const context$1 = {
				reason: admissionReason,
				retryable: true,
				originalMessage
			};
			return createErrorFromResponse({
				code: ErrorCode.CONTAINER_UNAVAILABLE,
				message: originalMessage,
				context: context$1,
				httpStatus: getHttpStatus(ErrorCode.CONTAINER_UNAVAILABLE),
				suggestion: getSuggestion(ErrorCode.CONTAINER_UNAVAILABLE, context$1),
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			}, { cause: error });
		}
		const context = {
			phase: "startup",
			error: originalMessage
		};
		return createErrorFromResponse({
			code: ErrorCode.INTERNAL_ERROR,
			message: `Container failed to start: ${originalMessage}`,
			context,
			httpStatus: getHttpStatus(ErrorCode.INTERNAL_ERROR),
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		}, { cause: error });
	}
	/**
	* Build a typed lifecycle cause to stamp on the RPC transport when the DO
	* tears the connection down for its own reasons (container stopped, sandbox
	* destroyed, transport switched). Handed to `client.disconnect(cause)` so
	* any RPC calls queued on the transport reject with this actionable reason
	* instead of the generic capnweb "disposing the main stub" message.
	*/
	buildDisconnectCause(reason, detail, stopParams) {
		const context = {
			reason,
			operation: "rpc.connect",
			phase: "connection",
			admitted: "unknown",
			retryable: reason === "runtime_replaced",
			...stopParams?.exitCode !== void 0 && { containerExitCode: stopParams.exitCode },
			...stopParams?.reason !== void 0 && { stopReason: stopParams.reason }
		};
		return new OperationInterruptedError({
			code: ErrorCode.OPERATION_INTERRUPTED,
			message: detail,
			context,
			httpStatus: getHttpStatus(ErrorCode.OPERATION_INTERRUPTED),
			suggestion: getSuggestion(ErrorCode.OPERATION_INTERRUPTED, context),
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
	}
	/**
	* Helper: Check if error is a transient startup error that should trigger retry
	*
	* These errors occur during normal container startup and are recoverable:
	* - Port not yet mapped (container starting, app not listening yet)
	* - Connection refused (port mapped but app not ready)
	* - Timeouts during startup (recoverable with retry)
	* - Network transients (temporary connectivity issues)
	*
	* Errors NOT included (permanent failures):
	* - "no such image" - missing Docker image
	* - "container already exists" - name collision
	* - Configuration errors
	*/
	isTransientStartupError(error) {
		if (!(error instanceof Error)) return false;
		const msg = error.message.toLowerCase();
		return [
			"container port not found",
			"connection refused: container port",
			"the container is not listening",
			"failed to verify port",
			"container did not start",
			"network connection lost",
			"container suddenly disconnected",
			"monitor failed to find container",
			"container exited with unexpected exit code",
			"container exited before we could determine",
			"timed out",
			"timeout",
			"the operation was aborted"
		].some((pattern) => msg.includes(pattern));
	}
	/**
	* Helper: Check if error is a permanent startup failure that will never recover
	*
	* These errors indicate resource exhaustion, misconfiguration, or missing images.
	* Retrying will never succeed, so the SDK should fail fast with HTTP 500.
	*
	* Error sources (traced from platform internals):
	*   - Container runtime: OOM, PID limit
	*   - Scheduling/provisioning: no matching app, no namespace configured
	*   - workerd container-client.c++: no such image
	*   - @cloudflare/containers: did not call start
	*/
	isPermanentStartupError(error) {
		if (!(error instanceof Error)) return false;
		const msg = error.message.toLowerCase();
		return [
			"ran out of memory",
			"too many subprocesses",
			"no application that matches",
			"no container application assigned",
			"no such image",
			"did not call start"
		].some((pattern) => msg.includes(pattern));
	}
	/**
	* Helper: Parse containerFetch arguments (supports multiple signatures)
	*/
	parseContainerFetchArgs(requestOrUrl, portOrInit, portParam) {
		let request;
		let port;
		if (requestOrUrl instanceof Request) {
			request = requestOrUrl;
			port = typeof portOrInit === "number" ? portOrInit : void 0;
		} else {
			const url = typeof requestOrUrl === "string" ? requestOrUrl : requestOrUrl.toString();
			const init = typeof portOrInit === "number" ? {} : portOrInit || {};
			port = typeof portOrInit === "number" ? portOrInit : typeof portParam === "number" ? portParam : void 0;
			request = new Request(url, init);
		}
		port ??= this.defaultPort;
		if (port === void 0) throw new Error("No port specified for container fetch");
		return {
			request,
			port
		};
	}
	/**
	* Override onActivityExpired to prevent automatic shutdown when keepAlive is enabled
	* When keepAlive is disabled, calls parent implementation which stops the container
	*/
	async onActivityExpired() {
		if (this.keepAliveEnabled) this.logger.debug("Activity expired but keepAlive is enabled - container will stay alive");
		else {
			this.logger.debug("Activity expired - stopping container");
			await super.onActivityExpired();
		}
	}
	isPreviewProxyRequest(request) {
		return request.headers.get(PREVIEW_PROXY_HEADER) === "1";
	}
	invalidPreviewTokenResponse() {
		return new Response(JSON.stringify({
			error: "Access denied: Invalid token or port not exposed",
			code: "INVALID_TOKEN"
		}), {
			status: 404,
			headers: { "Content-Type": "application/json" }
		});
	}
	stalePreviewURLResponse() {
		return new Response(JSON.stringify({
			error: "Preview URL is stale because the sandbox runtime is not active",
			code: "STALE_PREVIEW_URL"
		}), {
			status: 410,
			headers: { "Content-Type": "application/json" }
		});
	}
	getPreviewForwardingContainer() {
		return this.ctx.container;
	}
	beginPreviewForward() {
		const lifecycle = this;
		lifecycle.inflightRequests = (lifecycle.inflightRequests ?? 0) + 1;
		this.renewActivityTimeout();
		let settled = false;
		return () => {
			if (settled) return;
			settled = true;
			lifecycle.inflightRequests = Math.max(0, (lifecycle.inflightRequests ?? 0) - 1);
			if (lifecycle.inflightRequests === 0) this.renewActivityTimeout();
		};
	}
	async fetchPreviewIfRunning(request, port, runtime) {
		const container = this.getPreviewForwardingContainer();
		const state = await this.getState();
		if (!container?.running || state.status !== "healthy") return this.stalePreviewURLResponse();
		if (!await this.currentRuntime.isActive(runtime)) return this.stalePreviewURLResponse();
		const result = await forwardPreviewRequest(container.getTcpPort(port), request, {
			beginForward: () => this.beginPreviewForward(),
			renewActivity: () => this.renewActivityTimeout()
		});
		if (result.status === "network-lost") {
			if (!await this.currentRuntime.isActive(runtime)) return this.stalePreviewURLResponse();
			return new Response("Container suddenly disconnected, try again", { status: 500 });
		}
		if (result.status === "failed") {
			if (!await this.currentRuntime.isActive(runtime)) return this.stalePreviewURLResponse();
			this.logger.error("Preview request to container port failed", result.error instanceof Error ? result.error : new Error(String(result.error)), {
				port,
				method: request.method
			});
			return new Response(`Could not reach port ${port} in the container`, { status: 502 });
		}
		return result.response;
	}
	buildPreviewProxyRequest(request, port, sandboxId) {
		const url = new URL(request.url);
		const proxyUrl = `http://localhost:${port}${url.pathname}${url.search}`;
		const headers = new Headers(request.headers);
		for (const header of PREVIEW_PROXY_HEADERS) headers.delete(header);
		headers.set("X-Original-URL", request.url);
		headers.set("X-Forwarded-Host", url.hostname);
		headers.set("X-Forwarded-Proto", url.protocol.replace(":", ""));
		headers.set("X-Sandbox-Name", this.sandboxName ?? sandboxId);
		return new Request(proxyUrl, {
			method: request.method,
			headers,
			body: request.body,
			duplex: "half",
			redirect: "manual"
		});
	}
	async proxyPreviewRequest(request) {
		const portValue = request.headers.get(PREVIEW_PROXY_PORT_HEADER);
		const token = request.headers.get(PREVIEW_PROXY_TOKEN_HEADER);
		const sandboxId = request.headers.get(PREVIEW_PROXY_SANDBOX_ID_HEADER);
		const port = portValue === null ? NaN : Number.parseInt(portValue, 10);
		if (!Number.isFinite(port) || !validatePort(port) || !token || !sandboxId) return this.invalidPreviewTokenResponse();
		const proxyRequest = this.buildPreviewProxyRequest(request, port, sandboxId);
		const validation = await this.validatePreviewURLForRuntime(port, token);
		if (validation.status === "invalid") return this.invalidPreviewTokenResponse();
		if (validation.status === "stale") {
			this.logger.warn("Stale preview URL blocked", {
				port,
				sandboxId,
				containerStatus: validation.containerStatus,
				reason: validation.reason,
				method: request.method
			});
			return this.stalePreviewURLResponse();
		}
		return await this.fetchPreviewIfRunning(proxyRequest, port, validation.runtime);
	}
	async fetch(request) {
		const traceId = TraceContext.fromHeaders(request.headers) || TraceContext.generate();
		const requestLogger = this.logger.child({
			traceId,
			operation: "fetch"
		});
		const url = new URL(request.url);
		if (this.isPreviewProxyRequest(request)) return await this.proxyPreviewRequest(request);
		if (!this.sandboxName && request.headers.has("X-Sandbox-Name")) {
			const name = request.headers.get("X-Sandbox-Name");
			this.sandboxName = name;
			await this.ctx.storage.put("sandboxName", name);
		}
		const upgradeHeader = request.headers.get("Upgrade");
		const connectionHeader = request.headers.get("Connection");
		if (upgradeHeader?.toLowerCase() === "websocket" && connectionHeader?.toLowerCase().includes("upgrade")) try {
			requestLogger.debug("WebSocket upgrade requested", {
				path: url.pathname,
				port: this.determinePort(url)
			});
			return await super.fetch(request);
		} catch (error) {
			requestLogger.error("WebSocket connection failed", error instanceof Error ? error : new Error(String(error)), { path: url.pathname });
			throw error;
		}
		const port = this.determinePort(url);
		return await this.containerFetch(request, port);
	}
	wsConnect(request, port) {
		throw new Error("wsConnect must be called on the stub returned by getSandbox()");
	}
	determinePort(url) {
		const proxyMatch = url.pathname.match(/^\/proxy\/(\d+)/);
		if (proxyMatch) return parseInt(proxyMatch[1], 10);
		return 3e3;
	}
	/**
	* Return the default session id, lazily creating the container session
	* on first use. Called by every public method that needs a session.
	* Concurrent callers that target the same sessionId share one
	* in-flight initialization promise.
	*/
	async ensureDefaultSession() {
		const sessionId = `sandbox-${this.sandboxName || "default"}`;
		if (this.defaultSession === sessionId) return this.defaultSession;
		const generation = this.containerGeneration;
		const pending = this.defaultSessionInit;
		if (pending?.sessionId === sessionId && pending.generation === generation) return pending.promise;
		const promise = this.initializeDefaultSession(sessionId, generation);
		const init = {
			sessionId,
			generation,
			promise
		};
		this.defaultSessionInit = init;
		try {
			return await promise;
		} catch (err) {
			if (isSessionInitInvalidated(err)) {
				if (this.defaultSession === sessionId) return this.defaultSession;
				const freshPending = this.defaultSessionInit;
				if (freshPending != null && freshPending !== init && freshPending.sessionId === sessionId && freshPending.generation === this.containerGeneration) return freshPending.promise;
				return await this.initializeDefaultSession(sessionId, this.containerGeneration);
			}
			throw err;
		} finally {
			if (this.defaultSessionInit === init) this.defaultSessionInit = null;
		}
	}
	async initializeDefaultSession(sessionId, generation) {
		let placementId;
		try {
			placementId = (await this.client.utils.createSession({
				id: sessionId,
				env: this.envVars || {},
				cwd: "/workspace"
			})).containerPlacementId;
		} catch (error) {
			if (!(error instanceof SessionAlreadyExistsError)) throw error;
			placementId = error.containerPlacementId;
			this.logger.debug("Session exists in container but not in DO state, syncing", { sessionId });
		}
		if (generation !== this.containerGeneration) throw new SessionInitInvalidatedError();
		await this.ctx.storage.put("defaultSession", sessionId);
		await this.capturePlacementId(placementId);
		this.defaultSession = sessionId;
		this.logger.debug("Default session initialized", { sessionId });
		return sessionId;
	}
	/**
	* Persist the container's placement ID in DO storage.
	*
	* Called from the session-create handshake so subsequent reads via
	* `getContainerPlacementId()` do not require a round-trip to the container. The value
	* is overwritten on every handshake so that container replacements (which
	* assign a new placement ID) are reflected on the next session-create.
	*
	* A value of `undefined` means the handshake response omitted the field
	* (older container, unexpected error shape) and the stored value is left
	* untouched. `null` means the env var is not set in the container and is
	* stored as-is so callers can distinguish "observed and absent" from "not
	* yet observed."
	*/
	async capturePlacementId(containerPlacementId) {
		if (containerPlacementId === void 0) return;
		await this.ctx.storage.put("containerPlacementId", containerPlacementId);
	}
	async resolveExecution(explicitSessionId) {
		if (explicitSessionId !== void 0) {
			this.validateExplicitSessionId(explicitSessionId);
			if (explicitSessionId === DISABLE_SESSION_TOKEN) return { kind: "sessionless" };
			return {
				kind: "session",
				sessionId: explicitSessionId
			};
		}
		return {
			kind: "session",
			sessionId: await this.ensureDefaultSession()
		};
	}
	validateExplicitSessionId(sessionId) {
		if (sessionId.trim().length === 0) throw new Error("sessionId must not be empty or whitespace");
	}
	serializeExecutionContext(context) {
		if (context.kind === "sessionless") return DISABLE_SESSION_TOKEN;
		return context.sessionId;
	}
	getPublicExecutionSessionId(sessionId) {
		return sessionId === DISABLE_SESSION_TOKEN ? void 0 : sessionId;
	}
	/**
	* Resolves the session ID to annotate returned Process objects.
	*
	* Unlike `resolveExecution`, this is synchronous and never creates a
	* session. When the default session hasn't been established yet, it returns
	* `undefined` rather than triggering session creation. The resolved value is
	* only used to populate `Process.sessionId` on the returned object — it is
	* never sent to the container API.
	*/
	getProcessSessionBinding(explicitSessionId) {
		if (explicitSessionId !== void 0) {
			this.validateExplicitSessionId(explicitSessionId);
			if (explicitSessionId === DISABLE_SESSION_TOKEN) return;
			return explicitSessionId;
		}
		return this.defaultSession ?? void 0;
	}
	resolveExecutionEnv(sessionId, env$1) {
		if (sessionId === DISABLE_SESSION_TOKEN) {
			const mergedEnv = filterEnvVars({
				...this.envVars,
				...env$1 ?? {}
			});
			return Object.keys(mergedEnv).length > 0 ? mergedEnv : void 0;
		}
		if (env$1 === void 0) return;
		const filteredEnv = filterEnvVars(env$1);
		return Object.keys(filteredEnv).length > 0 ? filteredEnv : void 0;
	}
	buildExecutionRequestOptions(sessionId, options) {
		const env$1 = this.resolveExecutionEnv(sessionId, options?.env);
		if (options?.timeout === void 0 && env$1 === void 0 && options?.cwd === void 0 && options?.origin === void 0) return;
		return {
			...options?.timeout !== void 0 && { timeoutMs: options.timeout },
			...env$1 !== void 0 && { env: env$1 },
			...options?.cwd !== void 0 && { cwd: options.cwd },
			...options?.origin !== void 0 && { origin: options.origin }
		};
	}
	async exec(command, options) {
		const context = await this.resolveExecution();
		const session = this.serializeExecutionContext(context);
		return this.execWithSession(command, session, options);
	}
	async execWithSessionToken(command, sessionId, options) {
		this.validateExplicitSessionId(sessionId);
		return this.execWithSession(command, sessionId, options);
	}
	/**
	* Execute an infrastructure command (backup, mount, env setup, etc.)
	* tagged with origin: 'internal' so logging demotes it to debug level.
	*/
	async execInternal(command) {
		const session = await this.ensureDefaultSession();
		return this.execWithSession(command, session, { origin: "internal" });
	}
	/**
	* Internal session-aware exec implementation
	* Used by both public exec() and session wrappers
	*/
	async execWithSession(command, sessionId, options) {
		const startTime = Date.now();
		const timestamp = (/* @__PURE__ */ new Date()).toISOString();
		let execOutcome;
		let execError;
		try {
			if (options?.signal?.aborted) throw new Error("Operation was aborted");
			let result;
			if (options?.stream && options?.onOutput) result = await this.executeWithStreaming(command, sessionId, options, startTime, timestamp);
			else {
				const commandOptions = this.buildExecutionRequestOptions(sessionId, options);
				const response = await this.client.commands.execute(command, sessionId, commandOptions);
				const duration = Date.now() - startTime;
				const publicSessionId = this.getPublicExecutionSessionId(sessionId);
				result = this.mapExecuteResponseToExecResult(response, duration, publicSessionId);
			}
			execOutcome = {
				exitCode: result.exitCode,
				success: result.success
			};
			if (options?.onComplete) options.onComplete(result);
			return result;
		} catch (error) {
			execError = error instanceof Error ? error : new Error(String(error));
			if (options?.onError && error instanceof Error) options.onError(error);
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "sandbox.exec",
				outcome: execError ? "error" : "success",
				exitCode: execOutcome?.exitCode,
				durationMs: Date.now() - startTime,
				sessionId: this.getPublicExecutionSessionId(sessionId),
				origin: options?.origin ?? "user",
				error: execError ?? void 0,
				errorMessage: execError?.message
			});
		}
	}
	async executeWithStreaming(command, sessionId, options, startTime, timestamp) {
		let stdout = "";
		let stderr = "";
		try {
			const commandOptions = this.buildExecutionRequestOptions(sessionId, options);
			const stream = await this.client.commands.executeStream(command, sessionId, commandOptions);
			for await (const event of parseSSEStream(stream)) {
				if (options.signal?.aborted) throw new Error("Operation was aborted");
				switch (event.type) {
					case "stdout":
					case "stderr":
						if (event.data) {
							if (event.type === "stdout") stdout += event.data;
							if (event.type === "stderr") stderr += event.data;
							if (options.onOutput) options.onOutput(event.type, event.data);
						}
						break;
					case "complete": {
						const duration = Date.now() - startTime;
						return {
							success: (event.exitCode ?? 0) === 0,
							exitCode: event.exitCode ?? 0,
							stdout,
							stderr,
							command,
							duration,
							timestamp,
							sessionId: this.getPublicExecutionSessionId(sessionId)
						};
					}
					case "error": throw new Error(event.data || "Command execution failed");
				}
			}
			throw new Error("Stream ended without completion event");
		} catch (error) {
			if (options.signal?.aborted) throw new Error("Operation was aborted");
			throw error;
		}
	}
	mapExecuteResponseToExecResult(response, duration, sessionId) {
		return {
			success: response.success,
			exitCode: response.exitCode,
			stdout: response.stdout,
			stderr: response.stderr,
			command: response.command,
			duration,
			timestamp: response.timestamp,
			sessionId
		};
	}
	/**
	* Create a Process domain object from HTTP client DTO
	* Centralizes process object creation with bound methods
	* This eliminates duplication across startProcess, listProcesses, getProcess, and session wrappers
	*/
	createProcessFromDTO(data, sessionId) {
		return {
			id: data.id,
			pid: data.pid,
			command: data.command,
			status: data.status,
			startTime: typeof data.startTime === "string" ? new Date(data.startTime) : data.startTime,
			endTime: data.endTime ? typeof data.endTime === "string" ? new Date(data.endTime) : data.endTime : void 0,
			exitCode: data.exitCode,
			sessionId,
			kill: async (signal) => {
				await this.killProcess(data.id, signal);
			},
			getStatus: async () => {
				return (await this.getProcess(data.id))?.status || "error";
			},
			getLogs: async () => {
				const logs = await this.getProcessLogs(data.id);
				return {
					stdout: logs.stdout,
					stderr: logs.stderr
				};
			},
			waitForLog: async (pattern, timeout) => {
				return this.waitForLogPattern(data.id, data.command, pattern, timeout);
			},
			waitForPort: async (port, options) => {
				await this.waitForPortReady(data.id, data.command, port, options);
			},
			waitForExit: async (timeout) => {
				return this.waitForProcessExit(data.id, data.command, timeout);
			}
		};
	}
	/**
	* Wait for a log pattern to appear in process output
	*/
	async waitForLogPattern(processId, command, pattern, timeout) {
		const startTime = Date.now();
		const conditionStr = this.conditionToString(pattern);
		let collectedStdout = "";
		let collectedStderr = "";
		try {
			const existingLogs = await this.getProcessLogs(processId);
			collectedStdout = existingLogs.stdout;
			if (collectedStdout && !collectedStdout.endsWith("\n")) collectedStdout += "\n";
			collectedStderr = existingLogs.stderr;
			if (collectedStderr && !collectedStderr.endsWith("\n")) collectedStderr += "\n";
			const stdoutResult = this.matchPattern(existingLogs.stdout, pattern);
			if (stdoutResult) return stdoutResult;
			const stderrResult = this.matchPattern(existingLogs.stderr, pattern);
			if (stderrResult) return stderrResult;
		} catch (error) {
			this.logger.debug("Could not get existing logs, will stream", {
				processId,
				error: error instanceof Error ? error.message : String(error)
			});
		}
		const stream = await this.streamProcessLogs(processId);
		let timeoutId;
		let timeoutPromise;
		if (timeout !== void 0) {
			const remainingTime = timeout - (Date.now() - startTime);
			if (remainingTime <= 0) throw this.createReadyTimeoutError(processId, command, conditionStr, timeout);
			timeoutPromise = new Promise((_, reject) => {
				timeoutId = setTimeout(() => {
					reject(this.createReadyTimeoutError(processId, command, conditionStr, timeout));
				}, remainingTime);
			});
		}
		try {
			const streamProcessor = async () => {
				const checkPattern = () => {
					const stdoutResult = this.matchPattern(collectedStdout, pattern);
					if (stdoutResult) return stdoutResult;
					const stderrResult = this.matchPattern(collectedStderr, pattern);
					if (stderrResult) return stderrResult;
					return null;
				};
				for await (const event of parseSSEStream(stream)) {
					if (event.type === "stdout" || event.type === "stderr") {
						const data = event.data || "";
						if (event.type === "stdout") collectedStdout += data;
						else collectedStderr += data;
						const result = checkPattern();
						if (result) return result;
					}
					if (event.type === "exit") {
						const result = checkPattern();
						if (result) return result;
						throw this.createExitedBeforeReadyError(processId, command, conditionStr, event.exitCode ?? 1);
					}
				}
				const finalResult = checkPattern();
				if (finalResult) return finalResult;
				throw this.createExitedBeforeReadyError(processId, command, conditionStr, 0);
			};
			if (timeoutPromise) return await Promise.race([streamProcessor(), timeoutPromise]);
			return await streamProcessor();
		} finally {
			if (timeoutId) clearTimeout(timeoutId);
		}
	}
	/**
	* Wait for a port to become available (for process readiness checking)
	*/
	async waitForPortReady(processId, command, port, options) {
		const { mode = "http", path: path$1 = "/", status = {
			min: 200,
			max: 399
		}, timeout, interval = 500 } = options ?? {};
		const conditionStr = mode === "http" ? `port ${port} (HTTP ${path$1})` : `port ${port} (TCP)`;
		const statusMin = typeof status === "number" ? status : status.min;
		const statusMax = typeof status === "number" ? status : status.max;
		const stream = await this.client.ports.watchPort({
			port,
			mode,
			path: path$1,
			statusMin,
			statusMax,
			processId,
			interval
		});
		let timeoutId;
		let timeoutPromise;
		if (timeout !== void 0) timeoutPromise = new Promise((_, reject) => {
			timeoutId = setTimeout(() => {
				reject(this.createReadyTimeoutError(processId, command, conditionStr, timeout));
			}, timeout);
		});
		try {
			const streamProcessor = async () => {
				for await (const event of parseSSEStream(stream)) switch (event.type) {
					case "ready": return;
					case "process_exited": throw this.createExitedBeforeReadyError(processId, command, conditionStr, event.exitCode ?? 1);
					case "error": throw new Error(event.error || "Port watch failed");
				}
				throw new Error("Port watch stream ended unexpectedly");
			};
			if (timeoutPromise) await Promise.race([streamProcessor(), timeoutPromise]);
			else await streamProcessor();
		} finally {
			if (timeoutId) clearTimeout(timeoutId);
			try {
				await stream.cancel();
			} catch {}
		}
	}
	/**
	* Wait for a process to exit
	* Returns the exit code
	*/
	async waitForProcessExit(processId, command, timeout) {
		const stream = await this.streamProcessLogs(processId);
		let timeoutId;
		let timeoutPromise;
		if (timeout !== void 0) timeoutPromise = new Promise((_, reject) => {
			timeoutId = setTimeout(() => {
				reject(this.createReadyTimeoutError(processId, command, "process exit", timeout));
			}, timeout);
		});
		try {
			const streamProcessor = async () => {
				for await (const event of parseSSEStream(stream)) if (event.type === "exit") return { exitCode: event.exitCode ?? 1 };
				throw new Error(`Process ${processId} stream ended unexpectedly without exit event`);
			};
			if (timeoutPromise) return await Promise.race([streamProcessor(), timeoutPromise]);
			return await streamProcessor();
		} finally {
			if (timeoutId) clearTimeout(timeoutId);
		}
	}
	/**
	* Match a pattern against text
	*/
	matchPattern(text, pattern) {
		if (typeof pattern === "string") {
			if (text.includes(pattern)) {
				const lines = text.split("\n");
				for (const line of lines) if (line.includes(pattern)) return { line };
				return { line: pattern };
			}
		} else {
			const safePattern = new RegExp(pattern.source, pattern.flags.replace("g", ""));
			const match = text.match(safePattern);
			if (match) {
				const lines = text.split("\n");
				for (const line of lines) {
					const lineMatch = line.match(safePattern);
					if (lineMatch) return {
						line,
						match: lineMatch
					};
				}
				return {
					line: match[0],
					match
				};
			}
		}
		return null;
	}
	/**
	* Convert a log pattern to a human-readable string
	*/
	conditionToString(pattern) {
		if (typeof pattern === "string") return `"${pattern}"`;
		return pattern.toString();
	}
	/**
	* Create a ProcessReadyTimeoutError
	*/
	createReadyTimeoutError(processId, command, condition, timeout) {
		return new ProcessReadyTimeoutError({
			code: ErrorCode.PROCESS_READY_TIMEOUT,
			message: `Process did not become ready within ${timeout}ms. Waiting for: ${condition}`,
			context: {
				processId,
				command,
				condition,
				timeout
			},
			httpStatus: 408,
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			suggestion: `Check if your process outputs ${condition}. You can increase the timeout parameter.`
		});
	}
	/**
	* Create a ProcessExitedBeforeReadyError
	*/
	createExitedBeforeReadyError(processId, command, condition, exitCode) {
		return new ProcessExitedBeforeReadyError({
			code: ErrorCode.PROCESS_EXITED_BEFORE_READY,
			message: `Process exited with code ${exitCode} before becoming ready. Waiting for: ${condition}`,
			context: {
				processId,
				command,
				condition,
				exitCode
			},
			httpStatus: 500,
			timestamp: (/* @__PURE__ */ new Date()).toISOString(),
			suggestion: "Check process logs with getLogs() for error messages"
		});
	}
	async startProcess(command, options, sessionId) {
		try {
			const execution = await this.resolveExecution(sessionId);
			const session = this.serializeExecutionContext(execution);
			const processSession = this.getProcessSessionBinding(session);
			const requestOptions = {
				...this.buildExecutionRequestOptions(session, {
					timeout: options?.timeout,
					env: options?.env,
					cwd: options?.cwd
				}),
				...options?.processId !== void 0 && { processId: options.processId },
				...options?.encoding !== void 0 && { encoding: options.encoding },
				...options?.autoCleanup !== void 0 && { autoCleanup: options.autoCleanup }
			};
			const response = await this.client.processes.startProcess(command, session, requestOptions);
			const processObj = this.createProcessFromDTO({
				id: response.processId,
				pid: response.pid,
				command: response.command,
				status: "running",
				startTime: /* @__PURE__ */ new Date(),
				endTime: void 0,
				exitCode: void 0
			}, processSession);
			if (options?.onStart) options.onStart(processObj);
			if (options?.onOutput || options?.onExit) this.startProcessCallbackStream(response.processId, options).catch(() => {});
			return processObj;
		} catch (error) {
			if (options?.onError && error instanceof Error) options.onError(error);
			throw error;
		}
	}
	/**
	* Start background streaming for process callbacks
	* Opens SSE stream to container and routes events to callbacks
	*/
	async startProcessCallbackStream(processId, options) {
		try {
			const stream = await this.client.processes.streamProcessLogs(processId);
			for await (const event of parseSSEStream(stream)) switch (event.type) {
				case "stdout":
					if (event.data && options.onOutput) options.onOutput("stdout", event.data);
					break;
				case "stderr":
					if (event.data && options.onOutput) options.onOutput("stderr", event.data);
					break;
				case "exit":
				case "complete":
					if (options.onExit) options.onExit(event.exitCode ?? null);
					return;
			}
			throw new Error("Stream ended without completion event");
		} catch (error) {
			if (options.onError && error instanceof Error) options.onError(error);
			this.logger.error("Background process streaming failed", error instanceof Error ? error : new Error(String(error)), { processId });
		}
	}
	async listProcesses(sessionId) {
		const session = this.getProcessSessionBinding(sessionId);
		return (await this.client.processes.listProcesses()).processes.map((processData) => this.createProcessFromDTO({
			id: processData.id,
			pid: processData.pid,
			command: processData.command,
			status: processData.status,
			startTime: processData.startTime,
			endTime: processData.endTime,
			exitCode: processData.exitCode
		}, session));
	}
	async getProcess(id, sessionId) {
		const session = this.getProcessSessionBinding(sessionId);
		try {
			const response = await this.client.processes.getProcess(id);
			if (!response.process) return null;
			const processData = response.process;
			return this.createProcessFromDTO({
				id: processData.id,
				pid: processData.pid,
				command: processData.command,
				status: processData.status,
				startTime: processData.startTime,
				endTime: processData.endTime,
				exitCode: processData.exitCode
			}, session);
		} catch (error) {
			if (error instanceof ProcessNotFoundError) return null;
			throw error;
		}
	}
	async killProcess(id, signal, sessionId) {
		await this.client.processes.killProcess(id);
	}
	async killAllProcesses(sessionId) {
		return (await this.client.processes.killAllProcesses()).cleanedCount;
	}
	async cleanupCompletedProcesses(sessionId) {
		return 0;
	}
	async getProcessLogs(id, sessionId) {
		const response = await this.client.processes.getProcessLogs(id);
		return {
			stdout: response.stdout,
			stderr: response.stderr,
			processId: response.processId
		};
	}
	async execStream(command, options) {
		if (options?.signal?.aborted) throw new Error("Operation was aborted");
		const context = await this.resolveExecution(options?.sessionId);
		const session = this.serializeExecutionContext(context);
		const executionOptions = this.buildExecutionRequestOptions(session, {
			timeout: options?.timeout,
			env: options?.env,
			cwd: options?.cwd
		});
		return this.client.commands.executeStream(command, session, executionOptions);
	}
	async execStreamWithSessionToken(command, sessionId, options) {
		this.validateExplicitSessionId(sessionId);
		return this.execStreamWithSession(command, sessionId, options);
	}
	/**
	* Internal session-aware execStream implementation
	*/
	async execStreamWithSession(command, sessionId, options) {
		if (options?.signal?.aborted) throw new Error("Operation was aborted");
		return this.client.commands.executeStream(command, sessionId, this.buildExecutionRequestOptions(sessionId, {
			timeout: options?.timeout,
			env: options?.env,
			cwd: options?.cwd
		}));
	}
	/**
	* Stream logs from a background process as a ReadableStream.
	*/
	async streamProcessLogs(processId, options) {
		if (options?.signal?.aborted) throw new Error("Operation was aborted");
		return this.client.processes.streamProcessLogs(processId);
	}
	async gitCheckout(repoUrl, options) {
		const execution = await this.resolveExecution(options?.sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.git.checkout(repoUrl, session, {
			branch: options?.branch,
			targetDir: options?.targetDir,
			depth: options?.depth,
			timeoutMs: options?.cloneTimeoutMs
		});
	}
	async mkdir(path$1, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.mkdir(path$1, session, { recursive: options.recursive });
	}
	async writeFile(path$1, content, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const session = this.serializeExecutionContext(execution);
		if (content instanceof ReadableStream) return this.client.files.writeFileStream(path$1, content, session);
		return this.client.files.writeFile(path$1, content, session, { encoding: options.encoding });
	}
	async deleteFile(path$1, sessionId) {
		const execution = await this.resolveExecution(sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.deleteFile(path$1, session);
	}
	async renameFile(oldPath, newPath, sessionId) {
		const execution = await this.resolveExecution(sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.renameFile(oldPath, newPath, session);
	}
	async moveFile(sourcePath, destinationPath, sessionId) {
		const execution = await this.resolveExecution(sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.moveFile(sourcePath, destinationPath, session);
	}
	async readFile(path$1, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const session = this.serializeExecutionContext(execution);
		if (options.encoding === "none") return this.client.files.readFile(path$1, session, { encoding: "none" });
		return this.client.files.readFile(path$1, session, { encoding: options.encoding });
	}
	/**
	* Stream a file from the sandbox using Server-Sent Events
	* Returns a ReadableStream that can be consumed with streamFile() or collectFile() utilities
	* @param path - Path to the file to stream
	* @param options - Optional session ID
	*/
	async readFileStream(path$1, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.readFileStream(path$1, session);
	}
	async listFiles(path$1, options) {
		const context = await this.resolveExecution(options?.sessionId);
		const session = this.serializeExecutionContext(context);
		return this.client.files.listFiles(path$1, session, options);
	}
	async exists(path$1, sessionId) {
		const execution = await this.resolveExecution(sessionId);
		const session = this.serializeExecutionContext(execution);
		return this.client.files.exists(path$1, session);
	}
	/**
	* Watch a directory for file system changes using native inotify.
	*
	* The returned promise resolves only after the watcher is established on the
	* filesystem, so callers can immediately perform actions that depend on the
	* watch being active. The returned stream contains the full event sequence
	* starting with the `watching` event.
	*
	* Consume the stream with `parseSSEStream<FileWatchSSEEvent>(stream)`.
	*
	* @param path - Path to watch (absolute or relative to /workspace)
	* @param options - Watch options
	*/
	async watch(path$1, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const sessionId = this.serializeExecutionContext(execution);
		return this.client.watch.watch({
			path: path$1,
			recursive: options.recursive,
			include: options.include,
			exclude: options.exclude,
			sessionId
		});
	}
	/**
	* Check whether a path changed while this caller was disconnected.
	*
	* Pass the `version` returned from a prior call in `options.since` to learn
	* whether the path is unchanged, changed, or needs a full resync because the
	* retained change state was reset.
	*
	* @param path - Path to check (absolute or relative to /workspace)
	* @param options - Change-check options
	*/
	async checkChanges(path$1, options = {}) {
		const execution = await this.resolveExecution(options.sessionId);
		const sessionId = this.serializeExecutionContext(execution);
		return this.client.watch.checkChanges({
			path: path$1,
			recursive: options.recursive,
			include: options.include,
			exclude: options.exclude,
			since: options.since,
			sessionId
		});
	}
	/**
	* Expose a port and get a preview URL for accessing services running in the sandbox
	*
	* Preview URL authorization survives transient container restarts, but
	* forwarding is active only for the runtime where `exposePort()` was last
	* called. Call `exposePort()` again after a restart to reactivate an
	* existing URL for the current runtime.
	*
	* @param port - Port number to expose (1024-65535)
	* @param options - Configuration options
	* @param options.hostname - Your Worker's domain name (required for preview URL construction)
	* @param options.name - Optional friendly name for the port
	* @param options.token - Optional custom token for the preview URL (1-16 characters: lowercase letters, numbers, underscores)
	*                       If not provided, a random 16-character token will be generated automatically
	* @returns Preview URL information including the full URL, port number, and optional name
	*
	* @example
	* // With auto-generated token
	* const { url } = await sandbox.exposePort(8080, { hostname: 'example.com' });
	* // url: https://8080-sandbox-id-abc123random4567.example.com
	*
	* @example
	* // With custom token for stable URLs across deployments
	* const { url } = await sandbox.exposePort(8080, {
	*   hostname: 'example.com',
	*   token: 'my_token_v1'
	* });
	* // url: https://8080-sandbox-id-my_token_v1.example.com
	*/
	async exposePort(port, options) {
		const exposeStartTime = Date.now();
		let outcome = "error";
		let caughtError;
		try {
			if (!validatePort(port)) throw new SandboxSecurityError(`Invalid port number: ${port}. Must be 1024-65535, excluding 3000 (sandbox control plane).`);
			if (options.hostname.endsWith(".workers.dev")) throw new CustomDomainRequiredError({
				code: ErrorCode.CUSTOM_DOMAIN_REQUIRED,
				message: `Port exposure requires a custom domain. .workers.dev domains do not support wildcard subdomains required for port proxying.`,
				context: { originalError: options.hostname },
				httpStatus: 400,
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (!this.sandboxName) throw new Error("Sandbox name not available. Ensure sandbox is accessed through getSandbox()");
			if (options.token !== void 0) this.validateCustomToken(options.token);
			await this.ensureDefaultSession();
			let runtime = await this.currentRuntime.get();
			runtime = runtime ?? await this.currentRuntime.markStarted();
			await this.currentRuntime.assertActive(runtime);
			const token = await this.ctx.storage.transaction(async (txn) => {
				const tokens = await this.readPortTokens(txn);
				const existingEntry = tokens[port.toString()];
				const nextToken = options.token ?? existingEntry?.token ?? this.generatePortToken();
				const existingPort = Object.entries(tokens).find(([p, entry]) => entry.token === nextToken && p !== port.toString());
				if (existingPort) throw new SandboxSecurityError(`Token '${nextToken}' is already in use by port ${existingPort[0]}. Please use a different token.`);
				const activations = await this.readActivePreviewPorts(txn);
				tokens[port.toString()] = {
					token: nextToken,
					name: options.name
				};
				activations[port.toString()] = runtime.scope({ token: nextToken });
				await Promise.all([txn.put(PORT_TOKENS_STORAGE_KEY, tokens), this.writeActivePreviewPorts(activations, txn)]);
				return nextToken;
			});
			await this.currentRuntime.assertActive(runtime);
			const url = this.constructPreviewUrl(port, this.sandboxName, options.hostname, token);
			outcome = "success";
			return {
				url,
				port,
				name: options.name
			};
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "port.expose",
				outcome,
				port,
				durationMs: Date.now() - exposeStartTime,
				name: options.name,
				hostname: options.hostname,
				error: caughtError
			});
		}
	}
	/**
	* Revoke preview URL authorization and current-runtime activation for a port.
	*
	* Revocation is idempotent: calling this for a port with no preview state is
	* still successful. The operation clears Durable Object-owned preview state
	* only and does not contact, probe, wake, or clean up the container runtime.
	*/
	async unexposePort(port) {
		const unexposeStartTime = Date.now();
		let outcome = "error";
		let caughtError;
		try {
			if (!validatePort(port)) throw new SandboxSecurityError(`Invalid port number: ${port}. Must be 1024-65535, excluding 3000 (sandbox control plane).`);
			await this.ctx.storage.transaction(async (txn) => {
				const tokens = await this.readPortTokens(txn);
				if (tokens[port.toString()]) {
					delete tokens[port.toString()];
					await txn.put(PORT_TOKENS_STORAGE_KEY, tokens);
				}
				const activations = await this.readActivePreviewPorts(txn);
				if (activations[port.toString()]) {
					delete activations[port.toString()];
					await this.writeActivePreviewPorts(activations, txn);
				}
			});
			outcome = "success";
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			throw error;
		} finally {
			logCanonicalEvent(this.logger, {
				event: "port.unexpose",
				outcome,
				port,
				durationMs: Date.now() - unexposeStartTime,
				error: caughtError
			});
		}
	}
	/**
	* Returns preview URLs that are currently forwardable in the active runtime.
	* Durable authorization without current-runtime activation is omitted.
	*/
	async getExposedPorts(hostname) {
		if (!this.sandboxName) throw new Error("Sandbox name not available. Ensure sandbox is accessed through getSandbox()");
		return (await this.getCurrentPreviewPorts()).map(({ port, entry }) => ({
			url: this.constructPreviewUrl(port, this.sandboxName, hostname, entry.token),
			port,
			status: "active"
		}));
	}
	/**
	* Namespaced tunnel API. Quick tunnels are zero-config preview URLs
	* backed by Cloudflare's trycloudflare service.
	*
	* - `tunnels.get(port)` — idempotent. Returns the cached tunnel for
	*   `port` if one exists in DO storage, otherwise spawns a fresh
	*   cloudflared process and persists the record.
	* - `tunnels.list()` — records currently known to this sandbox, from
	*   DO storage.
	* - `tunnels.destroy(portOrInfo)` — tear down by port number or by
	*   the record returned from `get()`.
	*
	* Storage is cleared on container restart (`onStart`), so URLs do
	* not survive a container restart — the next `get(port)` call will
	* spawn a fresh tunnel with a new URL.
	*
	* Requires the RPC transport. Calling this on a route-based transport
	* throws "RPC transport required".
	*/
	get tunnels() {
		this.ensureTunnelsBuilt();
		return this.tunnelsHandler;
	}
	/**
	* Lazily construct both the public tunnels handler and its sibling
	* exit-handler callback. Called from the `tunnels` getter on first
	* access and on every access after a transport swap clears both
	* fields.
	*/
	ensureTunnelsBuilt() {
		if (this.tunnelsHandler) return;
		const built = createTunnelsHandler({
			client: this.client,
			storage: this.ctx.storage,
			logger: this.logger,
			sandboxId: this.ctx.id.toString(),
			currentRuntime: this.currentRuntime,
			currentLifetime: this.currentLifetime,
			withPortLock: this.tunnelPortLock,
			getNamedTunnelConfig: async () => {
				const envObj = this.env;
				const token = getEnvString(envObj, "CLOUDFLARE_API_TOKEN");
				if (!token) throw new Error("Named tunnels require CLOUDFLARE_API_TOKEN. Set it as a secret in your wrangler.jsonc.");
				const accountId = await this.getTunnelAccountId();
				return {
					token,
					accountId,
					zoneId: await this.getTunnelZoneId(token, accountId)
				};
			}
		});
		this.tunnelsHandler = built.tunnels;
		this.tunnelExitHandler = built.handleTunnelExit;
		this.destroyAllTunnels = built.destroyAll;
	}
	/**
	* Resolve the Cloudflare account id used for named-tunnel provisioning.
	*
	* Memoised for the lifetime of this DO instance. The first call may hit
	* `GET /user/tokens/verify` to derive the account id from the configured
	* `CLOUDFLARE_API_TOKEN`; subsequent calls return the cached promise.
	*
	* Only successful resolutions are cached: a rejected lookup clears the
	* slot so the next caller retries. Otherwise a transient failure on
	* first use would permanently poison every later named-tunnel `get()`
	* on this DO instance.
	*/
	getTunnelAccountId() {
		if (!this.tunnelAccountIdPromise) {
			const pending = resolveAccountId(this.env, { overrideKey: "CLOUDFLARE_TUNNEL_ACCOUNT_ID" });
			this.tunnelAccountIdPromise = pending;
			pending.catch(() => {
				if (this.tunnelAccountIdPromise === pending) this.tunnelAccountIdPromise = null;
			});
		}
		return this.tunnelAccountIdPromise;
	}
	/**
	* Resolve the Cloudflare zone id used for named-tunnel provisioning.
	*
	* Memoised for the lifetime of this DO instance. Falls back to the
	* single zone the token can see under `accountId` via `GET /zones`
	* when `CLOUDFLARE_ZONE_ID` is not set. Failed lookups clear the cache
	* so the next caller retries — see `getTunnelAccountId` for the
	* rationale.
	*/
	getTunnelZoneId(token, accountId) {
		if (!this.tunnelZoneIdPromise) {
			const pending = resolveZoneId(this.env, {
				token,
				accountId
			});
			this.tunnelZoneIdPromise = pending;
			pending.catch(() => {
				if (this.tunnelZoneIdPromise === pending) this.tunnelZoneIdPromise = null;
			});
		}
		return this.tunnelZoneIdPromise;
	}
	/**
	* Returns whether a port is currently preview-forwardable.
	* This checks Durable Object-owned auth and runtime activation without
	* contacting or waking the container.
	*/
	async isPortExposed(port) {
		if (!validatePort(port)) return false;
		return (await this.getCurrentPreviewPorts()).some((activePort) => activePort.port === port);
	}
	/**
	* Checks durable preview URL authorization for a port/token pair.
	*
	* This does not check whether the port is activated for the current runtime
	* and is not sufficient to decide whether preview traffic may forward.
	*/
	async validatePortToken(port, token) {
		const entry = (await this.readPortTokens())[port.toString()];
		if (!entry) return false;
		return this.previewTokensMatch(entry.token, token);
	}
	async validatePreviewURLForRuntime(port, token) {
		const containerState = await this.getState();
		const containerRunning = this.ctx.container?.running === true;
		const { tokens, activations, runtime } = await this.ctx.storage.transaction(async (txn) => {
			const [previewState, runtime$1] = await Promise.all([this.readPreviewState(txn), this.currentRuntime.getStored(txn)]);
			return {
				...previewState,
				runtime: runtime$1
			};
		});
		const entry = tokens[port.toString()];
		if (!entry) return { status: "invalid" };
		if (!this.previewTokensMatch(entry.token, token)) return { status: "invalid" };
		if (containerState.status !== "healthy") return {
			status: "stale",
			reason: "runtime-not-healthy",
			containerStatus: containerState.status
		};
		if (!containerRunning) return {
			status: "stale",
			reason: "runtime-not-running",
			containerStatus: containerState.status
		};
		if (!runtime) return {
			status: "stale",
			reason: "missing-runtime-id",
			containerStatus: containerState.status
		};
		const activation = activations[port.toString()];
		if (!activation) return {
			status: "stale",
			reason: "missing-activation",
			containerStatus: containerState.status
		};
		if (!runtime.owns(activation)) return {
			status: "stale",
			reason: "runtime-mismatch",
			containerStatus: containerState.status
		};
		if (!this.previewTokensMatch(activation.token, token)) {
			this.logger.warn("Preview URL activation token mismatch", {
				port,
				runtimeIdentityID: runtime.id
			});
			return {
				status: "stale",
				reason: "token-mismatch",
				containerStatus: containerState.status
			};
		}
		return {
			status: "active",
			runtime
		};
	}
	async getCurrentPreviewPorts() {
		const containerState = await this.getState();
		const containerRunning = this.ctx.container?.running === true;
		const { tokens, activations, runtime } = await this.ctx.storage.transaction(async (txn) => {
			const [previewState, runtime$1] = await Promise.all([this.readPreviewState(txn), this.currentRuntime.getStored(txn)]);
			return {
				...previewState,
				runtime: runtime$1
			};
		});
		if (containerState.status !== "healthy" || !containerRunning || !runtime) return [];
		const activePorts = [];
		for (const [portKey, activation] of Object.entries(activations)) {
			const port = Number.parseInt(portKey, 10);
			const entry = tokens[portKey];
			if (!entry || !Number.isInteger(port) || !validatePort(port)) continue;
			if (!runtime.owns(activation)) continue;
			if (!this.previewTokensMatch(entry.token, activation.token)) continue;
			activePorts.push({
				port,
				entry
			});
		}
		return activePorts.sort((a, b) => a.port - b.port);
	}
	previewTokensMatch(expected, actual) {
		const encoder = new TextEncoder();
		const a = encoder.encode(expected);
		const b = encoder.encode(actual);
		try {
			return crypto.subtle.timingSafeEqual(a, b);
		} catch {
			return false;
		}
	}
	validateCustomToken(token) {
		if (token.length === 0) throw new SandboxSecurityError(`Custom token cannot be empty.`);
		if (token.length > 16) throw new SandboxSecurityError(`Custom token too long. Maximum 16 characters allowed. Received: ${token.length} characters.`);
		if (!/^[a-z0-9_]+$/.test(token)) throw new SandboxSecurityError(`Custom token must contain only lowercase letters (a-z), numbers (0-9), and underscores (_). Invalid token provided.`);
	}
	generatePortToken() {
		const array = /* @__PURE__ */ new Uint8Array(12);
		crypto.getRandomValues(array);
		return btoa(String.fromCharCode(...array)).replace(/\+/g, "_").replace(/\//g, "_").replace(/=/g, "").toLowerCase();
	}
	constructPreviewUrl(port, sandboxId, hostname, token) {
		if (!validatePort(port)) throw new SandboxSecurityError(`Invalid port number: ${port}. Must be 1024-65535, excluding 3000 (sandbox control plane).`);
		const effectiveId = this.sandboxName || sandboxId;
		const hasUppercase = /[A-Z]/.test(effectiveId);
		if (!this.normalizeId && hasUppercase) throw new SandboxSecurityError(`Preview URLs require lowercase sandbox IDs. Your ID "${effectiveId}" contains uppercase letters.\n\nTo fix this:\n1. Create a new sandbox with: getSandbox(ns, "${effectiveId}", { normalizeId: true })\n2. This will create a sandbox with ID: "${effectiveId.toLowerCase()}"\n\nNote: Due to DNS case-insensitivity, IDs with uppercase letters cannot be used with preview URLs.`);
		const sanitizedSandboxId = sanitizeSandboxId(sandboxId).toLowerCase();
		if (isLocalhostPattern(hostname)) {
			const [host, portStr] = hostname.split(":");
			const mainPort = portStr || "80";
			try {
				const baseUrl = new URL(`http://${host}:${mainPort}`);
				baseUrl.hostname = `${port}-${sanitizedSandboxId}-${token}.${host}`;
				return baseUrl.toString();
			} catch (error) {
				throw new SandboxSecurityError(`Failed to construct preview URL: ${error instanceof Error ? error.message : "Unknown error"}`);
			}
		}
		try {
			const baseUrl = new URL(`https://${hostname}`);
			baseUrl.hostname = `${port}-${sanitizedSandboxId}-${token}.${hostname}`;
			return baseUrl.toString();
		} catch (error) {
			throw new SandboxSecurityError(`Failed to construct preview URL: ${error instanceof Error ? error.message : "Unknown error"}`);
		}
	}
	/**
	* Create isolated execution session for advanced use cases
	* Returns ExecutionSession with full sandbox API bound to specific session
	*/
	async createSession(options) {
		const sessionId = options?.id || `session-${Date.now()}`;
		if (sessionId === DISABLE_SESSION_TOKEN) throw new Error(`Session ID '${DISABLE_SESSION_TOKEN}' is reserved for internal use`);
		const filteredEnv = filterEnvVars({
			...this.envVars,
			...options?.env ?? {}
		});
		const envPayload = Object.keys(filteredEnv).length > 0 ? filteredEnv : void 0;
		const response = await this.client.utils.createSession({
			id: sessionId,
			...envPayload && { env: envPayload },
			...options?.cwd && { cwd: options.cwd },
			...options?.commandTimeoutMs !== void 0 && { commandTimeoutMs: options.commandTimeoutMs }
		});
		await this.capturePlacementId(response.containerPlacementId);
		return this.getSessionWrapper(sessionId);
	}
	/**
	* Get an existing session by ID
	* Returns ExecutionSession wrapper bound to the specified session
	*
	* This is useful for retrieving sessions across different requests/contexts
	* without storing the ExecutionSession object (which has RPC lifecycle limitations)
	*
	* @param sessionId - The ID of an existing session
	* @returns ExecutionSession wrapper bound to the session
	*/
	async getSession(sessionId) {
		return this.getSessionWrapper(sessionId);
	}
	/**
	* Delete an execution session
	* Cleans up session resources and removes it from the container
	* Note: Cannot delete the default session. To reset the default session,
	* use sandbox.destroy() to terminate the entire sandbox.
	*
	* @param sessionId - The ID of the session to delete
	* @returns Result with success status, sessionId, and timestamp
	* @throws Error if attempting to delete the default session
	*/
	async deleteSession(sessionId) {
		if (this.defaultSession && sessionId === this.defaultSession) throw new Error(`Cannot delete default session '${sessionId}'. Use sandbox.destroy() to terminate the sandbox.`);
		const response = await this.client.utils.deleteSession(sessionId);
		return {
			success: response.success,
			sessionId: response.sessionId,
			timestamp: response.timestamp
		};
	}
	/**
	* Get the Cloudflare placement ID observed for the underlying container.
	*
	* The placement ID is captured during the first session-create handshake
	* after a container start and stored in Durable Object storage, so this
	* method returns the cached value without contacting the container. A new
	* placement ID is captured on each subsequent session-create handshake,
	* which occurs whenever the container has been replaced.
	*
	* Returns `null` when a handshake has completed but the container's
	* `CLOUDFLARE_PLACEMENT_ID` environment variable is not set (for example,
	* in local development).
	*
	* Returns `undefined` when no handshake has been observed yet on this
	* sandbox. Call any method that triggers session creation (such as
	* `exec()`) to populate the value.
	*/
	async getContainerPlacementId() {
		return this.ctx.storage.get("containerPlacementId");
	}
	getSessionWrapper(sessionId) {
		return {
			id: sessionId,
			terminal: null,
			exec: (command, options) => this.execWithSession(command, sessionId, options),
			execStream: (command, options) => this.execStreamWithSession(command, sessionId, options),
			startProcess: (command, options) => this.startProcess(command, options, sessionId),
			listProcesses: () => this.listProcesses(sessionId),
			getProcess: (id) => this.getProcess(id, sessionId),
			killProcess: (id, signal) => this.killProcess(id, signal),
			killAllProcesses: () => this.killAllProcesses(),
			cleanupCompletedProcesses: () => this.cleanupCompletedProcesses(),
			getProcessLogs: (id) => this.getProcessLogs(id),
			streamProcessLogs: (processId, options) => this.streamProcessLogs(processId, options),
			writeFile: (path$1, content, options) => this.writeFile(path$1, content, {
				...options,
				sessionId
			}),
			readFile: ((path$1, options) => {
				const encoding = options?.encoding;
				if (encoding === "none") return this.readFile(path$1, {
					encoding: "none",
					sessionId
				});
				return this.readFile(path$1, {
					encoding,
					sessionId
				});
			}),
			readFileStream: (path$1) => this.readFileStream(path$1, { sessionId }),
			watch: (path$1, options) => this.watch(path$1, {
				...options,
				sessionId
			}),
			checkChanges: (path$1, options) => this.checkChanges(path$1, {
				...options,
				sessionId
			}),
			mkdir: (path$1, options) => this.mkdir(path$1, {
				...options,
				sessionId
			}),
			deleteFile: (path$1) => this.deleteFile(path$1, sessionId),
			renameFile: (oldPath, newPath) => this.renameFile(oldPath, newPath, sessionId),
			moveFile: (sourcePath, destPath) => this.moveFile(sourcePath, destPath, sessionId),
			listFiles: (path$1, options) => this.client.files.listFiles(path$1, sessionId, options),
			exists: (path$1) => this.exists(path$1, sessionId),
			gitCheckout: (repoUrl, options) => this.gitCheckout(repoUrl, {
				...options,
				sessionId
			}),
			setEnvVars: async (envVars) => {
				const { toSet, toUnset } = partitionEnvVars(envVars);
				try {
					for (const key of toUnset) {
						const unsetCommand = `unset ${key}`;
						const result = await this.client.commands.execute(unsetCommand, sessionId, { origin: "internal" });
						if (result.exitCode !== 0) throw new Error(`Failed to unset ${key}: ${result.stderr || "Unknown error"}`);
					}
					for (const [key, value] of Object.entries(toSet)) {
						const exportCommand = `export ${key}=${shellEscape(value)}`;
						const result = await this.client.commands.execute(exportCommand, sessionId, { origin: "internal" });
						if (result.exitCode !== 0) throw new Error(`Failed to set ${key}: ${result.stderr || "Unknown error"}`);
					}
				} catch (error) {
					this.logger.error("Failed to set environment variables", error instanceof Error ? error : new Error(String(error)), { sessionId });
					throw error;
				}
			},
			createCodeContext: (options) => this.codeInterpreter.createCodeContext(options),
			runCode: async (code, options) => {
				return (await this.codeInterpreter.runCode(code, options)).toJSON();
			},
			runCodeStream: (code, options) => this.codeInterpreter.runCodeStream(code, options),
			listCodeContexts: () => this.codeInterpreter.listCodeContexts(),
			deleteCodeContext: (contextId) => this.codeInterpreter.deleteCodeContext(contextId),
			mountBucket: (bucket, mountPath, options) => this.mountBucket(bucket, mountPath, options),
			unmountBucket: (mountPath) => this.unmountBucket(mountPath),
			createBackup: (options) => this.createBackup(options),
			restoreBackup: (backup) => this.restoreBackup(backup)
		};
	}
	async createCodeContext(options) {
		return this.codeInterpreter.createCodeContext(options);
	}
	async runCode(code, options) {
		return (await this.codeInterpreter.runCode(code, options)).toJSON();
	}
	async runCodeStream(code, options) {
		return this.codeInterpreter.runCodeStream(code, options);
	}
	async listCodeContexts() {
		return this.codeInterpreter.listCodeContexts();
	}
	async deleteCodeContext(contextId) {
		return this.codeInterpreter.deleteCodeContext(contextId);
	}
	/** UUID v4 format validator for backup IDs */
	static UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
	/**
	* Validate that a directory path is safe for backup operations.
	* Rejects empty, relative, traversal, null-byte, and unsupported-root paths.
	*/
	static validateBackupDir(dir, label) {
		if (!dir || !dir.startsWith("/")) throw new InvalidBackupConfigError({
			message: `${label} must be an absolute path`,
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: `${label} must be an absolute path` },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		if (dir.includes("\0")) throw new InvalidBackupConfigError({
			message: `${label} must not contain null bytes`,
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: `${label} must not contain null bytes` },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		if (dir.split("/").includes("..")) throw new InvalidBackupConfigError({
			message: `${label} must not contain ".." path segments`,
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: `${label} must not contain ".." path segments` },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		if (!BACKUP_ALLOWED_PREFIXES.some((prefix) => dir === prefix || dir.startsWith(`${prefix}/`))) throw new InvalidBackupConfigError({
			message: `${label} must be inside one of the supported backup roots (${BACKUP_ALLOWED_PREFIXES.join(", ")})`,
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: `${label} must be inside one of the supported backup roots` },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
	}
	/**
	* Returns the R2 bucket or throws if backup is not configured.
	*/
	requireBackupBucket() {
		if (!this.backupBucket) throw new InvalidBackupConfigError({
			message: "Backup not configured. Add a BACKUP_BUCKET R2 binding to your wrangler.jsonc.",
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: "Missing BACKUP_BUCKET R2 binding" },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		return this.backupBucket;
	}
	normalizeBackupExcludes(excludes) {
		const normalizedExcludes = [];
		for (const pattern of excludes) {
			const normalized = normalizeBackupExcludePattern(pattern);
			if (normalized === null) {
				this.logger.warn("Exclude pattern reduced to empty after globstar normalization; skipping", { original: pattern });
				continue;
			}
			if (normalized !== pattern) this.logger.warn("Exclude pattern contained ** (globstar) which mksquashfs does not support; normalized automatically", {
				original: pattern,
				normalized
			});
			normalizedExcludes.push(normalized);
		}
		return normalizedExcludes;
	}
	resolveBackupCompression(compression) {
		if (compression !== void 0) {
			if (typeof compression !== "object" || compression === null) throw new InvalidBackupConfigError({
				message: "BackupOptions.compression must be an object",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "compression must be an object" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
		const compressionOptions = compression;
		const format = compressionOptions?.format ?? BACKUP_DEFAULT_COMPRESSION;
		const threads = compressionOptions?.threads ?? BACKUP_DEFAULT_COMPRESS_THREADS;
		if (typeof format !== "string" || ![
			"gzip",
			"lz4",
			"zstd"
		].includes(format)) throw new InvalidBackupConfigError({
			message: "BackupOptions.compression.format must be one of: gzip, lz4, zstd",
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: "compression.format must be one of: gzip, lz4, zstd" },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		if (typeof threads !== "number" || !Number.isInteger(threads) || threads < 1) throw new InvalidBackupConfigError({
			message: "BackupOptions.compression.threads must be a positive integer",
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: "compression.threads must be a positive integer" },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		return {
			format,
			threads
		};
	}
	static PRESIGNED_URL_EXPIRY_SECONDS = 3600;
	/**
	* Create a unique, dedicated session for a single backup operation.
	* Each call produces a fresh session ID so concurrent or sequential
	* operations never share shell state. Callers must destroy the session
	* in a finally block via `client.utils.deleteSession()`.
	*/
	async ensureBackupSession() {
		const sessionId = `__sandbox_backup_${crypto.randomUUID()}`;
		await this.client.utils.createSession({
			id: sessionId,
			cwd: "/"
		});
		return sessionId;
	}
	/**
	* Returns validated presigned URL configuration or throws if not configured.
	* All credential fields plus the R2 binding are required for backup to work.
	*/
	requirePresignedURLSupport() {
		if (!this.r2Client || !this.r2AccountId || !this.backupBucketName) {
			const missing = [];
			if (!this.r2AccountId) missing.push("CLOUDFLARE_R2_ACCOUNT_ID or CLOUDFLARE_ACCOUNT_ID");
			if (!this.r2AccessKeyId) missing.push("R2_ACCESS_KEY_ID");
			if (!this.r2SecretAccessKey) missing.push("R2_SECRET_ACCESS_KEY");
			if (!this.backupBucketName) missing.push("BACKUP_BUCKET_NAME");
			throw new InvalidBackupConfigError({
				message: `Backup requires R2 presigned URL credentials. Missing: ${missing.join(", ")}. Set these as environment variables or secrets in your wrangler.jsonc.`,
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: `Missing env vars: ${missing.join(", ")}` },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
		return {
			client: this.r2Client,
			accountId: this.r2AccountId,
			bucketName: this.backupBucketName
		};
	}
	getBackupBucketEndpoint(accountId) {
		return this.backupBucketEndpoint ?? `https://${accountId}.r2.cloudflarestorage.com`;
	}
	getBackupObjectURL(accountId, bucketName, r2Key) {
		const encodedBucket = encodeURIComponent(bucketName);
		const encodedKey = r2Key.split("/").map((seg) => encodeURIComponent(seg)).join("/");
		return new URL(`${this.getBackupBucketEndpoint(accountId)}/${encodedBucket}/${encodedKey}`);
	}
	/**
	* Generate a presigned GET URL for downloading an object from R2.
	* The container can curl this URL directly without credentials.
	*/
	async generatePresignedGetURL(r2Key) {
		const { client, accountId, bucketName } = this.requirePresignedURLSupport();
		const url = this.getBackupObjectURL(accountId, bucketName, r2Key);
		url.searchParams.set("X-Amz-Expires", String(Sandbox.PRESIGNED_URL_EXPIRY_SECONDS));
		return (await client.sign(new Request(url), { aws: { signQuery: true } })).url;
	}
	/**
	* Generate a presigned PUT URL for uploading an object to R2.
	* The container can curl PUT to this URL directly without credentials.
	*/
	async generatePresignedPutURL(r2Key) {
		const { client, accountId, bucketName } = this.requirePresignedURLSupport();
		const url = this.getBackupObjectURL(accountId, bucketName, r2Key);
		url.searchParams.set("X-Amz-Expires", String(Sandbox.PRESIGNED_URL_EXPIRY_SECONDS));
		return (await client.sign(new Request(url, { method: "PUT" }), { aws: { signQuery: true } })).url;
	}
	/**
	* Upload a backup archive via presigned PUT URL.
	* The container curls the archive directly to R2, bypassing the DO.
	* ~24 MB/s throughput vs ~0.6 MB/s for base64 readFile.
	*/
	async uploadBackupPresigned(archivePath, r2Key, archiveSize, backupId, dir, backupSession) {
		const presignedURL = await this.generatePresignedPutURL(r2Key);
		const curlCmd = [
			"curl -sSf",
			"-X PUT",
			"-H 'Content-Type: application/octet-stream'",
			"--connect-timeout 10",
			"--max-time 1800",
			"--retry 2",
			"--retry-max-time 60",
			`-T ${shellEscape(archivePath)}`,
			shellEscape(presignedURL)
		].join(" ");
		const result = await this.execWithSession(curlCmd, backupSession, {
			timeout: 181e4,
			origin: "internal"
		});
		if (result.exitCode !== 0) throw new BackupCreateError({
			message: `Presigned URL upload failed (exit code ${result.exitCode}): ${result.stderr}`,
			code: ErrorCode.BACKUP_CREATE_FAILED,
			httpStatus: 500,
			context: {
				dir,
				backupId
			},
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		const head = await this.requireBackupBucket().head(r2Key);
		if (!head || head.size !== archiveSize) {
			const actualSize = head?.size ?? 0;
			throw new BackupCreateError({
				message: `Upload verification failed: expected ${archiveSize} bytes, got ${actualSize}.${result.exitCode === 0 && actualSize === 0 ? " This usually means the BACKUP_BUCKET R2 binding is using local storage while presigned URLs upload to remote R2. Add `\"remote\": true` to your BACKUP_BUCKET R2 binding in wrangler.jsonc to fix this." : ""}`,
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
	}
	/**
	* Generate a presigned PUT URL for a single part in a multipart upload.
	*/
	async generatePresignedPartURL(r2Key, uploadId, partNumber) {
		const { client, accountId, bucketName } = this.requirePresignedURLSupport();
		const url = this.getBackupObjectURL(accountId, bucketName, r2Key);
		url.searchParams.set("X-Amz-Expires", String(Sandbox.PRESIGNED_URL_EXPIRY_SECONDS));
		url.searchParams.set("partNumber", String(partNumber));
		url.searchParams.set("uploadId", uploadId);
		return (await client.sign(new Request(url, { method: "PUT" }), { aws: { signQuery: true } })).url;
	}
	/**
	* Upload a backup archive to R2 using parallel multipart upload.
	* Uses the S3-compatible API exclusively for create/complete/abort so that
	* the uploadId is in the same namespace as the presigned part PUT URLs.
	*/
	async uploadBackupMultipart(archivePath, r2Key, sizeBytes, backupId, dir, backupSession) {
		const targetParts = calculatePartCount(sizeBytes, BACKUP_MULTIPART_TARGET_PARTS, BACKUP_MULTIPART_MAX_PARTS);
		const numParts = Math.min(targetParts, Math.floor(sizeBytes / BACKUP_MULTIPART_MIN_PART_SIZE));
		if (numParts <= 1) return this.uploadBackupPresigned(archivePath, r2Key, sizeBytes, backupId, dir, backupSession);
		const { client, accountId, bucketName } = this.requirePresignedURLSupport();
		const objectURL = this.getBackupObjectURL(accountId, bucketName, r2Key).toString();
		const createResp = await client.fetch(`${objectURL}?uploads`, { method: "POST" });
		if (!createResp.ok) throw new BackupCreateError({
			message: `Failed to initiate multipart upload: HTTP ${createResp.status}`,
			code: ErrorCode.BACKUP_CREATE_FAILED,
			httpStatus: 500,
			context: {
				dir,
				backupId
			},
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		const uploadId = (await createResp.text()).match(/<UploadId>([^<]+)<\/UploadId>/)?.[1];
		if (!uploadId) throw new BackupCreateError({
			message: "Multipart upload response did not contain an UploadId",
			code: ErrorCode.BACKUP_CREATE_FAILED,
			httpStatus: 500,
			context: {
				dir,
				backupId
			},
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		const abortMultipart = async () => {
			await client.fetch(`${objectURL}?uploadId=${encodeURIComponent(uploadId)}`, { method: "DELETE" }).catch(() => {});
		};
		try {
			const partSize = Math.ceil(sizeBytes / numParts);
			const parts = await Promise.all(Array.from({ length: numParts }, (_, i) => ({
				partNumber: i + 1,
				url: "",
				offset: i * partSize,
				size: i === numParts - 1 ? sizeBytes - i * partSize : partSize
			})).map(async (part) => ({
				...part,
				url: await this.generatePresignedPartURL(r2Key, uploadId, part.partNumber)
			})));
			let uploadResult;
			try {
				uploadResult = await this.client.backup.uploadParts({
					archivePath,
					parts,
					sessionId: backupSession
				});
			} catch (err) {
				if (err instanceof SandboxError && err.errorResponse.httpStatus === 404) {
					await abortMultipart();
					return this.uploadBackupPresigned(archivePath, r2Key, sizeBytes, backupId, dir, backupSession);
				}
				throw err;
			}
			if (!uploadResult.success || uploadResult.parts.length !== numParts) throw new BackupCreateError({
				message: `Multipart upload returned ${uploadResult.parts.length} of ${numParts} parts`,
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const completeXml = [
				"<CompleteMultipartUpload>",
				...uploadResult.parts.map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${p.etag}</ETag></Part>`),
				"</CompleteMultipartUpload>"
			].join("");
			const completeResp = await client.fetch(`${objectURL}?uploadId=${encodeURIComponent(uploadId)}`, {
				method: "POST",
				headers: { "Content-Type": "application/xml" },
				body: completeXml
			});
			if (!completeResp.ok) {
				const body = await completeResp.text().catch(() => "");
				throw new BackupCreateError({
					message: `Multipart upload completion failed: HTTP ${completeResp.status} ${body}`,
					code: ErrorCode.BACKUP_CREATE_FAILED,
					httpStatus: 500,
					context: {
						dir,
						backupId
					},
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			const head = await this.requireBackupBucket().head(r2Key);
			if (!head || head.size !== sizeBytes) throw new BackupCreateError({
				message: `Multipart upload verification failed: expected ${sizeBytes} bytes, got ${head?.size ?? 0}`,
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		} catch (error) {
			await abortMultipart();
			throw error;
		}
	}
	/**
	* Download a backup archive from R2 via presigned GET URL.
	* For archives >= BACKUP_DOWNLOAD_PARALLEL_MIN_SIZE, uses BACKUP_DOWNLOAD_PARALLEL_PARTS
	* concurrent curl processes (each downloading a byte-range) to maximise both
	* network and disk-write throughput. Parts are written into a pre-sized file
	* with dd using byte offsets, then atomically moved to the final path.
	*/
	async downloadBackupParallel(archivePath, r2Key, expectedSize, backupId, dir, backupSession) {
		const presignedURL = await this.generatePresignedGetURL(r2Key);
		await this.execWithSession(`mkdir -p ${BACKUP_CONTAINER_DIR}`, backupSession, { origin: "internal" });
		const tmpPath = `${archivePath}.tmp`;
		if (expectedSize < BACKUP_DOWNLOAD_PARALLEL_MIN_SIZE) {
			const curlCmd = [
				"curl -sSf",
				"--connect-timeout 10",
				"--max-time 1800",
				"--retry 2",
				"--retry-max-time 60",
				`-o ${shellEscape(tmpPath)}`,
				shellEscape(presignedURL)
			].join(" ");
			const result = await this.execWithSession(curlCmd, backupSession, {
				timeout: 181e4,
				origin: "internal"
			});
			if (result.exitCode !== 0) {
				await this.execWithSession(`rm -f ${shellEscape(tmpPath)}`, backupSession, { origin: "internal" }).catch(() => {});
				throw new BackupRestoreError({
					message: `Presigned URL download failed (exit code ${result.exitCode}): ${result.stderr}`,
					code: ErrorCode.BACKUP_RESTORE_FAILED,
					httpStatus: 500,
					context: {
						dir,
						backupId
					},
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
		} else {
			const numParts = calculatePartCount(expectedSize, BACKUP_DOWNLOAD_PARALLEL_PARTS, BACKUP_DOWNLOAD_MAX_PARTS);
			const partSize = Math.floor(expectedSize / numParts);
			const startLines = Array.from({ length: numParts }, (_, i) => {
				const start = i * partSize;
				return {
					start,
					range: `${start}-${i < numParts - 1 ? start + partSize - 1 : expectedSize - 1}`
				};
			}).map(({ start, range }) => [
				"curl -sSf",
				"--connect-timeout 10",
				"--max-time 1800",
				`-H ${shellEscape(`Range: bytes=${range}`)}`,
				shellEscape(presignedURL),
				"|",
				"dd",
				`of=${shellEscape(tmpPath)}`,
				"oflag=seek_bytes",
				`seek=${start}`,
				"conv=notrunc",
				"2>/dev/null"
			].join(" ")).map((cmd, i) => `(set -o pipefail; ${cmd}) & J${i}=$!`);
			const waitLines = Array.from({ length: numParts }, (_, i) => `wait $J${i}; E${i}=$?`);
			const exitVars = Array.from({ length: numParts }, (_, i) => `$E${i}`);
			const script = [
				`rm -f ${shellEscape(tmpPath)}`,
				`truncate -s ${expectedSize} ${shellEscape(tmpPath)}`,
				...startLines,
				...waitLines,
				`FAILED=$(( ${exitVars.join(" + ")} ))`,
				`if [ "$FAILED" -ne 0 ]; then echo "download part exit codes: ${exitVars.join(" ")}" >&2; rm -f ${shellEscape(tmpPath)}; exit 1; fi`
			].join("; ");
			const result = await this.execWithSession(`( ${script} )`, backupSession, {
				timeout: 181e4,
				origin: "internal"
			});
			if (result.exitCode !== 0) {
				await this.execWithSession(`rm -f ${shellEscape(tmpPath)}`, backupSession, { origin: "internal" }).catch(() => {});
				throw new BackupRestoreError({
					message: `Parallel download failed (exit code ${result.exitCode}): ${result.stderr}`,
					code: ErrorCode.BACKUP_RESTORE_FAILED,
					httpStatus: 500,
					context: {
						dir,
						backupId
					},
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
		}
		const sizeCheck = await this.execWithSession(`stat -c %s ${shellEscape(tmpPath)}`, backupSession, { origin: "internal" });
		const actualSize = parseInt(sizeCheck.stdout.trim(), 10);
		if (actualSize !== expectedSize) {
			await this.execWithSession(`rm -f ${shellEscape(tmpPath)}`, backupSession, { origin: "internal" }).catch(() => {});
			throw new BackupRestoreError({
				message: `Downloaded archive size mismatch: expected ${expectedSize}, got ${actualSize}`,
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
		const mvResult = await this.execWithSession(`mv ${shellEscape(tmpPath)} ${shellEscape(archivePath)}`, backupSession, { origin: "internal" });
		if (mvResult.exitCode !== 0) {
			await this.execWithSession(`rm -f ${shellEscape(tmpPath)}`, backupSession, { origin: "internal" }).catch(() => {});
			throw new BackupRestoreError({
				message: `Failed to finalize downloaded archive: ${mvResult.stderr}`,
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
		}
	}
	/**
	* Serialize backup operations on this sandbox instance.
	* Concurrent backup/restore calls are queued so the multi-step
	* create-archive → read → upload (or mount → extract) flow
	* is not interleaved with another backup operation on the same directory.
	*/
	async enqueueBackupOp(fn) {
		try {
			await this.backupInProgress;
		} catch {}
		const next = fn();
		this.backupInProgress = next.catch(() => {});
		return await next;
	}
	/**
	* Create a backup of a directory and upload it to R2.
	*
	* Flow:
	*   1. Container creates squashfs archive from the directory
	*   2. Container uploads the archive directly to R2 via presigned URL
	*   3. DO writes metadata to R2
	*   4. Container cleans up the local archive
	*
	* The returned DirectoryBackup handle is serializable. Store it anywhere
	* (KV, D1, DO storage) and pass it to restoreBackup() later.
	*
	* Concurrent backup/restore calls on the same sandbox are serialized.
	*
	* Partially-written files in the target directory may not be captured
	* consistently. Completed writes are captured.
	*
	* NOTE: Expired backups are not automatically deleted from R2. Configure
	* R2 lifecycle rules on the BACKUP_BUCKET to garbage-collect objects
	* under the `backups/` prefix after the desired retention period.
	*/
	async createBackup(options) {
		if (options.localBucket) return await this.enqueueBackupOp(() => this.doCreateBackupLocal(options));
		this.requireBackupBucket();
		return await this.enqueueBackupOp(() => this.doCreateBackup(options));
	}
	async doCreateBackup(options) {
		const bucket = this.requireBackupBucket();
		this.requirePresignedURLSupport();
		const { dir, name, ttl = BACKUP_DEFAULT_TTL_SECONDS, gitignore = false, excludes = [], compression, multipart = true } = options;
		const backupStartTime = Date.now();
		let backupId;
		let sizeBytes;
		let outcome = "error";
		let caughtError;
		let backupSession;
		try {
			Sandbox.validateBackupDir(dir, "BackupOptions.dir");
			if (name !== void 0) {
				if (typeof name !== "string" || name.length > BACKUP_MAX_NAME_LENGTH) throw new InvalidBackupConfigError({
					message: `BackupOptions.name must be a string of at most ${BACKUP_MAX_NAME_LENGTH} characters`,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: `name must be a string of at most ${BACKUP_MAX_NAME_LENGTH} characters` },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
				if (/[\u0000-\u001f\u007f]/.test(name)) throw new InvalidBackupConfigError({
					message: "BackupOptions.name must not contain control characters",
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: "name must not contain control characters" },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			if (ttl <= 0) throw new InvalidBackupConfigError({
				message: "BackupOptions.ttl must be a positive number of seconds",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "ttl must be a positive number of seconds" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (typeof gitignore !== "boolean") throw new InvalidBackupConfigError({
				message: "BackupOptions.gitignore must be a boolean",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "gitignore must be a boolean" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (!Array.isArray(excludes) || !excludes.every((e) => typeof e === "string")) throw new InvalidBackupConfigError({
				message: "BackupOptions.excludes must be an array of strings",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "excludes must be an array of strings" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const resolvedCompression = this.resolveBackupCompression(compression);
			const normalizedExcludes = this.normalizeBackupExcludes(excludes);
			backupSession = await this.ensureBackupSession();
			backupId = crypto.randomUUID();
			const archivePath = `${BACKUP_CONTAINER_DIR}/${backupId}.sqsh`;
			const createResult = await this.client.backup.createArchive(dir, archivePath, backupSession, {
				gitignore,
				excludes: normalizedExcludes,
				compression: resolvedCompression
			});
			if (!createResult.success) throw new BackupCreateError({
				message: "Container failed to create backup archive",
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			sizeBytes = createResult.sizeBytes;
			const r2Key = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
			const metaKey = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_METADATA_OBJECT_NAME}`;
			if (multipart && createResult.sizeBytes >= BACKUP_MULTIPART_MIN_SIZE) await this.uploadBackupMultipart(archivePath, r2Key, createResult.sizeBytes, backupId, dir, backupSession);
			else await this.uploadBackupPresigned(archivePath, r2Key, createResult.sizeBytes, backupId, dir, backupSession);
			const metadata = {
				id: backupId,
				dir,
				name: name || null,
				sizeBytes: createResult.sizeBytes,
				ttl,
				createdAt: (/* @__PURE__ */ new Date()).toISOString()
			};
			await bucket.put(metaKey, JSON.stringify(metadata));
			outcome = "success";
			await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
			return {
				id: backupId,
				dir
			};
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			if (backupId && backupSession) {
				const archivePath = `${BACKUP_CONTAINER_DIR}/${backupId}.sqsh`;
				const r2Key = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
				const metaKey = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_METADATA_OBJECT_NAME}`;
				await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
				await bucket.delete(r2Key).catch(() => {});
				await bucket.delete(metaKey).catch(() => {});
			}
			throw error;
		} finally {
			if (backupSession) await this.client.utils.deleteSession(backupSession).catch(() => {});
			logCanonicalEvent(this.logger, {
				event: "backup.create",
				outcome,
				durationMs: Date.now() - backupStartTime,
				backupId,
				dir,
				name,
				sizeBytes,
				error: caughtError
			});
		}
	}
	/**
	* Local-dev implementation of createBackup.
	* Uses the R2 binding directly instead of presigned URLs.
	* Archive format is identical to production (squashfs + meta.json).
	*/
	async doCreateBackupLocal(options) {
		const { dir, name, ttl = BACKUP_DEFAULT_TTL_SECONDS, gitignore = false, excludes = [], compression } = options;
		const backupStartTime = Date.now();
		let backupId;
		let sizeBytes;
		let outcome = "error";
		let caughtError;
		let backupSession;
		const bucket = this.env.BACKUP_BUCKET;
		if (!bucket || !isR2Bucket(bucket)) throw new InvalidBackupConfigError({
			message: "BACKUP_BUCKET R2 binding not found in env. Add a BACKUP_BUCKET R2 binding to your wrangler.jsonc for local backup support.",
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: "Missing BACKUP_BUCKET R2 binding" },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		try {
			Sandbox.validateBackupDir(dir, "BackupOptions.dir");
			if (name !== void 0) {
				if (typeof name !== "string" || name.length > BACKUP_MAX_NAME_LENGTH) throw new InvalidBackupConfigError({
					message: `BackupOptions.name must be a string of at most ${BACKUP_MAX_NAME_LENGTH} characters`,
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: `name must be a string of at most ${BACKUP_MAX_NAME_LENGTH} characters` },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
				if (/[\u0000-\u001f\u007f]/.test(name)) throw new InvalidBackupConfigError({
					message: "BackupOptions.name must not contain control characters",
					code: ErrorCode.INVALID_BACKUP_CONFIG,
					httpStatus: 400,
					context: { reason: "name must not contain control characters" },
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			if (ttl <= 0) throw new InvalidBackupConfigError({
				message: "BackupOptions.ttl must be a positive number of seconds",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "ttl must be a positive number of seconds" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (typeof gitignore !== "boolean") throw new InvalidBackupConfigError({
				message: "BackupOptions.gitignore must be a boolean",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "gitignore must be a boolean" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (!Array.isArray(excludes) || !excludes.every((e) => typeof e === "string")) throw new InvalidBackupConfigError({
				message: "BackupOptions.excludes must be an array of strings",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "excludes must be an array of strings" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const resolvedCompression = this.resolveBackupCompression(compression);
			const normalizedExcludes = this.normalizeBackupExcludes(excludes);
			backupSession = await this.ensureBackupSession();
			backupId = crypto.randomUUID();
			const archivePath = `${BACKUP_CONTAINER_DIR}/${backupId}.sqsh`;
			const createResult = await this.client.backup.createArchive(dir, archivePath, backupSession, {
				gitignore,
				excludes: normalizedExcludes,
				compression: resolvedCompression
			});
			if (!createResult.success) throw new BackupCreateError({
				message: "Container failed to create backup archive",
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			sizeBytes = createResult.sizeBytes;
			const r2Key = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
			const metaKey = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_METADATA_OBJECT_NAME}`;
			const archiveStream = await this.client.files.readFileStream(archivePath, backupSession);
			const sseDecoded = new ReadableStream({ async start(controller) {
				try {
					for await (const chunk of streamFile(archiveStream)) if (chunk instanceof Uint8Array) controller.enqueue(chunk);
					controller.close();
				} catch (err) {
					controller.error(err);
				}
			} });
			const fixedStream = new FixedLengthStream(createResult.sizeBytes);
			sseDecoded.pipeTo(fixedStream.writable).catch(() => {});
			await bucket.put(r2Key, fixedStream.readable);
			const head = await bucket.head(r2Key);
			if (!head || head.size !== createResult.sizeBytes) throw new BackupCreateError({
				message: `Upload verification failed: expected ${createResult.sizeBytes} bytes, got ${head?.size ?? 0}`,
				code: ErrorCode.BACKUP_CREATE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const metadata = {
				id: backupId,
				dir,
				name: name || null,
				sizeBytes: createResult.sizeBytes,
				ttl,
				createdAt: (/* @__PURE__ */ new Date()).toISOString()
			};
			await bucket.put(metaKey, JSON.stringify(metadata));
			outcome = "success";
			await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
			return {
				id: backupId,
				dir,
				localBucket: true
			};
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			if (backupId && backupSession) {
				const archivePath = `${BACKUP_CONTAINER_DIR}/${backupId}.sqsh`;
				const r2Key = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
				const metaKey = `${BACKUP_STORAGE_PREFIX}/${backupId}/${BACKUP_METADATA_OBJECT_NAME}`;
				await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
				await bucket.delete(r2Key).catch(() => {});
				await bucket.delete(metaKey).catch(() => {});
			}
			throw error;
		} finally {
			if (backupSession) await this.client.utils.deleteSession(backupSession).catch(() => {});
			logCanonicalEvent(this.logger, {
				event: "backup.create",
				outcome,
				durationMs: Date.now() - backupStartTime,
				backupId,
				dir,
				name,
				sizeBytes,
				provider: "local-binding",
				error: caughtError
			});
		}
	}
	/**
	* Restore a backup from R2 into a directory.
	*
	* **Production flow** (`localBucket` not set):
	*   1. DO reads metadata from R2 and checks TTL
	*   2. Container mounts the backup archive from R2 via s3fs
	*   3. Container mounts the squashfs archive with FUSE overlayfs
	*
	* The target directory becomes an overlay mount with the backup as a
	* read-only lower layer and a writable upper layer for copy-on-write.
	* Any processes writing to the directory should be stopped first.
	*
	* **Mount Lifecycle**: The FUSE overlay mount persists only while the
	* container is running. When the sandbox sleeps or the container restarts,
	* the mount is lost and the directory becomes empty. Re-restore from the
	* backup handle to recover. This is an ephemeral restore, not a persistent
	* extraction.
	*
	* **Local-dev flow** (`localBucket: true` on the originating `createBackup` call):
	*   1. DO reads metadata and checks TTL via R2 binding
	*   2. DO downloads the archive from R2 and writes it to the container
	*   3. Container extracts the archive with `unsquashfs` (no FUSE needed)
	*
	* The backup is restored into `backup.dir`. This may differ from the
	* directory that was originally backed up, allowing cross-directory restore.
	*
	* Overlapping backups are independent: restoring a parent directory
	* overwrites everything inside it, including subdirectories that were
	* backed up separately. When restoring both, restore the parent first.
	*
	* Concurrent backup/restore calls on the same sandbox are serialized.
	*/
	async restoreBackup(backup) {
		if (!backup.localBucket) this.requireBackupBucket();
		return await this.enqueueBackupOp(() => this.doRestoreBackupWithRecovery(backup));
	}
	async doRestoreBackupWithRecovery(backup) {
		return await new RestoreLifecycleRunner({
			storage: this.ctx.storage,
			currentRuntime: this.currentRuntime,
			currentLifetime: this.currentLifetime
		}).execute({
			backupId: backup.id,
			dir: backup.dir,
			attempt: async (lifecycle) => {
				if (backup.localBucket) return await this.doRestoreBackupLocal(backup, lifecycle);
				return await this.doRestoreBackup(backup, lifecycle);
			}
		});
	}
	async doRestoreBackup(backup, lifecycle) {
		const restoreStartTime = Date.now();
		const bucket = this.requireBackupBucket();
		this.requirePresignedURLSupport();
		const { id, dir } = backup;
		let outcome = "error";
		let caughtError;
		let backupSession;
		try {
			if (!id || typeof id !== "string") throw new InvalidBackupConfigError({
				message: "Invalid backup: missing or invalid id",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "missing or invalid id" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (!Sandbox.UUID_REGEX.test(id)) throw new InvalidBackupConfigError({
				message: "Invalid backup: id must be a valid UUID (e.g. from createBackup)",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "id must be a valid UUID" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			Sandbox.validateBackupDir(dir, "Invalid backup: dir");
			const metaKey = `${BACKUP_STORAGE_PREFIX}/${id}/${BACKUP_METADATA_OBJECT_NAME}`;
			const metaObject = await bucket.get(metaKey);
			if (!metaObject) throw new BackupNotFoundError({
				message: `Backup not found: ${id}. Verify the backup ID is correct and the backup has not been deleted.`,
				code: ErrorCode.BACKUP_NOT_FOUND,
				httpStatus: 404,
				context: { backupId: id },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const metadata = await metaObject.json();
			const TTL_BUFFER_MS = 6e4;
			const createdAt = new Date(metadata.createdAt).getTime();
			if (Number.isNaN(createdAt)) throw new BackupRestoreError({
				message: `Backup metadata has invalid createdAt timestamp: ${metadata.createdAt}`,
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId: id
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const expiresAt = createdAt + metadata.ttl * 1e3;
			if (Date.now() + TTL_BUFFER_MS > expiresAt) throw new BackupExpiredError({
				message: `Backup ${id} has expired (created: ${metadata.createdAt}, TTL: ${metadata.ttl}s). Create a new backup.`,
				code: ErrorCode.BACKUP_EXPIRED,
				httpStatus: 400,
				context: {
					backupId: id,
					expiredAt: new Date(expiresAt).toISOString()
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const r2Key = `${BACKUP_STORAGE_PREFIX}/${id}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
			const archiveHead = await bucket.head(r2Key);
			if (!archiveHead) throw new BackupNotFoundError({
				message: `Backup archive not found in R2: ${id}. The archive may have been deleted by R2 lifecycle rules.`,
				code: ErrorCode.BACKUP_NOT_FOUND,
				httpStatus: 404,
				context: { backupId: id },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			backupSession = await this.ensureBackupSession();
			await lifecycle.runtimeReady();
			const archivePath = `${BACKUP_CONTAINER_DIR}/${id}.sqsh`;
			const mountGlob = `${BACKUP_CONTAINER_DIR}/mounts/${id}`;
			await this.execWithSession(`/usr/bin/fusermount3 -uz ${shellEscape(dir)} 2>/dev/null || true`, backupSession, { origin: "internal" }).catch(() => {});
			await this.execWithSession(`for d in ${shellEscape(mountGlob)}_*/lower ${shellEscape(mountGlob)}/lower; do [ -d "$d" ] && /usr/bin/fusermount3 -uz "$d" 2>/dev/null; done; true`, backupSession, { origin: "internal" }).catch(() => {});
			const sizeCheck = await this.execWithSession(`stat -c %s ${shellEscape(archivePath)} 2>/dev/null || echo 0`, backupSession, { origin: "internal" }).catch(() => ({ stdout: "0" }));
			if (Number.parseInt((sizeCheck.stdout ?? "0").trim(), 10) !== archiveHead.size) await this.downloadBackupParallel(archivePath, r2Key, archiveHead.size, id, dir, backupSession);
			await lifecycle.archiveReady(archiveHead.size);
			if (!(await this.client.backup.restoreArchive(dir, archivePath, backupSession)).success) throw new BackupRestoreError({
				message: "Container failed to restore backup archive",
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId: id
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const result = {
				success: true,
				dir,
				id
			};
			await lifecycle.verify(result);
			outcome = "success";
			return result;
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			if (id && backupSession) {
				const cleanupPath = `${BACKUP_CONTAINER_DIR}/${id}.sqsh`;
				await this.execWithSession(`rm -f ${shellEscape(cleanupPath)}`, backupSession, { origin: "internal" }).catch(() => {});
			}
			throw error;
		} finally {
			if (backupSession) await this.client.utils.deleteSession(backupSession).catch(() => {});
			logCanonicalEvent(this.logger, {
				event: "backup.restore",
				outcome,
				durationMs: Date.now() - restoreStartTime,
				backupId: id,
				dir,
				error: caughtError
			});
		}
	}
	/**
	* Local-dev implementation of restoreBackup.
	* Uses the R2 binding directly instead of presigned URLs, and
	* unsquashfs for extraction instead of squashfuse + fuse-overlayfs.
	*/
	async doRestoreBackupLocal(backup, lifecycle) {
		const restoreStartTime = Date.now();
		const { id, dir } = backup;
		let outcome = "error";
		let caughtError;
		let backupSession;
		const bucket = this.env.BACKUP_BUCKET;
		if (!bucket || !isR2Bucket(bucket)) throw new InvalidBackupConfigError({
			message: "BACKUP_BUCKET R2 binding not found in env. Add a BACKUP_BUCKET R2 binding to your wrangler.jsonc for local backup support.",
			code: ErrorCode.INVALID_BACKUP_CONFIG,
			httpStatus: 400,
			context: { reason: "Missing BACKUP_BUCKET R2 binding" },
			timestamp: (/* @__PURE__ */ new Date()).toISOString()
		});
		try {
			if (!id || typeof id !== "string") throw new InvalidBackupConfigError({
				message: "Invalid backup: missing or invalid id",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "missing or invalid id" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			if (!Sandbox.UUID_REGEX.test(id)) throw new InvalidBackupConfigError({
				message: "Invalid backup: id must be a valid UUID (e.g. from createBackup)",
				code: ErrorCode.INVALID_BACKUP_CONFIG,
				httpStatus: 400,
				context: { reason: "id must be a valid UUID" },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			Sandbox.validateBackupDir(dir, "Invalid backup: dir");
			const metaKey = `${BACKUP_STORAGE_PREFIX}/${id}/${BACKUP_METADATA_OBJECT_NAME}`;
			const metaObject = await bucket.get(metaKey);
			if (!metaObject) throw new BackupNotFoundError({
				message: `Backup not found: ${id}. Verify the backup ID is correct and the backup has not been deleted.`,
				code: ErrorCode.BACKUP_NOT_FOUND,
				httpStatus: 404,
				context: { backupId: id },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const metadata = await metaObject.json();
			const TTL_BUFFER_MS = 6e4;
			const createdAt = new Date(metadata.createdAt).getTime();
			if (Number.isNaN(createdAt)) throw new BackupRestoreError({
				message: `Backup metadata has invalid createdAt timestamp: ${metadata.createdAt}`,
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId: id
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const expiresAt = createdAt + metadata.ttl * 1e3;
			if (Date.now() + TTL_BUFFER_MS > expiresAt) throw new BackupExpiredError({
				message: `Backup ${id} has expired (created: ${metadata.createdAt}, TTL: ${metadata.ttl}s). Create a new backup.`,
				code: ErrorCode.BACKUP_EXPIRED,
				httpStatus: 400,
				context: {
					backupId: id,
					expiredAt: new Date(expiresAt).toISOString()
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const r2Key = `${BACKUP_STORAGE_PREFIX}/${id}/${BACKUP_ARCHIVE_OBJECT_NAME}`;
			const archiveObject = await bucket.get(r2Key);
			if (!archiveObject) throw new BackupNotFoundError({
				message: `Backup archive not found in R2: ${id}. The archive may have been deleted by R2 lifecycle rules.`,
				code: ErrorCode.BACKUP_NOT_FOUND,
				httpStatus: 404,
				context: { backupId: id },
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const archiveSize = metadata.sizeBytes;
			backupSession = await this.ensureBackupSession();
			await lifecycle.runtimeReady();
			const archivePath = `${BACKUP_CONTAINER_DIR}/${id}.sqsh`;
			await this.execWithSession(`mkdir -p ${BACKUP_CONTAINER_DIR}`, backupSession, { origin: "internal" });
			if (this.transport === "rpc") {
				const body = archiveObject.body;
				if (!body) throw new BackupRestoreError({
					message: `R2 archive object has no body stream for backup ${id}`,
					code: ErrorCode.BACKUP_RESTORE_FAILED,
					httpStatus: 500,
					context: {
						dir,
						backupId: id
					},
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
				await this.client.files.writeFileStream(archivePath, body, backupSession);
			} else {
				const archiveBuffer = await archiveObject.arrayBuffer();
				const base64Content = Buffer.from(archiveBuffer).toString("base64");
				const writeResult = await this.client.files.writeFile(archivePath, base64Content, backupSession, { encoding: "base64" });
				if (!writeResult.success) throw new BackupRestoreError({
					message: `Failed to write backup archive to ${archivePath}: ${"error" in writeResult && typeof writeResult.error === "object" && writeResult.error !== null && "message" in writeResult.error && typeof writeResult.error.message === "string" ? writeResult.error.message : `File write returned success: false for '${archivePath}'`}`,
					code: ErrorCode.BACKUP_RESTORE_FAILED,
					httpStatus: 500,
					context: {
						dir,
						backupId: id
					},
					timestamp: (/* @__PURE__ */ new Date()).toISOString()
				});
			}
			await lifecycle.archiveReady(archiveSize);
			const extractResult = await this.execWithSession(`/usr/bin/unsquashfs -f -d ${shellEscape(dir)} ${shellEscape(archivePath)}`, backupSession, { origin: "internal" });
			if (extractResult.exitCode !== 0) throw new BackupRestoreError({
				message: `unsquashfs extraction failed (exit code ${extractResult.exitCode}): ${extractResult.stderr}`,
				code: ErrorCode.BACKUP_RESTORE_FAILED,
				httpStatus: 500,
				context: {
					dir,
					backupId: id
				},
				timestamp: (/* @__PURE__ */ new Date()).toISOString()
			});
			const result = {
				success: true,
				dir,
				id
			};
			await lifecycle.verify(result);
			await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
			outcome = "success";
			return result;
		} catch (error) {
			caughtError = error instanceof Error ? error : new Error(String(error));
			if (id && backupSession) {
				const archivePath = `${BACKUP_CONTAINER_DIR}/${id}.sqsh`;
				await this.execWithSession(`rm -f ${shellEscape(archivePath)}`, backupSession, { origin: "internal" }).catch(() => {});
			}
			throw error;
		} finally {
			if (backupSession) await this.client.utils.deleteSession(backupSession).catch(() => {});
			logCanonicalEvent(this.logger, {
				event: "backup.restore",
				outcome,
				durationMs: Date.now() - restoreStartTime,
				backupId: id,
				dir,
				provider: "local-binding",
				error: caughtError
			});
		}
	}
	/**
	* Drop the routes restored for the mounts of a container that has stopped.
	*/
	async releaseRestoredMountRoutes() {
		const { r2Buckets, credentialProxyMounts } = this.restoredMountRoutes;
		this.restoredMountRoutes = noRestoredMountRoutes();
		for (const mountId of Object.keys(credentialProxyMounts)) {
			evictSigV4ClientCacheEntry(mountId);
			evictDirectoryMarkerCacheForMount(mountId);
		}
		if (Object.keys(r2Buckets).length > 0) this.staleMountRoutes.r2 = true;
		if (Object.keys(credentialProxyMounts).length > 0) this.staleMountRoutes.credentialProxy = true;
		await this.removeStaleMountRoutes();
	}
	/**
	* Rewrite the routes that still carry a stopped container's restored
	* mounts so they cover only the mounts in activeMounts. A failed update
	* stays marked and is retried on the next container start or stop.
	*/
	async removeStaleMountRoutes() {
		if (this.staleMountRoutes.r2) try {
			await this.configureR2EgressOutbound(this.getR2EgressParams());
			this.staleMountRoutes.r2 = false;
		} catch (error) {
			this.logger.warn("Failed to remove stale R2 mount routes", { error: error instanceof Error ? error.message : String(error) });
		}
		if (this.staleMountRoutes.credentialProxy) try {
			await this.configureS3CredentialProxyOutbound(this.getS3CredentialProxyParams());
			this.staleMountRoutes.credentialProxy = false;
		} catch (error) {
			this.logger.warn("Failed to remove stale credential proxy mount routes", { error: error instanceof Error ? error.message : String(error) });
		}
	}
	async configureR2EgressOutbound(activeParams) {
		const params = { buckets: {
			...this.restoredMountRoutes.r2Buckets,
			...activeParams.buckets
		} };
		const ctx = this.ctx;
		if (!ctx.container?.interceptOutboundHttp) throw new InvalidMountConfigError("R2 binding mounts require container outbound interception support");
		if (!ctx.exports?.ContainerProxy) throw new InvalidMountConfigError("R2 binding mounts require exporting ContainerProxy from the Worker entrypoint");
		if (Object.keys(params.buckets).length > 0) await this.setOutboundByHost("r2.internal", "r2EgressMount", params);
		else await this.removeOutboundByHost("r2.internal");
		this.logger.debug("r2 egress: registering host interception", {
			host: "r2.internal",
			method: "r2EgressMount",
			targetClassName: CONTAINER_PROXY_CLASS_NAME
		});
		const fetcher = ctx.exports.ContainerProxy({ props: {
			enableInternet: this.enableInternet,
			containerId: this.ctx.id.toString(),
			className: CONTAINER_PROXY_CLASS_NAME,
			outboundByHostOverrides: { "r2.internal": {
				method: "r2EgressMount",
				params
			} }
		} });
		if (!isFetcher(fetcher)) throw new InvalidMountConfigError("R2 binding mounts require ContainerProxy to return a valid Fetcher");
		await ctx.container.interceptOutboundHttp("r2.internal", fetcher);
	}
	async configureS3CredentialProxyOutbound(activeParams) {
		const params = { mounts: {
			...this.restoredMountRoutes.credentialProxyMounts,
			...activeParams.mounts
		} };
		const ctx = this.ctx;
		if (!ctx.container?.interceptOutboundHttp) throw new InvalidMountConfigError("Credential proxy bucket mounts require container outbound interception support");
		if (!ctx.exports?.ContainerProxy) throw new InvalidMountConfigError("Credential proxy bucket mounts require exporting ContainerProxy from the Worker entrypoint");
		const hosts = [S3_CREDENTIAL_PROXY_HOST, S3_CREDENTIAL_PROXY_DIAGNOSTIC_HOST];
		if (Object.keys(params.mounts).length > 0) for (const host of hosts) await this.setOutboundByHost(host, "s3CredentialProxyMount", params);
		else for (const host of hosts) await this.removeOutboundByHost(host);
		const hostOverrides = {};
		for (const host of hosts) hostOverrides[host] = {
			method: "s3CredentialProxyMount",
			params
		};
		this.logger.debug("s3 credential proxy: registering host interception", {
			hosts,
			method: "s3CredentialProxyMount",
			targetClassName: CONTAINER_PROXY_CLASS_NAME
		});
		const fetcher = ctx.exports.ContainerProxy({ props: {
			enableInternet: this.enableInternet,
			containerId: this.ctx.id.toString(),
			className: CONTAINER_PROXY_CLASS_NAME,
			outboundByHostOverrides: hostOverrides
		} });
		if (!isFetcher(fetcher)) throw new InvalidMountConfigError("Credential proxy bucket mounts require ContainerProxy to return a valid Fetcher");
		try {
			const selfTest = await fetcher.fetch(new Request(`http://${S3_CREDENTIAL_PROXY_HOST}${SELF_TEST_PATH}`));
			await selfTest.text();
			this.logger.debug("s3 credential proxy: fetcher self-test complete", { status: selfTest.status });
		} catch (error) {
			this.logger.warn("s3 credential proxy: fetcher self-test failed", { error: error instanceof Error ? error.message : String(error) });
		}
		for (const host of hosts) await ctx.container.interceptOutboundHttp(host, fetcher);
	}
};
// \0virtual:cloudflare/worker-entry
var worker_entry_default = { async fetch(request, env) {
	if (request.headers.get("authorization") !== `Bearer ${env.BUILD_TOKEN}`) return new Response("unauthorized", { status: 401 });
	if (request.method !== "POST") return new Response("POST only", { status: 405 });
	const box = getSandbox(env.Sandbox, "builder", { sleepAfter: "60m" });
	const path = new URL(request.url).pathname;
	const body = await request.json();
	if (path === "/exec" && body.cmd) {
		const r = await box.exec(body.cmd);
		return Response.json({
			exitCode: r.exitCode,
			stdout: r.stdout,
			stderr: r.stderr
		});
	}
	if (path === "/write" && body.path && body.content !== void 0) {
		await box.writeFile(body.path, body.content);
		return Response.json({ ok: true });
	}
	return new Response("not found", { status: 404 });
} };
export { Sandbox, worker_entry_default as default };

//# sourceMappingURL=index.js.map