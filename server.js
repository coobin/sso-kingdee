const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3002);
const APP_BASE_URL = requiredEnv("APP_BASE_URL");
const SESSION_SECRET = requiredEnv("SESSION_SECRET");

const AUTH_MODE = process.env.AUTH_MODE || "trusted_headers";
const AUTH_LOGIN_URL = process.env.AUTH_LOGIN_URL || "";
const AUTH_EXCHANGE_URL = process.env.AUTH_EXCHANGE_URL || "";
const AUTH_EXCHANGE_TOKEN = process.env.AUTH_EXCHANGE_TOKEN || "";
const AUTH_EXCHANGE_TIMEOUT_MS = Number(
  process.env.AUTH_EXCHANGE_TIMEOUT_MS || 5000,
);

const KINGDEE_COOKIE_NAME =
  process.env.KINGDEE_COOKIE_NAME || "kingdee_sso_session";
const COOKIE_SECURE = boolEnv("COOKIE_SECURE", true);
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || "";
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 3600);

const KINGDEE_BASE_URL = requiredEnv("KINGDEE_BASE_URL");
const KINGDEE_DBID = requiredEnv("KINGDEE_DBID");
const KINGDEE_APP_ID = requiredEnv("KINGDEE_APP_ID");
const KINGDEE_APP_SECRET = requiredEnv("KINGDEE_APP_SECRET");
const KINGDEE_LCID = String(process.env.KINGDEE_LCID || "2052");
const KINGDEE_ORIGIN_TYPE = process.env.KINGDEE_ORIGIN_TYPE || "SimPas";
const KINGDEE_ENTRY_ROLE = process.env.KINGDEE_ENTRY_ROLE || "";
const KINGDEE_FORM_ID = process.env.KINGDEE_FORM_ID || "";
const KINGDEE_FORM_TYPE = process.env.KINGDEE_FORM_TYPE || "";
const KINGDEE_PKID = process.env.KINGDEE_PKID || "";
const KINGDEE_OPEN_MODE = process.env.KINGDEE_OPEN_MODE || "";
const KINGDEE_OTHER_ARGS =
  process.env.KINGDEE_OTHER_ARGS || "|{'permitcount':'0'}";
const KINGDEE_FORM_ARGS = process.env.KINGDEE_FORM_ARGS || "";
const KINGDEE_LOGIN_THEN = process.env.KINGDEE_LOGIN_THEN || "";
const KINGDEE_SIGN_ALGO = (process.env.KINGDEE_SIGN_ALGO || "sha256").toLowerCase();
const KINGDEE_SIGN_SORT = boolEnv("KINGDEE_SIGN_SORT", false);
const KINGDEE_UD_ENCODING = (process.env.KINGDEE_UD_ENCODING || "utf-8").trim();
const KINGDEE_SECOND_CHECK_SECRET = process.env.KINGDEE_SECOND_CHECK_SECRET || "";
const KINGDEE_SIGN_INCLUDE_SECOND_CHECK = boolEnv(
  "KINGDEE_SIGN_INCLUDE_SECOND_CHECK",
  false,
);
const KINGDEE_SIGN_INCLUDE_ENTRY_ROLE = boolEnv(
  "KINGDEE_SIGN_INCLUDE_ENTRY_ROLE",
  true,
);
const KINGDEE_SIGN_INCLUDE_PERMITCOUNT = boolEnv(
  "KINGDEE_SIGN_INCLUDE_PERMITCOUNT",
  true,
);
const KINGDEE_SIGN_USERNAME_MODE = (
  process.env.KINGDEE_SIGN_USERNAME_MODE || "raw"
).toLowerCase();
const KINGDEE_SIGN_USERNAME_OVERRIDE =
  process.env.KINGDEE_SIGN_USERNAME_OVERRIDE || "";
const KINGDEE_UD_USERNAME_OVERRIDE =
  process.env.KINGDEE_UD_USERNAME_OVERRIDE || "";
const KINGDEE_LOGIN_AGAIN = process.env.KINGDEE_LOGIN_AGAIN || "";

const REMOTE_USER_HEADER = (
  process.env.REMOTE_USER_HEADER || "remote-user"
).toLowerCase();
const REMOTE_EMAIL_HEADER = (
  process.env.REMOTE_EMAIL_HEADER || "remote-email"
).toLowerCase();
const REMOTE_NAME_HEADER = (
  process.env.REMOTE_NAME_HEADER || "remote-name"
).toLowerCase();
const REMOTE_KINGDEE_USERNAME_HEADER = (
  process.env.REMOTE_KINGDEE_USERNAME_HEADER || "remote-kingdee-username"
).toLowerCase();
const KINGDEE_USERNAME_SOURCE =
  process.env.KINGDEE_USERNAME_SOURCE || "auto";
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase();
const LOG_REQUESTS = boolEnv("LOG_REQUESTS", true);
const LOG_UTC_OFFSET_MINUTES = Number.parseInt(
  process.env.LOG_UTC_OFFSET_MINUTES || "480",
  10,
);

validateConfig();

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function boolEnv(name, defaultValue) {
  const value = process.env[name];
  if (value == null || value === "") return defaultValue;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function validateConfig() {
  const authModes = new Set(["trusted_headers", "exchange_code"]);
  if (!authModes.has(AUTH_MODE)) {
    throw new Error(
      `Invalid AUTH_MODE: ${AUTH_MODE}. Expected trusted_headers or exchange_code`,
    );
  }

  if (AUTH_MODE === "exchange_code") {
    if (!AUTH_LOGIN_URL) {
      throw new Error("AUTH_LOGIN_URL is required when AUTH_MODE=exchange_code");
    }
    if (!AUTH_EXCHANGE_URL) {
      throw new Error("AUTH_EXCHANGE_URL is required when AUTH_MODE=exchange_code");
    }
  }

  const usernameSources = new Set([
    "auto",
    "kingdee_header",
    "remote_user",
    "remote_name",
    "email",
    "email_localpart",
  ]);
  if (!usernameSources.has(KINGDEE_USERNAME_SOURCE)) {
    throw new Error(
      `Invalid KINGDEE_USERNAME_SOURCE: ${KINGDEE_USERNAME_SOURCE}`,
    );
  }

  const signAlgos = new Set(["sha256", "sha1"]);
  if (!signAlgos.has(KINGDEE_SIGN_ALGO)) {
    throw new Error(
      `Invalid KINGDEE_SIGN_ALGO: ${KINGDEE_SIGN_ALGO}. Expected sha256 or sha1`,
    );
  }

  const signUsernameModes = new Set(["raw", "url_encoded", "unicode_escaped"]);
  if (!signUsernameModes.has(KINGDEE_SIGN_USERNAME_MODE)) {
    throw new Error(
      `Invalid KINGDEE_SIGN_USERNAME_MODE: ${KINGDEE_SIGN_USERNAME_MODE}. Expected raw, url_encoded, or unicode_escaped`,
    );
  }

  const logLevels = new Set(["debug", "info", "warn", "error"]);
  if (!logLevels.has(LOG_LEVEL)) {
    throw new Error(
      `Invalid LOG_LEVEL: ${LOG_LEVEL}. Expected debug, info, warn, or error`,
    );
  }

  if (
    Number.isNaN(LOG_UTC_OFFSET_MINUTES) ||
    LOG_UTC_OFFSET_MINUTES < -720 ||
    LOG_UTC_OFFSET_MINUTES > 840
  ) {
    throw new Error(
      `Invalid LOG_UTC_OFFSET_MINUTES: ${process.env.LOG_UTC_OFFSET_MINUTES}. Expected -720..840`,
    );
  }
}

const LOG_PRIORITIES = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function logEvent(level, message, details = {}) {
  if (LOG_PRIORITIES[level] < LOG_PRIORITIES[LOG_LEVEL]) {
    return;
  }
  const shifted = new Date(Date.now() + LOG_UTC_OFFSET_MINUTES * 60 * 1000);
  const sign = LOG_UTC_OFFSET_MINUTES >= 0 ? "+" : "-";
  const absOffset = Math.abs(LOG_UTC_OFFSET_MINUTES);
  const offsetHours = String(Math.floor(absOffset / 60)).padStart(2, "0");
  const offsetMinutes = String(absOffset % 60).padStart(2, "0");
  const payload = {
    ts: shifted
      .toISOString()
      .replace("Z", `${sign}${offsetHours}:${offsetMinutes}`),
    level,
    message,
    ...details,
  };
  console.log(JSON.stringify(payload));
}

function maskText(value, keepStart = 2, keepEnd = 2) {
  return String(value || "");
}

function maskEmail(value) {
  return String(value || "");
}

function summarizeUser(user) {
  if (!user) return null;
  return {
    userId: maskText(user.userId, 2, 0),
    email: maskEmail(user.email),
    name: maskText(user.name, 1, 0),
    kingdeeUsername: maskText(user.kingdeeUsername, 1, 0),
  };
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (Array.isArray(xff) && xff[0]) {
    return String(xff[0]).split(",")[0].trim();
  }
  if (typeof xff === "string" && xff) {
    return xff.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "";
}

function sanitizeUrlForLog(rawUrl) {
  const parsed = new URL(rawUrl, APP_BASE_URL);
  return `${parsed.pathname}${parsed.search}`;
}

function json(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, ...headers });
  res.end();
}

function badRequest(res, message) {
  json(res, 400, { error: message });
}

function serverError(res, message, details) {
  const payload = { error: message };
  if (details) payload.details = details;
  json(res, 500, payload);
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || "";
  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;
    const key = trimmed.slice(0, index);
    const value = trimmed.slice(index + 1);
    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge != null) parts.push(`Max-Age=${options.maxAge}`);
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  return parts.join("; ");
}

function signValue(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

function createSessionCookie(user) {
  const payload = {
    userId: user.userId || "",
    email: user.email || "",
    name: user.name || "",
    kingdeeUsername: user.kingdeeUsername || "",
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signValue(encodedPayload);
  return serializeCookie(KINGDEE_COOKIE_NAME, `${encodedPayload}.${signature}`, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
    domain: COOKIE_DOMAIN || undefined,
  });
}

function clearSessionCookie() {
  return serializeCookie(KINGDEE_COOKIE_NAME, "", {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "Lax",
    path: "/",
    expires: new Date(0),
    domain: COOKIE_DOMAIN || undefined,
  });
}

function readSession(req) {
  const cookies = parseCookies(req);
  const raw = cookies[KINGDEE_COOKIE_NAME];
  if (!raw) return null;

  const [encodedPayload, providedSignature] = raw.split(".");
  if (!encodedPayload || !providedSignature) return null;

  const expectedSignature = signValue(encodedPayload);
  const signatureBuffer = Buffer.from(providedSignature);
  const expectedBuffer = Buffer.from(expectedSignature);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf-8"),
    );
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function getSingleHeader(req, headerName) {
  const value = req.headers[headerName];
  const raw = Array.isArray(value) ? value[0] || "" : String(value || "");
  return normalizeIdentityValue(raw);
}

function normalizeIdentityValue(value) {
  let text = String(value || "").trim();
  if (!text) return "";

  if (/%[0-9a-fA-F]{2}/.test(text)) {
    try {
      text = decodeURIComponent(text);
    } catch {
      // Keep original value if decode fails.
    }
  }

  // Recover UTF-8 text that was decoded as latin1 in HTTP headers.
  if (!/[\u4e00-\u9fff]/.test(text)) {
    const repaired = Buffer.from(text, "latin1").toString("utf8");
    if (/[\u4e00-\u9fff]/.test(repaired)) {
      text = repaired;
    }
  }

  return text;
}

function emailLocalPart(email) {
  const value = String(email || "").trim();
  if (!value.includes("@")) return value;
  return value.split("@")[0];
}

function resolveKingdeeUsername(user) {
  const candidates = {
    kingdee_header: user.kingdeeUsername,
    remote_user: user.userId,
    remote_name: user.name,
    email: user.email,
    email_localpart: emailLocalPart(user.email),
  };

  if (KINGDEE_USERNAME_SOURCE !== "auto") {
    return String(candidates[KINGDEE_USERNAME_SOURCE] || "").trim();
  }

  return String(
    candidates.kingdee_header ||
      candidates.remote_user ||
      candidates.email ||
      candidates.email_localpart ||
      "",
  ).trim();
}

function getTrustedHeaderUser(req) {
  const user = {
    userId: getSingleHeader(req, REMOTE_USER_HEADER),
    email: getSingleHeader(req, REMOTE_EMAIL_HEADER),
    name: getSingleHeader(req, REMOTE_NAME_HEADER),
    kingdeeUsername: getSingleHeader(req, REMOTE_KINGDEE_USERNAME_HEADER),
  };

  if (!user.userId && !user.email && !user.kingdeeUsername) {
    return null;
  }

  user.kingdeeUsername = resolveKingdeeUsername(user);
  if (!user.userId) {
    user.userId = user.kingdeeUsername || user.email;
  }

  return user;
}

function buildState(req) {
  const next = extractNext(req.url);
  const payload = Buffer.from(
    JSON.stringify({ next, ts: Date.now() }),
    "utf-8",
  ).toString("base64url");
  const signature = signValue(payload);
  return `${payload}.${signature}`;
}

function parseState(state) {
  if (!state) return "/";
  const [payload, signature] = state.split(".");
  if (!payload || !signature) return "/";
  const expectedSignature = signValue(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return "/";
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf-8"),
    );
    return sanitizeNext(parsed.next);
  } catch {
    return "/";
  }
}

function sanitizeNext(next) {
  if (!next || typeof next !== "string") return "/";
  if (!next.startsWith("/")) return "/";
  if (next.startsWith("//")) return "/";
  return next;
}

function extractNext(rawUrl) {
  const url = new URL(rawUrl, APP_BASE_URL);
  return sanitizeNext(url.searchParams.get("next") || "/sso/kingdee");
}

function buildAuthLoginUrl(req) {
  if (!AUTH_LOGIN_URL) {
    throw new Error("AUTH_LOGIN_URL is not configured");
  }
  const authUrl = new URL(AUTH_LOGIN_URL);
  authUrl.searchParams.set("redirect_uri", `${APP_BASE_URL}/auth/callback`);
  authUrl.searchParams.set("state", buildState(req));
  return authUrl.toString();
}

async function exchangeCodeForUser(code) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AUTH_EXCHANGE_TIMEOUT_MS);
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (AUTH_EXCHANGE_TOKEN) {
    headers.Authorization = `Bearer ${AUTH_EXCHANGE_TOKEN}`;
  }

  try {
    const response = await fetch(AUTH_EXCHANGE_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ code }),
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(
        `Auth exchange failed with ${response.status}: ${JSON.stringify(payload)}`,
      );
    }

    const user = {
      userId: readNested(payload, [
        "userId",
        "userid",
        "user.userId",
        "user.id",
        "data.userId",
        "data.userid",
        "data.user.userId",
        "data.user.id",
      ]),
      email: readNested(payload, [
        "email",
        "user.email",
        "data.email",
        "data.user.email",
      ]),
      name: readNested(payload, [
        "name",
        "user.name",
        "data.name",
        "data.user.name",
      ]),
      kingdeeUsername: readNested(payload, [
        "kingdeeUsername",
        "kingdee_username",
        "username",
        "loginName",
        "login_name",
        "account",
        "user.kingdeeUsername",
        "user.username",
        "user.loginName",
        "data.kingdeeUsername",
        "data.username",
        "data.loginName",
        "data.user.kingdeeUsername",
        "data.user.username",
        "data.user.loginName",
      ]),
    };

    user.kingdeeUsername = resolveKingdeeUsername(user);
    if (!user.kingdeeUsername) {
      throw new Error(
        `Auth exchange succeeded but kingdee username could not be resolved: ${JSON.stringify(payload)}`,
      );
    }
    if (!user.userId) {
      user.userId = user.kingdeeUsername || user.email;
    }

    return user;
  } finally {
    clearTimeout(timer);
  }
}

function readNested(object, paths) {
  for (const path of paths) {
    const value = path.split(".").reduce((current, key) => {
      if (current && Object.hasOwn(current, key)) return current[key];
      return undefined;
    }, object);
    if (value != null && value !== "") {
      return String(value).trim();
    }
  }
  return "";
}

function buildKingdeeLoginPayload(user) {
  const resolvedUsername = resolveKingdeeUsername(user);
  if (!resolvedUsername) {
    throw new Error(
      `Unable to resolve Kingdee username. Check trusted headers and KINGDEE_USERNAME_SOURCE=${KINGDEE_USERNAME_SOURCE}`,
    );
  }
  const udUsername = String(KINGDEE_UD_USERNAME_OVERRIDE || resolvedUsername);

  // Kingdee third-party login examples use Unix seconds.
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signeddata = buildSignedData(udUsername, timestamp);

  const ud = {
    dbid: KINGDEE_DBID,
    username: udUsername,
    appid: KINGDEE_APP_ID,
    signeddata,
    timestamp,
    lcid: KINGDEE_LCID,
    origintype: KINGDEE_ORIGIN_TYPE,
  };

  ud.entryrole = KINGDEE_ENTRY_ROLE || "";
  ud.formid = KINGDEE_FORM_ID || "";
  ud.formtype = KINGDEE_FORM_TYPE || "";
  ud.pkid = KINGDEE_PKID || "";
  ud.otherargs = KINGDEE_OTHER_ARGS || "";
  ud.loginthen = KINGDEE_LOGIN_THEN || "";
  ud.loginAgain = KINGDEE_LOGIN_AGAIN || "";
  ud.openmode = KINGDEE_OPEN_MODE || null;
  if (KINGDEE_FORM_ARGS) ud.formargs = KINGDEE_FORM_ARGS;

  const loginUrl = new URL("/K3Cloud/html5/index.aspx", KINGDEE_BASE_URL);
  if (KINGDEE_UD_ENCODING) {
    loginUrl.searchParams.set("udencoding", KINGDEE_UD_ENCODING);
  }
  const udJson = stringifyJsonAsAscii(ud);
  loginUrl.searchParams.set("ud", Buffer.from(udJson, "utf8").toString("base64"));
  return {
    loginUrl: loginUrl.toString(),
    resolvedUsername,
    udUsername,
    timestamp,
    signeddata,
    ud,
  };
}

function buildKingdeeLoginUrl(user) {
  return buildKingdeeLoginPayload(user).loginUrl;
}

function stringifyJsonAsAscii(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function buildSignedData(username, timestamp) {
  return buildSignedDataWithOptions(username, timestamp, {
    signAlgo: KINGDEE_SIGN_ALGO,
    signSort: KINGDEE_SIGN_SORT,
    includeSecondCheck: KINGDEE_SIGN_INCLUDE_SECOND_CHECK,
    signUsername: resolveSignUsernameForSignature(username),
  });
}

function buildSignedDataWithOptions(username, timestamp, options = {}) {
  const signUsername =
    options.signUsername != null
      ? options.signUsername
      : resolveSignUsernameForSignature(username);
  const entryRoleForSign =
    options.entryRole != null ? String(options.entryRole) : String(KINGDEE_ENTRY_ROLE || "");
  const permitCountForSign =
    options.permitCount != null
      ? String(options.permitCount)
      : extractPermitCount(KINGDEE_OTHER_ARGS);
  const signParts = [
    KINGDEE_DBID,
    signUsername,
    KINGDEE_APP_ID,
    KINGDEE_APP_SECRET,
    String(timestamp),
  ];
  const includeEntryRole =
    options.includeEntryRole != null
      ? Boolean(options.includeEntryRole)
      : KINGDEE_SIGN_INCLUDE_ENTRY_ROLE;
  const includePermitCount =
    options.includePermitCount != null
      ? Boolean(options.includePermitCount)
      : KINGDEE_SIGN_INCLUDE_PERMITCOUNT;
  if (includeEntryRole) {
    signParts.push(entryRoleForSign);
  }
  if (includePermitCount) {
    signParts.push(permitCountForSign);
  }
  if (options.includeSecondCheck && KINGDEE_SECOND_CHECK_SECRET) {
    signParts.push(KINGDEE_SECOND_CHECK_SECRET);
  }
  const signSort =
    options.signSort != null ? Boolean(options.signSort) : KINGDEE_SIGN_SORT;
  const signAlgo = options.signAlgo || KINGDEE_SIGN_ALGO;
  const signatureText = (signSort ? [...signParts].sort() : signParts).join("");
  return crypto.createHash(signAlgo).update(signatureText, "utf8").digest("hex");
}

function extractPermitCount(otherArgs) {
  const value = String(otherArgs || "");
  const match = value.match(/permitcount['"]?\s*:\s*['"]?([^'"}\s]+)/i);
  if (match && match[1] != null) {
    return String(match[1]);
  }
  return "0";
}

function resolveSignUsernameForSignature(username) {
  const value = String(
    KINGDEE_SIGN_USERNAME_OVERRIDE || username || "",
  );
  if (KINGDEE_SIGN_USERNAME_MODE === "url_encoded") {
    return encodeURIComponent(value);
  }
  if (KINGDEE_SIGN_USERNAME_MODE === "unicode_escaped") {
    return toUnicodeEscaped(value);
  }
  return value;
}

function toUnicodeEscaped(value) {
  return String(value).replace(/[\u007f-\uffff]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function resolveAuthenticatedUser(req) {
  if (AUTH_MODE === "trusted_headers") {
    return getTrustedHeaderUser(req);
  }
  return readSession(req);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, APP_BASE_URL);
  const reqIdHeader = req.headers["x-request-id"];
  const reqId =
    (Array.isArray(reqIdHeader) ? reqIdHeader[0] : reqIdHeader) ||
    crypto.randomUUID();
  const startedAt = Date.now();
  const baseLog = {
    reqId: String(reqId),
    method: req.method,
    path: url.pathname,
    ip: getClientIp(req),
  };
  const finish = (level, message, details = {}) => {
    logEvent(level, message, {
      ...baseLog,
      durationMs: Date.now() - startedAt,
      ...details,
    });
  };

  if (LOG_REQUESTS) {
    logEvent("info", "request.start", {
      ...baseLog,
      query: sanitizeUrlForLog(url.toString()),
    });
  }

  try {
    if (req.method === "GET" && url.pathname === "/healthz") {
      finish("debug", "healthz.ok");
      return json(res, 200, {
        ok: true,
        authMode: AUTH_MODE,
        usernameSource: KINGDEE_USERNAME_SOURCE,
      });
    }

    if (req.method === "GET" && url.pathname === "/logout") {
      finish("info", "session.logout");
      return redirect(res, "/", { "Set-Cookie": clearSessionCookie() });
    }

    if (req.method === "GET" && url.pathname === "/") {
      const user = resolveAuthenticatedUser(req);
      if (!user) {
        if (AUTH_MODE === "trusted_headers") {
          finish("warn", "root.unauthorized", {
            authMode: AUTH_MODE,
          });
          return json(res, 401, {
            error:
              "Missing trusted auth headers. Ensure your reverse proxy forwards Authelia Remote-* identity headers to this service.",
          });
        }
        finish("info", "root.redirect.auth", {
          authMode: AUTH_MODE,
        });
        return redirect(res, buildAuthLoginUrl(req));
      }
      finish("info", "root.redirect.sso", {
        user: summarizeUser(user),
      });
      return redirect(res, "/sso/kingdee");
    }

    if (req.method === "GET" && url.pathname === "/auth/callback") {
      if (AUTH_MODE !== "exchange_code") {
        finish("warn", "auth.callback.not_enabled");
        return json(res, 404, { error: "Not found" });
      }

      const code = url.searchParams.get("code");
      if (!code) {
        finish("warn", "auth.callback.missing_code");
        return badRequest(res, "Missing code");
      }

      const user = await exchangeCodeForUser(code);
      const sessionCookie = createSessionCookie(user);
      const next = parseState(url.searchParams.get("state"));
      finish("info", "auth.callback.success", {
        user: summarizeUser(user),
        next,
      });
      return redirect(res, next, { "Set-Cookie": sessionCookie });
    }

    if (req.method === "GET" && url.pathname === "/sso/kingdee") {
      const user = resolveAuthenticatedUser(req);
      if (!user) {
        if (AUTH_MODE === "trusted_headers") {
          finish("warn", "sso.unauthorized", {
            authMode: AUTH_MODE,
          });
          return json(res, 401, {
            error:
              "Missing trusted auth headers. Ensure Nginx and Authelia are correctly configured.",
          });
        }
        finish("info", "sso.redirect.auth", {
          authMode: AUTH_MODE,
        });
        return redirect(res, buildAuthLoginUrl(req));
      }

      const payload = buildKingdeeLoginPayload(user);
      finish("info", "sso.redirect.kingdee", {
        user: summarizeUser(user),
        sign: {
          timestamp: payload.timestamp,
          signeddataPrefix: payload.signeddata.slice(0, 12),
          udUsername: maskText(payload.udUsername, 1, 0),
        },
        target: sanitizeUrlForLog(payload.loginUrl),
      });
      return redirect(res, payload.loginUrl);
    }

    if (req.method === "GET" && url.pathname === "/debug/session") {
      const user = resolveAuthenticatedUser(req);
      finish("debug", "debug.session", {
        authenticated: Boolean(user),
        user: summarizeUser(user),
      });
      return json(res, 200, {
        authenticated: Boolean(user),
        session: user || null,
        authMode: AUTH_MODE,
        usernameSource: KINGDEE_USERNAME_SOURCE,
      });
    }

    if (req.method === "GET" && url.pathname === "/debug/url") {
      const user = resolveAuthenticatedUser(req);
      if (!user) {
        finish("debug", "debug.url.unauthenticated");
        return json(res, 200, {
          authenticated: false,
          session: null,
        });
      }

      const kingdeeUsername = resolveKingdeeUsername(user);
      const payload = buildKingdeeLoginPayload(user);
      finish("debug", "debug.url", {
        user: summarizeUser(user),
        kingdeeUsername: maskText(kingdeeUsername, 1, 0),
        target: sanitizeUrlForLog(payload.loginUrl),
      });
      return json(res, 200, {
        authenticated: true,
        session: user,
        resolved: {
          kingdeeUsername,
        },
        loginUrl: payload.loginUrl,
      });
    }

    if (req.method === "GET" && url.pathname === "/debug/sign") {
      const username = (url.searchParams.get("username") || "").trim();
      const timestamp = (url.searchParams.get("timestamp") || "").trim();
      if (!username || !timestamp) {
        finish("warn", "debug.sign.missing_params");
        return badRequest(res, "Missing username or timestamp");
      }
      const signeddata = buildSignedData(username, timestamp);
      finish("debug", "debug.sign", {
        username: maskText(username, 1, 0),
        timestamp,
        signeddataPrefix: signeddata.slice(0, 12),
      });
      return json(res, 200, {
        username,
        timestamp,
        signAlgo: KINGDEE_SIGN_ALGO,
        signSort: KINGDEE_SIGN_SORT,
        includeSecondCheck: KINGDEE_SIGN_INCLUDE_SECOND_CHECK,
        includeEntryRole: KINGDEE_SIGN_INCLUDE_ENTRY_ROLE,
        includePermitCount: KINGDEE_SIGN_INCLUDE_PERMITCOUNT,
        signUsernameMode: KINGDEE_SIGN_USERNAME_MODE,
        signeddata,
      });
    }

    if (req.method === "GET" && url.pathname === "/debug/sign-candidates") {
      const username = (url.searchParams.get("username") || "").trim();
      const timestamp = (url.searchParams.get("timestamp") || "").trim();
      const target = (url.searchParams.get("target") || "").trim().toLowerCase();
      if (!username || !timestamp) {
        finish("warn", "debug.sign_candidates.missing_params");
        return badRequest(res, "Missing username or timestamp");
      }

      const usernameVariants = [
        { mode: "raw", value: username },
        { mode: "url_encoded", value: encodeURIComponent(username) },
        { mode: "unicode_escaped", value: toUnicodeEscaped(username) },
      ];
      if (KINGDEE_SIGN_USERNAME_OVERRIDE) {
        usernameVariants.push({
          mode: "override",
          value: KINGDEE_SIGN_USERNAME_OVERRIDE,
        });
      }

      const candidates = [];
      for (const algo of ["sha256", "sha1"]) {
        for (const sort of [true, false]) {
          for (const includeSecondCheck of [false, true]) {
            if (includeSecondCheck && !KINGDEE_SECOND_CHECK_SECRET) continue;
            for (const includeEntryRole of [false, true]) {
              for (const includePermitCount of [false, true]) {
                for (const variant of usernameVariants) {
                  const signeddata = buildSignedDataWithOptions(username, timestamp, {
                    signAlgo: algo,
                    signSort: sort,
                    includeSecondCheck,
                    includeEntryRole,
                    includePermitCount,
                    signUsername: variant.value,
                  });
                  candidates.push({
                    signAlgo: algo,
                    signSort: sort,
                    includeSecondCheck,
                    includeEntryRole,
                    includePermitCount,
                    signUsernameMode: variant.mode,
                    signeddata,
                    matched: Boolean(target) && signeddata.toLowerCase() === target,
                  });
                }
              }
            }
          }
        }
      }

      return json(res, 200, {
        username,
        timestamp,
        target: target || null,
        candidates,
      });
    }

    finish("warn", "request.not_found");
    return json(res, 404, { error: "Not found" });
  } catch (error) {
    finish("error", "request.error", {
      error: error.message,
      stack: error.stack,
    });
    return serverError(res, "Unexpected server error", error.message);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  logEvent("info", "server.started", {
    port: PORT,
    authMode: AUTH_MODE,
    usernameSource: KINGDEE_USERNAME_SOURCE,
    sign: {
      algo: KINGDEE_SIGN_ALGO,
      sort: KINGDEE_SIGN_SORT,
      includeEntryRole: KINGDEE_SIGN_INCLUDE_ENTRY_ROLE,
      includePermitCount: KINGDEE_SIGN_INCLUDE_PERMITCOUNT,
      includeSecondCheck: KINGDEE_SIGN_INCLUDE_SECOND_CHECK,
    },
  });
});
