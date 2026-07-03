const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { URL } = require("url");

const ROOT_DIR = __dirname;
const STORAGE_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT_DIR, "data");
const REDIRECTS_FILE = path.join(STORAGE_DIR, "redirects.json");

loadEnv(path.join(ROOT_DIR, ".env"));

const PORT = Number(process.env.PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 80);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 443);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-moi";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-moi-aussi";
const LETSENCRYPT_EMAIL = (process.env.LETSENCRYPT_EMAIL || "").trim();
const LETSENCRYPT_DOMAINS = parseDomainList(process.env.LETSENCRYPT_DOMAINS || "");
const LETSENCRYPT_STAGING = isTruthy(process.env.LETSENCRYPT_STAGING);
const CERTBOT_BIN = (process.env.CERTBOT_BIN || "certbot").trim() || "certbot";
const CERTBOT_DIR = path.join(STORAGE_DIR, "letsencrypt");
const sessions = new Map();
let useSecureCookies = false;

ensureDataFile();

const requestListener = async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = normalizePath(url.pathname);
    const requestHost = normalizeHost(req.headers.host || "");
    const method = req.method || "GET";

    if (pathname === "/login" && method === "GET") {
      return renderLogin(res, getFlashMessage(url));
    }

    if (pathname === "/login" && method === "POST") {
      const form = await parseForm(req);
      if (
        form.username === ADMIN_USERNAME &&
        form.password === ADMIN_PASSWORD
      ) {
        const token = createSessionToken();
        sessions.set(token, { createdAt: Date.now() });
        setCookie(res, "session", signToken(token), {
          httpOnly: true,
          secure: useSecureCookies
        });
        redirect(res, "/admin");
        return;
      }

      redirect(res, "/login?error=Identifiants%20invalides");
      return;
    }

    if (pathname === "/logout") {
      clearCookie(res, "session");
      redirect(res, "/login");
      return;
    }

    if (pathname === "/admin" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const redirects = readRedirects();
      const editSource = normalizeSource(url.searchParams.get("edit") || "");
      const editingRedirect = editSource
        ? redirects.find((item) => item.source === editSource) || null
        : null;
      return renderAdmin(res, redirects, getFlashMessage(url), editingRedirect);
    }

    if (pathname === "/admin/redirects" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const originalSource = normalizeSource(form.originalSource || form.source || "");
      const source = normalizeSource(form.source || "");
      const target = (form.target || "").trim();
      const existingRedirects = readRedirects().filter((item) => item.source !== originalSource);

      const error = validateRedirectInput(source, target, existingRedirects);
      if (error) {
        redirect(res, `/admin?error=${encodeURIComponent(error)}`);
        return;
      }

      existingRedirects.push({
        source,
        target,
        code: 301,
        updatedAt: new Date().toISOString()
      });
      existingRedirects.sort((a, b) => a.source.localeCompare(b.source));
      writeRedirects(existingRedirects);
      redirect(
        res,
        `/admin?success=${encodeURIComponent(originalSource ? "Redirection modifiee" : "Redirection enregistree")}`
      );
      return;
    }

    if (pathname === "/admin/redirects/delete" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const source = normalizeSource(form.source || "");
      const redirects = readRedirects().filter((item) => item.source !== source);
      writeRedirects(redirects);
      redirect(res, "/admin?success=Redirection%20supprimee");
      return;
    }

    if (pathname === "/admin/tls/request" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const redirects = readRedirects();
      const form = await parseForm(req);
      const requestedDomain = normalizeHost(form.domain || "");
      const availableDomains = collectTlsDomains(redirects);

      if (!LETSENCRYPT_EMAIL) {
        redirect(res, "/admin?error=LETSENCRYPT_EMAIL%20est%20requis");
        return;
      }

      if (!requestedDomain || !availableDomains.includes(requestedDomain)) {
        redirect(res, "/admin?error=Domaine%20TLS%20invalide");
        return;
      }

      try {
        await runCommand(CERTBOT_BIN, buildCertbotArgs([requestedDomain], requestedDomain));
        redirect(res, `/admin?success=${encodeURIComponent(`Certificat demande pour ${requestedDomain}`)}`);
      } catch (error) {
        redirect(res, `/admin?error=${encodeURIComponent(error.message)}`);
      }
      return;
    }

    const redirects = readRedirects();
    const sourceCandidates = buildSourceCandidates(requestHost, pathname);
    const match = redirects.find((item) => sourceCandidates.includes(item.source));

    if (match) {
      const resolvedTarget = resolveRedirectTarget(match.target, redirects, new Set([match.source]));
      if (!resolvedTarget) {
        res.writeHead(500, { "Content-Type": "text/html; charset=utf-8" });
        res.end(
          renderPage(
            "Erreur",
            `<p>La redirection pour <code>${escapeHtml(match.source)}</code> forme une boucle ou pointe vers une cible inexistante.</p>`
          )
        );
        return;
      }

      res.writeHead(301, { Location: resolvedTarget });
      res.end();
      return;
    }

    renderNotFound(res, requestHost, pathname);
  } catch (error) {
    res.writeHead(500, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderPage("Erreur", `<p>Erreur interne: ${escapeHtml(error.message)}</p>`));
  }
};

startServer().catch((error) => {
  console.error(`[startup] ${error.message}`);
  process.exit(1);
});

function loadEnv(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, "utf8");
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex === -1) {
      continue;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim();
    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function ensureDataFile() {
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }

  if (!fs.existsSync(REDIRECTS_FILE)) {
    fs.writeFileSync(REDIRECTS_FILE, "[]\n", "utf8");
  }
}

function logStorageStatus() {
  const storageExists = fs.existsSync(STORAGE_DIR);
  const fileExists = fs.existsSync(REDIRECTS_FILE);
  let writable = false;

  try {
    fs.accessSync(STORAGE_DIR, fs.constants.R_OK | fs.constants.W_OK);
    writable = true;
  } catch {
    writable = false;
  }

  console.log(`[storage] DATA_DIR=${STORAGE_DIR}`);
  console.log(`[storage] directory_exists=${storageExists} file_exists=${fileExists} read_write=${writable}`);
}

async function startServer() {
  logStorageStatus();

  const tlsDomains = collectTlsDomains(readRedirects());
  if (tlsDomains.length > 0) {
    if (!LETSENCRYPT_EMAIL) {
      console.warn("[tls] LETSENCRYPT_EMAIL est absent. Demarrage en HTTP simple.");
    } else {
      const primaryDomain = tlsDomains[0];
      if (hasTlsCertificate(primaryDomain)) {
        const tlsOptions = loadTlsOptions(primaryDomain);
        useSecureCookies = true;

        https.createServer(tlsOptions, requestListener).listen(HTTPS_PORT, () => {
          console.log(`[https] Application disponible sur https://localhost:${HTTPS_PORT}`);
          console.log(`[https] Certificat charge pour: ${tlsDomains.join(", ")}`);
        });

        http.createServer(redirectHttpToHttps).listen(HTTP_PORT, () => {
          console.log(`[http] Redirection HTTP->HTTPS active sur le port ${HTTP_PORT}`);
        });
        return;
      }

      console.warn("[tls] Aucun certificat present. Demarrage en HTTP simple.");
      console.warn(`[tls] Lance manuellement cette commande: ${buildCertbotCommand(tlsDomains)}`);
    }
  }

  http.createServer(requestListener).listen(PORT, () => {
    console.log(`Application disponible sur http://localhost:${PORT}`);
  });
}

function collectTlsDomains(redirects) {
  const domains = new Set(LETSENCRYPT_DOMAINS);
  for (const redirect of redirects) {
    const host = extractSourceHost(redirect.source);
    if (host) {
      domains.add(host);
    }
  }

  const validDomains = [];
  for (const domain of domains) {
    if (domain.startsWith("*.")) {
      console.warn(`[tls] Domaine ignore: ${domain}. Les wildcards Let's Encrypt exigent un challenge DNS.`);
      continue;
    }
    if (!isDnsHostname(domain)) {
      console.warn(`[tls] Domaine ignore: ${domain}. Nom de domaine invalide.`);
      continue;
    }
    validDomains.push(domain);
  }

  return validDomains.sort();
}

function parseDomainList(input) {
  return Array.from(
    new Set(
      String(input || "")
        .split(/[,\s]+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
    )
  );
}

function extractSourceHost(source) {
  try {
    const normalized = normalizeSource(source || "");
    const slashIndex = normalized.indexOf("/");
    if (slashIndex <= 0) {
      return "";
    }
    const candidate = normalized.slice(0, slashIndex).toLowerCase();
    return candidate.includes(".") ? candidate : "";
  } catch {
    return "";
  }
}

function isDnsHostname(host) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(host);
}

function isTruthy(value) {
  return ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function buildCertbotArgs(domains, certName = "") {
  const configDir = path.join(CERTBOT_DIR, "config");
  const workDir = path.join(CERTBOT_DIR, "work");
  const logsDir = path.join(CERTBOT_DIR, "logs");

  fs.mkdirSync(configDir, { recursive: true });
  fs.mkdirSync(workDir, { recursive: true });
  fs.mkdirSync(logsDir, { recursive: true });

  const args = [
    "certonly",
    "--standalone",
    "--non-interactive",
    "--agree-tos",
    "--keep-until-expiring",
    "--preferred-challenges",
    "http",
    "--config-dir",
    configDir,
    "--work-dir",
    workDir,
    "--logs-dir",
    logsDir,
    "-m",
    LETSENCRYPT_EMAIL
  ];

  if (certName) {
    args.push("--cert-name", certName);
  }

  if (LETSENCRYPT_STAGING) {
    args.push("--test-cert");
  }

  for (const domain of domains) {
    args.push("-d", domain);
  }

  return args;
}

function buildCertbotCommand(domains, certName = "") {
  return [CERTBOT_BIN, ...buildCertbotArgs(domains, certName)]
    .map((part) => (/\s/.test(part) ? `"${part}"` : part))
    .join(" ");
}

function hasTlsCertificate(primaryDomain) {
  const liveDir = path.join(CERTBOT_DIR, "config", "live", primaryDomain);
  const keyPath = path.join(liveDir, "privkey.pem");
  const certPath = path.join(liveDir, "fullchain.pem");
  return fs.existsSync(keyPath) && fs.existsSync(certPath);
}

function loadTlsOptions(primaryDomain) {
  const liveDir = path.join(CERTBOT_DIR, "config", "live", primaryDomain);
  const keyPath = path.join(liveDir, "privkey.pem");
  const certPath = path.join(liveDir, "fullchain.pem");

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    throw new Error(`Certificat introuvable apres execution de certbot pour ${primaryDomain}.`);
  }

  return {
    key: fs.readFileSync(keyPath, "utf8"),
    cert: fs.readFileSync(certPath, "utf8")
  };
}

function runCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: ROOT_DIR,
      stdio: "inherit"
    });

    child.on("error", (error) => {
      reject(new Error(`Impossible de lancer ${command}: ${error.message}`));
    });

    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${command} a echoue avec le code ${code}.`));
    });
  });
}

function redirectHttpToHttps(req, res) {
  const host = normalizeHost(req.headers.host || "") || "localhost";
  const targetHost = HTTPS_PORT === 443 ? host : `${host}:${HTTPS_PORT}`;
  const location = `https://${targetHost}${req.url || "/"}`;
  res.writeHead(301, { Location: location });
  res.end();
}

function readRedirects() {
  ensureDataFile();
  try {
    const raw = fs.readFileSync(REDIRECTS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeRedirects(redirects) {
  fs.writeFileSync(REDIRECTS_FILE, `${JSON.stringify(redirects, null, 2)}\n`, "utf8");
}

function normalizePath(input) {
  const trimmed = (input || "").trim();
  if (!trimmed || trimmed === "/") {
    return "/";
  }

  const withLeadingSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withLeadingSlash.replace(/\/+$/g, "") || "/";
}

function normalizeHost(input) {
  const trimmed = (input || "").trim().toLowerCase();
  return trimmed.replace(/:\d+$/, "");
}

function formatSource(host, pathname) {
  return host ? `${host}${pathname}` : pathname;
}

function buildSourceCandidates(host, pathname) {
  const candidates = [];
  const seen = new Set();

  for (const candidateHost of buildHostVariants(host)) {
    const candidate = formatSource(candidateHost, pathname);
    if (!candidate || seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    candidates.push(candidate);
  }

  if (!seen.has(pathname)) {
    candidates.push(pathname);
  }

  return candidates;
}

function buildHostVariants(host) {
  const normalizedHost = normalizeHost(host);
  if (!normalizedHost) {
    return [""];
  }

  const variants = [normalizedHost];
  if (shouldAllowWwwAlias(normalizedHost)) {
    if (normalizedHost.startsWith("www.")) {
      variants.push(normalizedHost.slice(4));
    } else {
      variants.push(`www.${normalizedHost}`);
    }
  }

  return Array.from(new Set(variants.filter(Boolean)));
}

function shouldAllowWwwAlias(host) {
  return host.includes(".") && host !== "localhost" && !host.endsWith(".local");
}

function normalizeSource(input) {
  const trimmed = (input || "").trim();
  if (!trimmed) {
    return "";
  }

  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    const parsed = new URL(trimmed);
    return formatSource(normalizeHost(parsed.host), normalizePath(parsed.pathname));
  }

  if (trimmed.startsWith("/")) {
    return normalizePath(trimmed);
  }

  if (trimmed.includes(".")) {
    const parsed = new URL(`http://${trimmed}`);
    return formatSource(normalizeHost(parsed.host), normalizePath(parsed.pathname));
  }

  return normalizePath(trimmed);
}

function validateRedirectInput(source, target, redirects = []) {
  if (!source) {
    return "La source est requise.";
  }

  const sourcePath = extractSourcePath(source);
  if (
    sourcePath === "/admin" ||
    sourcePath.startsWith("/admin/") ||
    sourcePath === "/login" ||
    sourcePath === "/logout"
  ) {
    return "Ce chemin est reserve a l'administration.";
  }

  if (!target) {
    return "La cible est requise.";
  }

  const parsedTarget = parseAbsoluteTarget(target);
  if (parsedTarget) {
    if (isLocalTarget(parsedTarget)) {
      return "La cible doit etre un site externe.";
    }
    return "";
  }

  let normalizedTarget = "";
  try {
    normalizedTarget = normalizeSource(target);
  } catch {
    return "La cible doit etre une URL absolue valide ou une source existante.";
  }

  if (!normalizedTarget) {
    return "La cible doit etre une URL absolue valide ou une source existante.";
  }

  if (normalizedTarget === source) {
    return "La cible ne peut pas pointer vers elle-meme.";
  }

  const redirectMap = new Map(redirects.map((item) => [item.source, item.target]));
  if (!redirectMap.has(normalizedTarget)) {
    return "La cible interne doit correspondre a une source deja enregistree.";
  }

  if (!resolveRedirectTarget(normalizedTarget, redirects, new Set([source]))) {
    return "Cette cible interne cree une boucle de redirection.";
  }

  return "";
}

function extractSourcePath(source) {
  const slashIndex = source.indexOf("/");
  return slashIndex === -1 ? "/" : normalizePath(source.slice(slashIndex));
}

function isLocalTarget(parsedUrl) {
  const hostname = (parsedUrl.hostname || "").toLowerCase();
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".local")
  );
}

function parseAbsoluteTarget(target) {
  try {
    const parsed = new URL(target);
    return ["http:", "https:"].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function resolveRedirectTarget(target, redirects, visited = new Set()) {
  const parsedTarget = parseAbsoluteTarget(target);
  if (parsedTarget) {
    return parsedTarget.toString();
  }

  let normalizedTarget = "";
  try {
    normalizedTarget = normalizeSource(target);
  } catch {
    return "";
  }

  if (!normalizedTarget || visited.has(normalizedTarget)) {
    return "";
  }

  const nextRedirect = redirects.find((item) => item.source === normalizedTarget);
  if (!nextRedirect) {
    return "";
  }

  visited.add(normalizedTarget);
  return resolveRedirectTarget(nextRedirect.target, redirects, visited);
}

function isAuthenticated(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const signed = cookies.session;
  if (!signed) {
    return false;
  }

  const token = verifyToken(signed);
  return Boolean(token && sessions.has(token));
}

function parseCookies(header) {
  return header.split(";").reduce((acc, part) => {
    const [name, ...rest] = part.trim().split("=");
    if (!name) {
      return acc;
    }
    acc[name] = decodeURIComponent(rest.join("=") || "");
    return acc;
  }, {});
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "SameSite=Lax"];
  if (options.httpOnly) {
    parts.push("HttpOnly");
  }
  if (options.secure) {
    parts.push("Secure");
  }
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  const secureFlag = useSecureCookies ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly${secureFlag}`);
}

function signToken(token) {
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(token)
    .digest("hex");
  return `${token}.${signature}`;
}

function verifyToken(value) {
  const parts = value.split(".");
  if (parts.length !== 2) {
    return "";
  }

  const [token, signature] = parts;
  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(token)
    .digest("hex");

  const matches =
    signature.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));

  return matches ? token : "";
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

function parseForm(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 1e6) {
        reject(new Error("Requete trop volumineuse."));
      }
    });

    req.on("end", () => {
      const params = new URLSearchParams(body);
      resolve(Object.fromEntries(params.entries()));
    });

    req.on("error", reject);
  });
}

function getFlashMessage(url) {
  return {
    error: url.searchParams.get("error") || "",
    success: url.searchParams.get("success") || ""
  };
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function buildTlsDomainStatuses(redirects) {
  const domains = collectTlsDomains(redirects);
  if (!domains.length) {
    return [];
  }

  const primaryInfo = readCertificateInfo(domains[0]);

  return domains.map((domain) => {
    const domainInfo = readCertificateInfo(domain);
    const certificateInfo =
      domainInfo && domainInfo.coversDomain(domain)
        ? domainInfo
        : primaryInfo && primaryInfo.coversDomain(domain)
          ? primaryInfo
          : null;

    return {
      domain,
      command: LETSENCRYPT_EMAIL ? buildCertbotCommand([domain], domain) : "",
      hasCertificate: Boolean(certificateInfo),
      expiresAt: certificateInfo ? formatCertificateDate(certificateInfo.expiresAt) : "Aucun certificat detecte"
    };
  });
}

function readCertificateInfo(domain) {
  const liveDir = path.join(CERTBOT_DIR, "config", "live", domain);
  const certPath = path.join(liveDir, "fullchain.pem");
  if (!fs.existsSync(certPath)) {
    return null;
  }

  try {
    const pem = fs.readFileSync(certPath, "utf8");
    const certificate = new crypto.X509Certificate(pem);
    const expiresAt = new Date(certificate.validTo);

    return {
      expiresAt,
      coversDomain(hostname) {
        try {
          return Boolean(certificate.checkHost(hostname));
        } catch {
          return false;
        }
      }
    };
  } catch {
    return null;
  }
}

function formatCertificateDate(value) {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return "Date inconnue";
  }

  return value.toLocaleString("fr-FR", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Europe/Paris"
  });
}

function renderTlsStatusSection(statuses) {
  if (!statuses.length) {
    return "";
  }

  const rows = statuses
    .map(
      (item) => `
        <tr>
          <td><code>${escapeHtml(item.domain)}</code></td>
          <td>${item.hasCertificate ? `<span class="status-ok">Actif</span>` : `<span class="status-missing">Manquant</span>`}</td>
          <td>${escapeHtml(item.expiresAt)}</td>
          <td class="command-cell">
            <code class="command-text">${escapeHtml(item.command || "Renseignez LETSENCRYPT_EMAIL pour generer la commande.")}</code>
          </td>
          <td class="actions-cell">
            <form method="post" action="/admin/tls/request">
              <input type="hidden" name="domain" value="${escapeHtml(item.domain)}" />
              <button type="submit" ${item.command ? "" : "disabled"}>${item.hasCertificate ? "Renouveler" : "Demander"}</button>
            </form>
            <button type="button" class="secondary copy-button" data-copy="${escapeHtml(item.command)}" ${item.command ? "" : "disabled"}>Copier</button>
          </td>
        </tr>
      `
    )
    .join("");

  return `
    <section class="card">
      <h2>Certificats TLS</h2>
      <p>Le certificat reste liste par host exact. Le routage essaie aussi automatiquement les variantes avec et sans <code>www</code>.</p>
      <p>Le bouton lance directement la demande depuis l'application. La commande reste visible pour debug.</p>
      <table>
        <thead>
          <tr>
            <th>Domaine</th>
            <th>Etat</th>
            <th>Expiration</th>
            <th>Commande</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
  `;
}

function renderLogin(res, flash) {
  const messages = renderMessages(flash);
  const content = `
    <section class="card auth-card">
      <h1>Connexion</h1>
      <p>Identifiez-vous pour gerer vos redirections URL.</p>
      ${messages}
      <form method="post" action="/login" class="form-grid">
        <label>
          <span>Nom d'utilisateur</span>
          <input type="text" name="username" autocomplete="username" required />
        </label>
        <label>
          <span>Mot de passe</span>
          <input type="password" name="password" autocomplete="current-password" required />
        </label>
        <button type="submit">Se connecter</button>
      </form>
    </section>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(renderPage("Connexion", content));
}

function renderAdmin(res, redirects, flash, editingRedirect = null) {
  const messages = renderMessages(flash);
  const formTitle = editingRedirect ? "Modifier la redirection" : "Nouvelle redirection";
  const submitLabel = editingRedirect ? "Mettre a jour" : "Enregistrer";
  const tlsStatuses = buildTlsDomainStatuses(redirects);
  const tlsSection = renderTlsStatusSection(tlsStatuses);
  const rows = redirects.length
    ? redirects
        .map(
          (item) => `
            <tr>
              <td><code>${escapeHtml(item.source)}</code></td>
              <td>${renderTargetCell(item.target)}</td>
              <td>${item.code}</td>
              <td class="actions-cell">
                <a href="/admin?edit=${encodeURIComponent(item.source)}" class="link-button secondary">Modifier</a>
                <form method="post" action="/admin/redirects/delete">
                  <input type="hidden" name="source" value="${escapeHtml(item.source)}" />
                  <button type="submit" class="danger">Supprimer</button>
                </form>
              </td>
            </tr>
          `
        )
        .join("")
    : `<tr><td colspan="4">Aucune redirection enregistree.</td></tr>`;

  const content = `
    <header class="topbar">
      <div>
        <h1>Redirections URL</h1>
        <p>La source peut etre un chemin simple ou un sous-domaine avec chemin. La cible peut etre une URL externe ou une autre source deja enregistree.</p>
        <p>L'application essaie d'abord le host exact, puis les variantes usuelles avec et sans <code>www</code>. Si les deux existent, la redirection exacte reste prioritaire.</p>
      </div>
      <a href="/logout" class="link-button">Deconnexion</a>
    </header>
    ${messages}
    <section class="card">
      <h2>${formTitle}</h2>
      <form method="post" action="/admin/redirects" class="form-grid">
        <input type="hidden" name="originalSource" value="${escapeHtml(editingRedirect ? editingRedirect.source : "")}" />
        <label>
          <span>URL souhaitee</span>
          <input type="text" name="source" placeholder="www.example.rooky.fr/mon-chemin ou /mon-chemin" value="${escapeHtml(editingRedirect ? editingRedirect.source : "")}" required />
        </label>
        <label>
          <span>Cible</span>
          <input type="text" name="target" placeholder="https://exemple.com/page ou rooky.fr" value="${escapeHtml(editingRedirect ? editingRedirect.target : "")}" required />
        </label>
        <label>
          <span>Code</span>
          <input type="text" value="301" disabled />
        </label>
        <p>La cible peut etre une URL externe ou une source deja enregistree. L'application resout alors la destination finale avant de repondre en 301.</p>
        <div class="form-actions">
          <button type="submit">${submitLabel}</button>
          ${editingRedirect ? '<a href="/admin" class="link-button secondary">Annuler</a>' : ""}
        </div>
      </form>
    </section>
    ${tlsSection}
    <section class="card">
      <h2>Liste des redirections</h2>
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Cible</th>
            <th>Code</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </section>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(renderPage("Administration", content));
}

function renderNotFound(res, requestHost, pathname) {
  const requestedSource = formatSource(requestHost, pathname);
  res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
  res.end(
    renderPage(
      "Non trouve",
      `
        <section class="card auth-card">
          <h1>404</h1>
          <p>Aucune redirection definie pour <code>${escapeHtml(requestedSource)}</code>.</p>
          <p><a href="/admin">Acceder a l'administration</a></p>
        </section>
      `
    )
  );
}

function renderMessages(flash) {
  const parts = [];
  if (flash.error) {
    parts.push(`<div class="message error">${escapeHtml(flash.error)}</div>`);
  }
  if (flash.success) {
    parts.push(`<div class="message success">${escapeHtml(flash.success)}</div>`);
  }
  return parts.join("");
}

function renderPage(title, content) {
  return `<!doctype html>
  <html lang="fr">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${escapeHtml(title)}</title>
      <style>
        :root {
          --bg: #f4efe8;
          --panel: #fffdf9;
          --ink: #1f1a17;
          --muted: #75685d;
          --line: #d8cdc1;
          --accent: #b04a2f;
          --accent-dark: #7f331f;
          --danger: #923434;
          --success: #2f6b46;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: Georgia, "Times New Roman", serif;
          color: var(--ink);
          background:
            radial-gradient(circle at top left, #f9d9c8 0, transparent 28%),
            linear-gradient(135deg, #f3ece4 0%, #efe5da 55%, #e9ddcf 100%);
          min-height: 100vh;
        }
        .shell {
          width: min(980px, calc(100% - 32px));
          margin: 40px auto;
        }
        .card {
          background: rgba(255, 253, 249, 0.95);
          border: 1px solid var(--line);
          border-radius: 18px;
          padding: 24px;
          box-shadow: 0 12px 30px rgba(81, 51, 34, 0.08);
          margin-bottom: 20px;
        }
        .auth-card {
          max-width: 460px;
          margin: 80px auto;
        }
        h1, h2, p {
          margin-top: 0;
        }
        p {
          color: var(--muted);
          line-height: 1.5;
        }
        .topbar {
          display: flex;
          justify-content: space-between;
          gap: 16px;
          align-items: center;
          margin-bottom: 20px;
        }
        .form-grid {
          display: grid;
          gap: 16px;
        }
        label span {
          display: block;
          font-size: 14px;
          margin-bottom: 8px;
          color: var(--muted);
        }
        input, button, .link-button {
          border-radius: 12px;
          font: inherit;
        }
        input {
          width: 100%;
          padding: 12px 14px;
          border: 1px solid var(--line);
          background: #fff;
          color: var(--ink);
        }
        button, .link-button {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border: 0;
          background: var(--accent);
          color: #fff;
          padding: 12px 18px;
          cursor: pointer;
          text-decoration: none;
        }
        button:hover, .link-button:hover {
          background: var(--accent-dark);
        }
        .danger {
          background: var(--danger);
        }
        .secondary {
          background: #e9dfd4;
          color: var(--ink);
        }
        .secondary:hover {
          background: #d9ccbe;
        }
        .form-actions,
        .actions-cell {
          display: flex;
          gap: 10px;
          align-items: center;
          flex-wrap: wrap;
        }
        .actions-cell form {
          margin: 0;
        }
        .message {
          padding: 12px 14px;
          border-radius: 12px;
          margin-bottom: 16px;
        }
        .message.error {
          background: #f8e0dc;
          color: #6d2419;
        }
        .message.success {
          background: #deefe4;
          color: #184b2b;
        }
        .status-ok {
          color: var(--success);
          font-weight: 700;
        }
        .status-missing {
          color: var(--danger);
          font-weight: 700;
        }
        .command-cell {
          min-width: 320px;
        }
        .command-text {
          display: inline-block;
          white-space: pre-wrap;
          word-break: break-word;
        }
        .copy-button[disabled] {
          opacity: 0.5;
          cursor: not-allowed;
        }
        table {
          width: 100%;
          border-collapse: collapse;
        }
        th, td {
          text-align: left;
          padding: 14px 10px;
          border-top: 1px solid var(--line);
          vertical-align: top;
        }
        code {
          background: #f5eee6;
          padding: 2px 6px;
          border-radius: 6px;
        }
        a {
          color: var(--accent-dark);
        }
        @media (max-width: 720px) {
          .shell {
            width: min(100% - 20px, 980px);
            margin: 20px auto;
          }
          .card {
            padding: 18px;
          }
          .topbar {
            flex-direction: column;
            align-items: stretch;
          }
          table, thead, tbody, tr, td, th {
            display: block;
          }
          thead {
            display: none;
          }
          tr {
            border-top: 1px solid var(--line);
            padding: 10px 0;
          }
          td {
            border: 0;
            padding: 8px 0;
          }
        }
      </style>
    </head>
    <body>
      <main class="shell">${content}</main>
      <script>
        document.addEventListener("click", async (event) => {
          const button = event.target.closest(".copy-button");
          if (!button || button.disabled) {
            return;
          }

          const text = button.dataset.copy || "";
          if (!text) {
            return;
          }

          try {
            await navigator.clipboard.writeText(text);
            const previous = button.textContent;
            button.textContent = "Copie";
            setTimeout(() => {
              button.textContent = previous;
            }, 1200);
          } catch {
            button.textContent = "Echec";
          }
        });
      </script>
    </body>
  </html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderTargetCell(target) {
  const parsedTarget = parseAbsoluteTarget(target);
  if (parsedTarget) {
    return `<a href="${escapeHtml(parsedTarget.toString())}" target="_blank" rel="noreferrer">${escapeHtml(target)}</a>`;
  }

  return `<code>${escapeHtml(target)}</code>`;
}
