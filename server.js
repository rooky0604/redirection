const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const ROOT_DIR = __dirname;
const STORAGE_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT_DIR, "data");
const REDIRECTS_FILE = path.join(STORAGE_DIR, "redirects.json");

loadEnv(path.join(ROOT_DIR, ".env"));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-moi";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-moi-aussi";
const sessions = new Map();
let useSecureCookies = false;

ensureDataFile();

const requestListener = async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = normalizePath(url.pathname);
    const requestHost = normalizeHost(req.headers.host || "");
    const method = req.method || "GET";

    console.log(`[request] ${method} host=${requestHost || "(none)"} path=${pathname}`);

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
        updatedAt: new Date().toISOString(),
        public: form.public === "on",
        publicLabel: (form.publicLabel || "").trim()
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

    const redirects = readRedirects();
    const sourceCandidates = buildSourceCandidates(requestHost, pathname);
    const match =
      redirects.find((item) => sourceCandidates.includes(item.source)) ||
      redirects.find((item) => matchesWildcardSource(item.source, requestHost, pathname));

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

    if (pathname === "/") {
      return renderHome(res, redirects);
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

  http.createServer(requestListener).listen(PORT, () => {
    console.log(`Application disponible sur http://localhost:${PORT}`);
  });
}

function isDnsHostname(host) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(host);
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

function matchesWildcardSource(source, requestHost, pathname) {
  const slashIndex = source.indexOf("/");
  const hostPart = slashIndex === -1 ? source : source.slice(0, slashIndex);
  if (!hostPart.startsWith("*.")) {
    return false;
  }

  const baseDomain = hostPart.slice(2);
  if (!baseDomain || !requestHost || !requestHost.endsWith(`.${baseDomain}`)) {
    return false;
  }

  const sourcePath = slashIndex === -1 ? "/" : normalizePath(source.slice(slashIndex));
  return sourcePath === pathname;
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

  const sourceSlashIndex = source.indexOf("/");
  const sourceHostPart = sourceSlashIndex === -1 ? source : source.slice(0, sourceSlashIndex);
  if (sourceHostPart.startsWith("*.") && !isDnsHostname(sourceHostPart.slice(2))) {
    return "Le domaine wildcard doit etre au format *.exemple.fr.";
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
  const rows = redirects.length
    ? redirects
        .map(
          (item) => `
            <tr>
              <td><code>${escapeHtml(item.source)}</code></td>
              <td>${renderTargetCell(item.target)}</td>
              <td>${item.code}</td>
              <td>${item.public ? "Oui" : "Non"}</td>
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
    : `<tr><td colspan="5">Aucune redirection enregistree.</td></tr>`;

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
          <input type="text" name="source" placeholder="www.example.rooky.fr/mon-chemin ou *.exemple.fr ou /mon-chemin" value="${escapeHtml(editingRedirect ? editingRedirect.source : "")}" required />
        </label>
        <label>
          <span>Cible</span>
          <input type="text" name="target" placeholder="https://exemple.com/page ou rooky.fr" value="${escapeHtml(editingRedirect ? editingRedirect.target : "")}" required />
        </label>
        <label>
          <span>Code</span>
          <input type="text" value="301" disabled />
        </label>
        <label>
          <span>Titre public (optionnel)</span>
          <input type="text" name="publicLabel" placeholder="Ex: Mon Discord" value="${escapeHtml(editingRedirect ? editingRedirect.publicLabel || "" : "")}" />
        </label>
        <label class="checkbox-label">
          <input type="checkbox" name="public" ${editingRedirect && editingRedirect.public ? "checked" : ""} />
          <span>Afficher ce lien sur la page d'accueil publique</span>
        </label>
        <p>La cible peut etre une URL externe ou une source deja enregistree. L'application resout alors la destination finale avant de repondre en 301.</p>
        <div class="form-actions">
          <button type="submit">${submitLabel}</button>
          ${editingRedirect ? '<a href="/admin" class="link-button secondary">Annuler</a>' : ""}
        </div>
      </form>
    </section>
    <section class="card">
      <h2>Liste des redirections</h2>
      <table>
        <thead>
          <tr>
            <th>Source</th>
            <th>Cible</th>
            <th>Code</th>
            <th>Public</th>
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

const ICON_LINK =
  '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 14.5l5-5"/><path d="M8 16.5l-1.5 1.5a3 3 0 0 1-4.2-4.2L4 12"/><path d="M16 7.5l1.5-1.5a3 3 0 0 1 4.2 4.2L20 12"/></svg>';

const PLATFORMS = [
  {
    name: "Discord",
    color: "#5865F2",
    hosts: ["discord.com", "discord.gg"],
    keyword: "discord",
    icon:
      '<svg viewBox="0 0 24 24"><path fill="white" d="M8.5 12.5c0 .8-.6 1.5-1.3 1.5s-1.3-.7-1.3-1.5.6-1.5 1.3-1.5 1.3.7 1.3 1.5zm8.6 0c0 .8-.6 1.5-1.3 1.5s-1.3-.7-1.3-1.5.6-1.5 1.3-1.5 1.3.7 1.3 1.5z"/><path fill="white" d="M17.5 6.5C16.3 5.9 15 5.5 13.7 5.3c-.2.3-.3.6-.5 1-1.3-.2-2.7-.2-4 0-.1-.4-.3-.7-.5-1-1.3.2-2.6.6-3.8 1.2C2.6 9.7 2 13 2.3 16.2c1.5 1.1 3 1.8 4.6 2.3.4-.5.7-1.1 1-1.7-.6-.2-1.1-.5-1.6-.8.1-.1.3-.2.4-.3 3 1.4 6.3 1.4 9.3 0 .1.1.3.2.4.3-.5.3-1 .6-1.6.8.3.6.6 1.1 1 1.7 1.6-.5 3.1-1.2 4.6-2.3.4-3.7-.6-7-2.9-9.7z"/></svg>'
  },
  {
    name: "TikTok",
    color: "#010101",
    hosts: ["tiktok.com"],
    keyword: "tiktok",
    icon:
      '<svg viewBox="0 0 24 24"><path fill="white" d="M14.5 3h-2.7v11.6a2.6 2.6 0 1 1-1.9-2.5v-2.8a5.4 5.4 0 1 0 4.6 5.3V9.2a6.7 6.7 0 0 0 4 1.3V7.8a4 4 0 0 1-4-4.1z"/></svg>'
  },
  {
    name: "Instagram",
    color: "#d6249f",
    gradient: "linear-gradient(45deg, #feda75, #d62976, #4f5bd5)",
    hosts: ["instagram.com"],
    keyword: "instagram",
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.6"><rect x="3.5" y="3.5" width="17" height="17" rx="5"/><circle cx="12" cy="12" r="4.2"/><circle cx="17.2" cy="6.8" r="1" fill="white" stroke="none"/></svg>'
  },
  {
    name: "YouTube",
    color: "#FF0000",
    hosts: ["youtube.com", "youtu.be"],
    keyword: "youtube",
    icon:
      '<svg viewBox="0 0 24 24"><rect x="2.5" y="5.5" width="19" height="13" rx="4" fill="white"/><path fill="#FF0000" d="M10.5 9.2v5.6l5-2.8z"/></svg>'
  },
  {
    name: "X (Twitter)",
    color: "#000000",
    hosts: ["twitter.com", "x.com"],
    keyword: "twitter",
    icon:
      '<svg viewBox="0 0 24 24"><path stroke="white" stroke-width="2.4" stroke-linecap="round" fill="none" d="M4 4l16 16M20 4L4 20"/></svg>'
  },
  {
    name: "Twitch",
    color: "#9146FF",
    hosts: ["twitch.tv"],
    keyword: "twitch",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M5 3l-2 4v12h5v2h3l2-2h4l4-4V3H5zm14 10l-3 3h-4l-2 2v-2H7V5h12v8z"/><rect x="12" y="7" width="1.6" height="4.5"/><rect x="16" y="7" width="1.6" height="4.5"/></svg>'
  },
  {
    name: "Telegram",
    color: "#26A5E4",
    hosts: ["t.me", "telegram.org", "telegram.me"],
    keyword: "telegram",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M21 4L3 11.5l6 2 2 6 2.5-4 4.5 3.5L21 4zM9.5 13l8-6.5-6.5 7.5-.3 3-1.2-4z"/></svg>'
  },
  {
    name: "WhatsApp",
    color: "#25D366",
    hosts: ["wa.me", "whatsapp.com"],
    keyword: "whatsapp",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M12 3a9 9 0 0 0-7.8 13.5L3 21l4.7-1.2A9 9 0 1 0 12 3zm0 16.2a7.2 7.2 0 0 1-3.7-1l-.3-.2-2.8.7.7-2.7-.2-.3A7.2 7.2 0 1 1 12 19.2zm4-5.4c-.2-.1-1.3-.6-1.5-.7-.2-.1-.4-.1-.5.1-.2.2-.6.7-.7.9-.1.2-.3.2-.5.1-.7-.3-1.4-.7-2-1.3-.5-.5-1-1.1-1.4-1.7-.1-.2 0-.4.1-.5.1-.1.2-.3.4-.4.1-.1.2-.3.2-.4.1-.2 0-.3 0-.5-.1-.1-.5-1.3-.7-1.7-.2-.5-.4-.4-.5-.4h-.5c-.2 0-.5.1-.7.3-.2.2-.9.9-.9 2.2s1 2.5 1.1 2.7c.1.2 2 3 4.8 4.2.7.3 1.2.5 1.6.6.7.2 1.3.2 1.8.1.5-.1 1.3-.5 1.5-1 .2-.5.2-.9.1-1z"/></svg>'
  },
  {
    name: "Snapchat",
    color: "#FFFC00",
    dark: true,
    hosts: ["snapchat.com"],
    keyword: "snapchat",
    icon:
      '<svg viewBox="0 0 24 24" fill="#3c3c3c"><path d="M12 3c-3 0-5 2.3-5 5.5 0 1 .1 1.8.2 2.5-.7.3-1.7.6-2.2 1-.3.2-.2.6.1.8.5.3 1.3.6 1.8 1-.1.3-.3.6-.6.9-.3.3-.1.7.3.8.6.1 1.1.2 1.4.5.2.7.9 2 3 2.4.5.1 1-.2 1.5-.2h1.1c.5 0 1 .3 1.5.2 2.1-.4 2.8-1.7 3-2.4.3-.3.8-.4 1.4-.5.4-.1.6-.5.3-.8-.3-.3-.5-.6-.6-.9.5-.4 1.3-.7 1.8-1 .3-.2.4-.6.1-.8-.5-.4-1.5-.7-2.2-1 .1-.7.2-1.5.2-2.5 0-3.2-2-5.5-5-5.5z"/></svg>'
  },
  {
    name: "Spotify",
    color: "#1DB954",
    hosts: ["spotify.com"],
    keyword: "spotify",
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round"><path d="M6 15.5c3.5-1.2 8-1 11 .7"/><path d="M6.5 11.8c4-1.3 9-1 12 1"/><path d="M7 8.2c4.5-1.4 10-1.1 13.5 1.2"/></svg>'
  },
  {
    name: "Facebook",
    color: "#1877F2",
    hosts: ["facebook.com", "fb.com"],
    keyword: "facebook",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M14 8.5h2V5.7c-.3 0-1.3-.1-2.5-.1-2.5 0-4.2 1.5-4.2 4.3v2.3H6.8v3.2h2.5V21h3.3v-5.6h2.5l.4-3.2h-2.9V9.9c0-.9.2-1.4 1.4-1.4z"/></svg>'
  },
  {
    name: "LinkedIn",
    color: "#0A66C2",
    hosts: ["linkedin.com"],
    keyword: "linkedin",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M6.9 8.6H4V19h2.9V8.6zM5.4 4.3a1.7 1.7 0 1 0 0 3.4 1.7 1.7 0 0 0 0-3.4zM20 12.6c0-3-1.6-4.4-3.8-4.4-1.7 0-2.5 1-2.9 1.6V8.6H10.4c0 .8 0 10.4 0 10.4h2.9v-5.8c0-.3 0-.6.1-.9.3-.6.9-1.3 1.9-1.3 1.3 0 1.9 1 1.9 2.5v5.5H20v-5.9z"/></svg>'
  },
  {
    name: "GitHub",
    color: "#181717",
    hosts: ["github.com"],
    keyword: "github",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M12 2.5a9.5 9.5 0 0 0-3 18.5c.5.1.6-.2.6-.5v-1.7c-2.7.6-3.2-1.2-3.2-1.2-.4-1.1-1-1.4-1-1.4-.9-.6.1-.6.1-.6.9.1 1.4 1 1.4 1 .9 1.5 2.3 1.1 2.8.8.1-.6.3-1.1.6-1.3-2.2-.2-4.4-1.1-4.4-4.9 0-1.1.4-1.9 1-2.6-.1-.2-.4-1.2.1-2.6 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 4.9 0c1.9-1.3 2.7-1 2.7-1 .5 1.4.2 2.4.1 2.6.6.7 1 1.5 1 2.6 0 3.8-2.2 4.7-4.4 4.9.3.3.6.8.6 1.7v2.5c0 .3.1.6.6.5A9.5 9.5 0 0 0 12 2.5z"/></svg>'
  }
];

const DEFAULT_PLATFORM = { name: "Lien", color: "#b04a2f", hosts: [], keyword: "", icon: ICON_LINK };

function detectPlatform(source, resolvedTarget) {
  let hostname = "";
  try {
    hostname = new URL(resolvedTarget).hostname.toLowerCase();
  } catch {
    hostname = "";
  }

  const byHost = PLATFORMS.find((platform) =>
    platform.hosts.some((host) => hostname === host || hostname.endsWith(`.${host}`))
  );
  if (byHost) {
    return byHost;
  }

  const label = source.toLowerCase();
  const byKeyword = PLATFORMS.find((platform) => platform.keyword && label.includes(platform.keyword));
  return byKeyword || DEFAULT_PLATFORM;
}

function buildPublicLinkHref(source) {
  const slashIndex = source.indexOf("/");
  const host = slashIndex === -1 ? source : source.slice(0, slashIndex);
  const linkPath = slashIndex === -1 ? "/" : source.slice(slashIndex);
  if (!host) {
    return linkPath;
  }
  return `https://${host}${linkPath}`;
}

function buildPublicLinks(redirects) {
  return redirects
    .filter((item) => item.public && !item.source.startsWith("*."))
    .map((item) => {
      const resolvedTarget = resolveRedirectTarget(item.target, redirects, new Set([item.source])) || item.target;
      const platform = detectPlatform(item.source, resolvedTarget);
      return {
        href: buildPublicLinkHref(item.source),
        label: item.publicLabel || platform.name,
        platform
      };
    });
}

function renderLinksList(publicLinks) {
  if (!publicLinks.length) {
    return "";
  }

  const rows = publicLinks
    .map(
      (link) => `
        <a class="link-row" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">
          <span class="link-row-icon" style="background:${link.platform.gradient || link.platform.color}">
            ${link.platform.icon}
          </span>
          <span class="link-row-label">${escapeHtml(link.label)}</span>
          <span class="link-row-arrow" aria-hidden="true">&rsaquo;</span>
        </a>
      `
    )
    .join("");

  return `<div class="links-list">${rows}</div>`;
}

function renderHome(res, redirects) {
  const publicLinks = buildPublicLinks(redirects);
  const linksList = renderLinksList(publicLinks);
  const content = `
    <section class="profile-card">
      <div class="hero-glow" aria-hidden="true"></div>
      <span class="hero-badge">Redirections 301</span>
      <h1>Rooky Redirect</h1>
      <p>Une passerelle sobre pour vos domaines et sous-domaines : chaque URL trouve sa destination, sans fioriture.</p>
      ${linksList}
    </section>
    <footer class="site-footer">
      <a href="/admin" class="footer-link">Administration</a>
    </footer>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(renderPage("Rooky Redirect", content));
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
        .profile-card {
          position: relative;
          overflow: hidden;
          max-width: 480px;
          margin: 90px auto 24px;
          padding: 44px 36px;
          text-align: center;
          background: rgba(255, 253, 249, 0.92);
          border: 1px solid var(--line);
          border-radius: 28px;
          box-shadow: 0 24px 50px rgba(81, 51, 34, 0.12);
          animation: hero-rise 0.6s ease-out;
        }
        .hero-glow {
          position: absolute;
          inset: -60% -40% auto -40%;
          height: 260px;
          background: radial-gradient(circle, rgba(176, 74, 47, 0.25), transparent 70%);
          filter: blur(10px);
          animation: hero-glow-move 8s ease-in-out infinite;
          pointer-events: none;
        }
        .hero-badge {
          position: relative;
          display: inline-block;
          padding: 6px 14px;
          border-radius: 999px;
          background: #f5e2d6;
          color: var(--accent-dark);
          font-size: 12px;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          margin-bottom: 18px;
        }
        .profile-card h1 {
          position: relative;
          font-size: 2.1rem;
          margin-bottom: 10px;
        }
        .profile-card p {
          position: relative;
          margin: 0 auto 8px;
        }
        @keyframes hero-rise {
          from {
            opacity: 0;
            transform: translateY(12px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        @keyframes hero-glow-move {
          0%, 100% {
            transform: translateX(-8%) scale(1);
          }
          50% {
            transform: translateX(8%) scale(1.15);
          }
        }
        @media (prefers-reduced-motion: reduce) {
          .profile-card,
          .hero-glow {
            animation: none;
          }
        }
        .links-list {
          position: relative;
          display: flex;
          flex-direction: column;
          gap: 12px;
          margin-top: 28px;
          text-align: left;
        }
        .link-row {
          display: flex;
          align-items: center;
          gap: 14px;
          padding: 12px 16px;
          border-radius: 16px;
          background: #fff;
          border: 1px solid var(--line);
          text-decoration: none;
          color: var(--ink);
          transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
        }
        .link-row:hover {
          transform: translateY(-2px) scale(1.01);
          box-shadow: 0 12px 24px rgba(81, 51, 34, 0.1);
          border-color: var(--accent);
        }
        .link-row-icon {
          flex: 0 0 auto;
          width: 38px;
          height: 38px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .link-row-icon svg {
          width: 20px;
          height: 20px;
        }
        .link-row-label {
          flex: 1;
          font-size: 14px;
          font-weight: 600;
        }
        .link-row-arrow {
          flex: 0 0 auto;
          color: var(--muted);
          font-size: 18px;
          transition: transform 0.15s ease;
        }
        .link-row:hover .link-row-arrow {
          transform: translateX(3px);
          color: var(--accent);
        }
        .site-footer {
          text-align: center;
          margin: 0 0 40px;
        }
        .footer-link {
          font-size: 12px;
          color: var(--muted);
          text-decoration: none;
          opacity: 0.7;
        }
        .footer-link:hover {
          opacity: 1;
          text-decoration: underline;
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
        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .checkbox-label input {
          width: auto;
        }
        .checkbox-label span {
          margin-bottom: 0;
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
