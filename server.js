const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const ROOT_DIR = __dirname;
const STORAGE_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT_DIR, "data");
const REDIRECTS_FILE = path.join(STORAGE_DIR, "redirects.json");
const SITE_CONFIG_FILE = path.join(STORAGE_DIR, "site-config.json");
const MONITORS_FILE = path.join(STORAGE_DIR, "monitors.json");

loadEnv(path.join(ROOT_DIR, ".env"));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-moi";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-moi-aussi";
const MONITOR_INTERVAL_MS = 60 * 1000;
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

    if (pathname === "/go" && method === "GET") {
      const redirects = readRedirects();
      const source = normalizeSource(url.searchParams.get("to") || "");
      const item = redirects.find((entry) => entry.source === source && entry.public);

      if (!item) {
        renderNotFound(res, requestHost, pathname);
        return;
      }

      const resolvedTarget = resolveRedirectTarget(item.target, redirects, new Set([item.source]));
      if (!resolvedTarget) {
        res.writeHead(500, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(
          renderPage(
            "Erreur",
            `<p>La redirection pour <code>${escapeHtml(item.source)}</code> forme une boucle ou pointe vers une cible inexistante.</p>`
          )
        );
        return;
      }

      res.writeHead(301, { Location: resolvedTarget, "Cache-Control": "no-store" });
      res.end();
      if (!isPrefetchRequest(req)) {
        registerClick(item.source);
      }
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
      const activeTab = url.searchParams.get("tab") || "";
      return renderAdmin(res, redirects, getFlashMessage(url), editingRedirect, activeTab);
    }

    if (pathname === "/admin/site" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      return renderSiteSettings(res, getFlashMessage(url), getSiteConfig(), readRedirects());
    }

    if (pathname === "/admin/site" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const logoUrl = (form.logoUrl || "").trim();
      if (logoUrl && !parseAbsoluteTarget(logoUrl)) {
        redirect(res, "/admin/site?error=URL%20du%20logo%20invalide");
        return;
      }

      const faviconUrl = (form.faviconUrl || "").trim();
      if (faviconUrl && !parseAbsoluteTarget(faviconUrl)) {
        redirect(res, "/admin/site?error=URL%20du%20favicon%20invalide");
        return;
      }

      writeSiteConfig({
        title: (form.title || "").trim(),
        badge: (form.badge || "").trim(),
        tagline: (form.tagline || "").trim(),
        logoUrl,
        faviconUrl
      });
      redirect(res, "/admin/site?success=Personnalisation%20enregistree");
      return;
    }

    if (pathname === "/admin/site/groups/move" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const name = (form.name || "").trim();
      const direction = form.direction === "up" ? -1 : 1;
      const redirects = readRedirects();
      const allNames = Array.from(new Set(redirects.map((item) => (item.group || "").trim()).filter(Boolean)));
      const currentOrder = applyGroupOrder(allNames, getSiteConfig().groupOrder);
      const index = currentOrder.indexOf(name);
      const targetIndex = index + direction;

      if (index !== -1 && targetIndex >= 0 && targetIndex < currentOrder.length) {
        [currentOrder[index], currentOrder[targetIndex]] = [currentOrder[targetIndex], currentOrder[index]];
        writeSiteConfig({ groupOrder: currentOrder });
      }

      redirect(res, "/admin/site?success=Ordre%20des%20groupes%20mis%20a%20jour");
      return;
    }

    if (pathname === "/admin/site/groups/reorder" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const order = (form.order || "")
        .split("||")
        .map((value) => value.trim())
        .filter(Boolean);
      writeSiteConfig({ groupOrder: order });
      redirect(res, "/admin/site?success=Ordre%20des%20groupes%20mis%20a%20jour");
      return;
    }

    if (pathname === "/admin/site/groups/rename" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const oldName = (form.oldName || "").trim();
      const newName = (form.newName || "").trim();

      if (!oldName || !newName) {
        redirect(res, "/admin/site?error=Nom%20de%20groupe%20invalide");
        return;
      }

      if (oldName !== newName) {
        const redirects = readRedirects();
        let changed = false;
        for (const item of redirects) {
          if ((item.group || "").trim() === oldName) {
            item.group = newName;
            changed = true;
          }
        }
        if (changed) {
          writeRedirects(redirects);
        }

        const groupOrder = getSiteConfig().groupOrder.map((name) => (name === oldName ? newName : name));
        writeSiteConfig({ groupOrder });
      }

      redirect(res, "/admin/site?success=Groupe%20renomme");
      return;
    }

    if (pathname === "/admin/monitoring" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      return renderMonitoring(res, readMonitorConfig(), getFlashMessage(url));
    }

    if (pathname === "/admin/monitoring" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const webhookUrl = (form.webhookUrl || "").trim();
      if (webhookUrl && !parseAbsoluteTarget(webhookUrl)) {
        redirect(res, "/admin/monitoring?error=URL%20de%20webhook%20invalide");
        return;
      }

      const config = readMonitorConfig();
      config.webhookUrl = webhookUrl;
      writeMonitorConfig(config);

      if (webhookUrl) {
        const testResult = await sendDiscordEmbed(webhookUrl, {
          title: "Test de notification",
          description: "Si vous voyez ce message, le webhook est correctement configure.",
          color: 0x6d5ef7,
          timestamp: new Date().toISOString()
        });

        if (!testResult.ok) {
          console.error(`[monitoring] echec du message de test: ${testResult.status || ""} ${testResult.error || ""}`);
          redirect(
            res,
            `/admin/monitoring?error=${encodeURIComponent(
              `Webhook enregistre mais le message de test a echoue (${testResult.status || testResult.error || "erreur inconnue"}).`
            )}`
          );
          return;
        }
      }

      redirect(res, "/admin/monitoring?success=Webhook%20enregistre%20et%20message%20de%20test%20envoye");
      return;
    }

    if (pathname === "/admin/monitoring/bots" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const name = (form.name || "").trim();
      const guildId = (form.guildId || "").trim();
      const botId = (form.botId || "").trim();
      const botUsername = (form.botUsername || "").trim();

      if (!guildId || (!botId && !botUsername)) {
        redirect(res, "/admin/monitoring?error=ID%20de%20serveur%20et%20ID%20ou%20nom%20du%20bot%20requis");
        return;
      }

      const config = readMonitorConfig();
      config.bots.push({
        id: crypto.randomBytes(4).toString("hex"),
        name,
        guildId,
        botId,
        botUsername,
        status: "inconnu",
        lastCheckedAt: "",
        lastError: ""
      });
      writeMonitorConfig(config);
      redirect(res, "/admin/monitoring?success=Bot%20ajoute");
      return;
    }

    if (pathname === "/admin/monitoring/bots/delete" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const config = readMonitorConfig();
      config.bots = config.bots.filter((bot) => bot.id !== id);
      writeMonitorConfig(config);
      redirect(res, "/admin/monitoring?success=Bot%20retire");
      return;
    }

    if (pathname === "/admin/monitoring/bots/check" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const config = readMonitorConfig();
      const bot = config.bots.find((entry) => entry.id === id);

      if (bot) {
        await checkAndNotifyBot(bot, config);
        writeMonitorConfig(config);
      }

      redirect(res, "/admin/monitoring?success=Verification%20effectuee");
      return;
    }

    if (pathname === "/admin/stats" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const statsTab = url.searchParams.get("tab") || "";
      return renderStats(res, readRedirects().filter(isPubliclyVisible), getFlashMessage(url), statsTab);
    }

    if (pathname === "/admin/stats/reset" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const source = normalizeSource(form.source || "");
      const tab = (form.tab || "").trim();
      const redirects = readRedirects();
      const item = redirects.find((entry) => entry.source === source);
      if (item) {
        item.clicks = 0;
        writeRedirects(redirects);
      }
      const query = new URLSearchParams({ success: "Compteur remis a zero" });
      if (tab) {
        query.set("tab", tab);
      }
      redirect(res, `/admin/stats?${query.toString()}`);
      return;
    }

    if (pathname === "/admin/redirects" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const rawOriginalSource = (form.originalSource || "").trim();
      const originalSource = rawOriginalSource ? normalizeSource(rawOriginalSource) : "";
      const useFinalLink = form.useFinalLink === "on";
      const rawSource = (form.source || "").trim();
      const tab = (form.tab || "").trim();

      if (!rawSource && !useFinalLink) {
        redirect(res, buildAdminRedirectUrl({ error: "La source est requise.", tab }));
        return;
      }

      const source = rawSource ? normalizeSource(rawSource) : generatePlaceholderSource();
      const target = (form.target || "").trim();
      const allRedirects = readRedirects();
      const editIndex = originalSource ? allRedirects.findIndex((item) => item.source === originalSource) : -1;
      const existingRedirects = allRedirects.filter((item) => item.source !== originalSource);

      const error = validateRedirectInput(source, target, existingRedirects);
      if (error) {
        redirect(res, buildAdminRedirectUrl({ error, tab }));
        return;
      }

      const customImageUrl = (form.customImageUrl || "").trim();
      if (customImageUrl && !parseAbsoluteTarget(customImageUrl)) {
        redirect(res, buildAdminRedirectUrl({ error: "URL d'image invalide.", tab }));
        return;
      }

      const spotifyMeta = isSpotifyUrl(target) ? await fetchSpotifyOEmbed(target) : null;
      const steamMeta = isSteamUrl(target) ? await fetchSteamAppDetails(target) : null;

      const savedRedirect = {
        source,
        target,
        code: 301,
        updatedAt: new Date().toISOString(),
        public: form.public === "on",
        publicLabel: (form.publicLabel || "").trim(),
        group: (form.groupNew || "").trim() || (form.groupSelect || "").trim(),
        useFinalLink,
        customImageUrl,
        spotifyTitle: spotifyMeta ? spotifyMeta.title : "",
        spotifyImage: spotifyMeta ? spotifyMeta.thumbnailUrl : "",
        steamTitle: steamMeta ? steamMeta.title : "",
        steamImage: steamMeta ? steamMeta.imageUrl : ""
      };

      if (editIndex === -1) {
        existingRedirects.push(savedRedirect);
      } else {
        existingRedirects.splice(Math.min(editIndex, existingRedirects.length), 0, savedRedirect);
      }
      writeRedirects(existingRedirects);
      redirect(
        res,
        buildAdminRedirectUrl({
          success: originalSource ? "Redirection modifiee" : "Redirection enregistree",
          tab
        })
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
      const tab = (form.tab || "").trim();
      const redirects = readRedirects().filter((item) => item.source !== source);
      writeRedirects(redirects);
      redirect(res, buildAdminRedirectUrl({ success: "Redirection supprimee", tab }));
      return;
    }

    if (pathname === "/admin/redirects/move" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const source = normalizeSource(form.source || "");
      const direction = form.direction === "up" ? -1 : 1;
      const tab = (form.tab || "").trim();
      const redirects = readRedirects();
      const index = redirects.findIndex((item) => item.source === source);
      const targetIndex = index + direction;

      if (index !== -1 && targetIndex >= 0 && targetIndex < redirects.length) {
        [redirects[index], redirects[targetIndex]] = [redirects[targetIndex], redirects[index]];
        writeRedirects(redirects);
      }

      redirect(res, buildAdminRedirectUrl({ success: "Ordre mis a jour", tab }));
      return;
    }

    if (pathname === "/admin/redirects/reorder" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const tab = (form.tab || "").trim();
      const order = (form.order || "")
        .split("||")
        .map((value) => normalizeSource(value))
        .filter(Boolean);
      const orderSet = new Set(order);
      const redirects = readRedirects();
      const itemsBySource = new Map(redirects.map((item) => [item.source, item]));

      const reordered = [];
      let inserted = false;
      for (const item of redirects) {
        if (!orderSet.has(item.source)) {
          reordered.push(item);
          continue;
        }
        if (!inserted) {
          for (const source of order) {
            const orderedItem = itemsBySource.get(source);
            if (orderedItem) {
              reordered.push(orderedItem);
            }
          }
          inserted = true;
        }
      }

      writeRedirects(reordered);
      redirect(res, buildAdminRedirectUrl({ success: "Ordre mis a jour", tab }));
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
        res.writeHead(500, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(
          renderPage(
            "Erreur",
            `<p>La redirection pour <code>${escapeHtml(match.source)}</code> forme une boucle ou pointe vers une cible inexistante.</p>`
          )
        );
        return;
      }

      res.writeHead(301, { Location: resolvedTarget, "Cache-Control": "no-store" });
      res.end();
      if (!isPrefetchRequest(req)) {
        registerClick(match.source);
      }
      return;
    }

    if (pathname === "/") {
      return renderHome(res, redirects);
    }

    renderNotFound(res, requestHost, pathname);
  } catch (error) {
    res.writeHead(500, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
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

  if (!fs.existsSync(SITE_CONFIG_FILE)) {
    fs.writeFileSync(SITE_CONFIG_FILE, "{}\n", "utf8");
  }

  if (!fs.existsSync(MONITORS_FILE)) {
    fs.writeFileSync(MONITORS_FILE, JSON.stringify({ webhookUrl: "", bots: [] }, null, 2) + "\n", "utf8");
  }
}

const DEFAULT_SITE_CONFIG = {
  title: "Rooky",
  badge: "Liens officiels",
  tagline: "Retrouvez ici tous mes liens et comptes officiels, reunis au meme endroit.",
  logoUrl: ""
};

function readSiteConfig() {
  ensureDataFile();
  try {
    const raw = fs.readFileSync(SITE_CONFIG_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeSiteConfig(nextConfig) {
  const current = readSiteConfig();
  const merged = { ...current, ...nextConfig };
  fs.writeFileSync(SITE_CONFIG_FILE, `${JSON.stringify(merged, null, 2)}\n`, "utf8");
}

function getSiteConfig() {
  const config = readSiteConfig();
  return {
    title: String(config.title || "").trim() || DEFAULT_SITE_CONFIG.title,
    badge: String(config.badge || "").trim() || DEFAULT_SITE_CONFIG.badge,
    tagline: String(config.tagline || "").trim() || DEFAULT_SITE_CONFIG.tagline,
    logoUrl: String(config.logoUrl || "").trim(),
    faviconUrl: String(config.faviconUrl || "").trim(),
    groupOrder: Array.isArray(config.groupOrder) ? config.groupOrder.filter((v) => typeof v === "string") : []
  };
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

  runMonitorChecks().catch((error) => console.error(`[monitoring] ${error.message}`));
  setInterval(() => {
    runMonitorChecks().catch((error) => console.error(`[monitoring] ${error.message}`));
  }, MONITOR_INTERVAL_MS);
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

function isPrefetchRequest(req) {
  const purpose = (
    req.headers["sec-purpose"] ||
    req.headers["purpose"] ||
    req.headers["x-purpose"] ||
    req.headers["x-moz"] ||
    ""
  ).toLowerCase();
  return purpose.includes("prefetch") || purpose.includes("preview") || purpose.includes("prerender");
}

function registerClick(source) {
  const redirects = readRedirects();
  const item = redirects.find((entry) => entry.source === source);
  if (!item) {
    return;
  }
  item.clicks = (item.clicks || 0) + 1;
  writeRedirects(redirects);
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
    sourcePath === "/logout" ||
    sourcePath === "/go"
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

function generatePlaceholderSource() {
  return `/_link-${crypto.randomBytes(4).toString("hex")}`;
}

function isSpotifyUrl(value) {
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    return hostname === "open.spotify.com" || hostname.endsWith(".spotify.com");
  } catch {
    return false;
  }
}

function fetchSpotifyOEmbed(spotifyUrl, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const oembedUrl = `https://open.spotify.com/oembed?url=${encodeURIComponent(spotifyUrl)}`;

    const req = https.get(oembedUrl, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve(null);
        return;
      }

      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          resolve({
            title: String(parsed.title || "").trim(),
            thumbnailUrl: String(parsed.thumbnail_url || "").trim()
          });
        } catch {
          resolve(null);
        }
      });
    });

    req.on("timeout", () => {
      req.destroy();
    });
    req.on("error", () => resolve(null));
  });
}

function isSteamUrl(value) {
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    return hostname === "store.steampowered.com" || hostname.endsWith(".steampowered.com");
  } catch {
    return false;
  }
}

function extractSteamAppId(value) {
  const match = value.match(/\/app\/(\d+)/);
  return match ? match[1] : "";
}

function fetchSteamAppDetails(steamUrl, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const appId = extractSteamAppId(steamUrl);
    if (!appId) {
      resolve(null);
      return;
    }

    const apiUrl = `https://store.steampowered.com/api/appdetails?appids=${appId}&l=french`;

    const req = https.get(apiUrl, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve(null);
        return;
      }

      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          const entry = parsed[appId];
          if (!entry || !entry.success || !entry.data) {
            resolve(null);
            return;
          }
          resolve({
            title: String(entry.data.name || "").trim(),
            imageUrl: String(entry.data.header_image || "").trim()
          });
        } catch {
          resolve(null);
        }
      });
    });

    req.on("timeout", () => {
      req.destroy();
    });
    req.on("error", () => resolve(null));
  });
}

function readMonitorConfig() {
  ensureDataFile();
  try {
    const raw = fs.readFileSync(MONITORS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      webhookUrl: String(parsed?.webhookUrl || "").trim(),
      bots: Array.isArray(parsed?.bots) ? parsed.bots : []
    };
  } catch {
    return { webhookUrl: "", bots: [] };
  }
}

function writeMonitorConfig(config) {
  fs.writeFileSync(MONITORS_FILE, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function fetchDiscordGuildWidget(guildId, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const apiUrl = `https://discord.com/api/guilds/${encodeURIComponent(guildId)}/widget.json?_=${Date.now()}`;

    const req = https.get(apiUrl, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve({ ok: false, error: `HTTP ${res.statusCode} (le widget du serveur est-il active ?)` });
        return;
      }

      let body = "";
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ ok: true, members: Array.isArray(parsed.members) ? parsed.members : [] });
        } catch {
          resolve({ ok: false, error: "Reponse invalide du widget Discord." });
        }
      });
    });

    req.on("timeout", () => {
      req.destroy();
    });
    req.on("error", (error) => resolve({ ok: false, error: error.message }));
  });
}

async function checkBotStatus(guildId, botId, botUsername) {
  const widget = await fetchDiscordGuildWidget(guildId);
  if (!widget.ok) {
    return { status: "erreur", detail: widget.error };
  }

  const normalizedUsername = (botUsername || "").trim().toLowerCase();
  const member = widget.members.find((m) => {
    const idMatch = botId && String(m.id) === String(botId);
    const usernameMatch = normalizedUsername && String(m.username || "").toLowerCase() === normalizedUsername;
    return idMatch || usernameMatch;
  });

  return member
    ? { status: "en ligne", detail: member.status || "online" }
    : { status: "hors ligne", detail: "" };
}

function sendDiscordEmbed(webhookUrl, embed) {
  return new Promise((resolve) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(webhookUrl);
    } catch {
      resolve({ ok: false, error: "URL de webhook invalide." });
      return;
    }

    const payload = JSON.stringify({ embeds: [embed] });
    let settled = false;
    const finish = (result) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };

    const req = https.request(
      {
        hostname: parsedUrl.hostname,
        path: `${parsedUrl.pathname}${parsedUrl.search}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        },
        timeout: 6000
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
        });
        res.on("end", () => {
          const ok = res.statusCode >= 200 && res.statusCode < 300;
          finish(ok ? { ok: true, status: res.statusCode } : { ok: false, status: res.statusCode, error: body });
        });
      }
    );

    req.on("timeout", () => {
      req.destroy();
      finish({ ok: false, error: "Delai depasse en contactant Discord." });
    });
    req.on("error", (error) => finish({ ok: false, error: error.message }));
    req.write(payload);
    req.end();
  });
}

async function checkAndNotifyBot(bot, config) {
  const result = await checkBotStatus(bot.guildId, bot.botId, bot.botUsername);
  const previousStatus = bot.status || "inconnu";
  const label = bot.name || bot.botUsername || bot.botId;

  if (result.status === "erreur") {
    console.warn(`[monitoring] ${label}: erreur (${result.detail})`);
    bot.lastError = result.detail;
    bot.lastCheckedAt = new Date().toISOString();
    return;
  }

  console.log(`[monitoring] ${label}: ${result.status} (precedent: ${previousStatus})`);
  bot.lastError = "";
  bot.lastCheckedAt = new Date().toISOString();

  if (result.status === previousStatus) {
    return;
  }

  console.log(`[monitoring] ${label}: changement detecte ${previousStatus} -> ${result.status}`);

  if (config.webhookUrl && previousStatus !== "inconnu") {
    const sendResult = await sendDiscordEmbed(config.webhookUrl, {
      title: label,
      description: result.status === "en ligne" ? "Le bot est maintenant en ligne." : "Le bot est maintenant hors ligne.",
      color: result.status === "en ligne" ? 0x3ddc84 : 0xf0555f,
      timestamp: new Date().toISOString()
    });
    if (sendResult.ok) {
      console.log(`[monitoring] ${label}: embed envoye`);
    } else {
      console.error(`[monitoring] ${label}: echec envoi embed: ${sendResult.status || ""} ${sendResult.error || ""}`);
    }
  } else if (previousStatus === "inconnu") {
    console.log(`[monitoring] ${label}: premiere verification, pas de notification`);
  }

  bot.status = result.status;
}

async function runMonitorChecks() {
  const config = readMonitorConfig();
  if (!config.bots.length) {
    return;
  }

  console.log(`[monitoring] verification de ${config.bots.length} bot(s)...`);

  for (const bot of config.bots) {
    await checkAndNotifyBot(bot, config);
  }

  writeMonitorConfig(config);
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

function buildAdminRedirectUrl({ success = "", error = "", tab = "" } = {}) {
  const query = new URLSearchParams();
  if (success) {
    query.set("success", success);
  }
  if (error) {
    query.set("error", error);
  }
  if (tab) {
    query.set("tab", tab);
  }
  const qs = query.toString();
  return `/admin${qs ? `?${qs}` : ""}`;
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
      <a href="/" class="link-button secondary back-home-link">Retour a l'accueil</a>
    </section>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Connexion", content));
}

function renderAdmin(res, redirects, flash, editingRedirect = null, activeTab = "") {
  const messages = renderMessages(flash);
  const formTitle = editingRedirect ? "Modifier la redirection" : "Nouvelle redirection";
  const submitLabel = editingRedirect ? "Mettre a jour" : "Enregistrer";
  const existingGroups = Array.from(
    new Set(redirects.map((item) => (item.group || "").trim()).filter(Boolean))
  ).sort((a, b) => a.localeCompare(b));
  const currentGroup = editingRedirect ? editingRedirect.group || "" : "";
  const groupOptions = [
    `<option value="">(Aucun groupe)</option>`,
    ...existingGroups.map(
      (group) => `<option value="${escapeHtml(group)}" ${group === currentGroup ? "selected" : ""}>${escapeHtml(group)}</option>`
    )
  ].join("");

  const renderRow = (item, index, tabLabel) => {
    const tabParam = tabLabel ? `&tab=${encodeURIComponent(tabLabel)}` : "";
    return `
    <tr data-source="${escapeHtml(item.source)}" class="draggable-row">
      <td class="drag-handle" draggable="true" title="Glisser pour reordonner">&#8942;&#8942;</td>
      <td><code>${escapeHtml(item.source)}</code></td>
      <td>${renderTargetCell(item.target)}</td>
      <td>${isPubliclyVisible(item) ? "Oui" : "Non"}</td>
      <td class="actions-cell">
        <form method="post" action="/admin/redirects/move">
          <input type="hidden" name="source" value="${escapeHtml(item.source)}" />
          <input type="hidden" name="direction" value="up" />
          <input type="hidden" name="tab" value="${escapeHtml(tabLabel)}" />
          <button type="submit" class="secondary move-button" ${index === 0 ? "disabled" : ""} title="Monter">&uarr;</button>
        </form>
        <form method="post" action="/admin/redirects/move">
          <input type="hidden" name="source" value="${escapeHtml(item.source)}" />
          <input type="hidden" name="direction" value="down" />
          <input type="hidden" name="tab" value="${escapeHtml(tabLabel)}" />
          <button type="submit" class="secondary move-button" ${index === redirects.length - 1 ? "disabled" : ""} title="Descendre">&darr;</button>
        </form>
        <a href="/admin?edit=${encodeURIComponent(item.source)}${tabParam}" class="link-button secondary">Modifier</a>
        <form method="post" action="/admin/redirects/delete">
          <input type="hidden" name="source" value="${escapeHtml(item.source)}" />
          <input type="hidden" name="tab" value="${escapeHtml(tabLabel)}" />
          <button type="submit" class="danger">Supprimer</button>
        </form>
      </td>
    </tr>
  `;
  };

  const renderGroupTable = (items, tabLabel) => `
    <div class="table-scroll">
      <table data-tab="${escapeHtml(tabLabel)}">
        <thead>
          <tr>
            <th></th>
            <th>Source</th>
            <th>Cible</th>
            <th>Public</th>
            <th>Ordre / Action</th>
          </tr>
        </thead>
        <tbody>${items.map((item) => renderRow(item, redirects.indexOf(item), tabLabel)).join("")}</tbody>
      </table>
    </div>
  `;

  const groupSections = (() => {
    if (!redirects.length) {
      return `<section class="card"><p>Aucune redirection enregistree.</p></section>`;
    }

    const byGroup = new Map();
    const order = [];
    for (const item of redirects) {
      const key = (item.group || "").trim();
      if (!byGroup.has(key)) {
        byGroup.set(key, []);
        order.push(key);
      }
      byGroup.get(key).push(item);
    }

    if (order.length <= 1) {
      return `<section class="card group-card">${renderGroupTable(redirects, "")}</section>`;
    }

    const orderedKeys = applyGroupOrder(order, getSiteConfig().groupOrder);
    const tabs = orderedKeys.map((key) => {
      const label = key ? key : "Sans groupe";
      return {
        label,
        content: renderGroupTable(byGroup.get(key), label)
      };
    });

    return `<section class="card group-card">${renderCssTabs(tabs, "admin-tab", activeTab)}</section>`;
  })();

  const content = `
    <header class="topbar">
      <div>
        <h1>Redirections URL</h1>
        <p>La source peut etre un chemin simple ou un sous-domaine avec chemin. La cible peut etre une URL externe ou une autre source deja enregistree.</p>
        <p>L'application essaie d'abord le host exact, puis les variantes usuelles avec et sans <code>www</code>. Si les deux existent, la redirection exacte reste prioritaire.</p>
      </div>
      <div class="topbar-actions">
        <a href="/" class="link-button secondary" target="_blank" rel="noreferrer">Apercu</a>
        <a href="/admin/stats" class="link-button secondary">Statistiques</a>
        <a href="/admin/site" class="link-button secondary">Personnalisation</a>
        <a href="/admin/monitoring" class="link-button secondary">Monitoring</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <details class="card add-redirect" ${editingRedirect ? "open" : ""}>
      <summary class="add-redirect-summary">${editingRedirect ? "Modifier la redirection" : "Ajouter une redirection"}</summary>
      <form method="post" action="/admin/redirects" class="form-grid">
        <input type="hidden" name="originalSource" value="${escapeHtml(editingRedirect ? editingRedirect.source : "")}" />
        <input type="hidden" name="tab" value="${escapeHtml(activeTab)}" />
        <label>
          <span>URL souhaitee (facultative si "Utiliser le lien final" est coche)</span>
          <input type="text" name="source" placeholder="www.example.rooky.fr/mon-chemin ou *.exemple.fr ou /mon-chemin" value="${escapeHtml(editingRedirect ? editingRedirect.source : "")}" />
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
        <label>
          <span>Image personnalisee (URL, optionnel)</span>
          <input type="text" name="customImageUrl" placeholder="https://exemple.com/mon-image.png" value="${escapeHtml(editingRedirect ? editingRedirect.customImageUrl || "" : "")}" />
        </label>
        <label>
          <span>Ajouter au menu / groupe existant</span>
          <select name="groupSelect">${groupOptions}</select>
        </label>
        <label>
          <span>Ou creer un nouveau menu / groupe</span>
          <input type="text" name="groupNew" placeholder="Ex: Reseaux sociaux" />
        </label>
        <label class="checkbox-label">
          <span class="switch">
            <input type="checkbox" name="public" ${editingRedirect && editingRedirect.public ? "checked" : ""} />
            <span class="switch-track"><span class="switch-thumb"></span></span>
          </span>
          <span>Afficher ce lien sur la page d'accueil publique</span>
        </label>
        <label class="checkbox-label">
          <span class="switch">
            <input type="checkbox" name="useFinalLink" ${editingRedirect && editingRedirect.useFinalLink ? "checked" : ""} />
            <span class="switch-track"><span class="switch-thumb"></span></span>
          </span>
          <span>Utiliser le lien final pour ce lien</span>
        </label>
        <p>La cible peut etre une URL externe ou une source deja enregistree. L'application resout alors la destination finale avant de repondre en 301.</p>
        <p>Cochez "Utiliser le lien final pour ce lien" si vous n'avez pas besoin d'une redirection source fonctionnelle : l'URL souhaitee devient facultative, et seule la cible finale sera utilisee sur la page publique.</p>
        <p>Chaque menu/groupe cree devient un onglet sur la page d'accueil publique, et les liens que vous y ajoutez apparaissent a l'interieur. Utilisez les fleches dans les listes ci-dessous pour changer l'ordre d'affichage.</p>
        <p>Note: une source generique <code>*.domaine.fr</code> ne peut jamais apparaitre comme lien public individuel, meme si la case est cochee. La colonne "Public" reflete l'etat reel sur la page d'accueil.</p>
        <p>L'image personnalisee remplace l'icone (ou la favicon detectee automatiquement) affichee sur la page publique pour ce lien, y compris la pochette Spotify ou la bannière Steam si applicable.</p>
        <div class="form-actions">
          <button type="submit">${submitLabel}</button>
          ${editingRedirect ? '<a href="/admin" class="link-button secondary">Annuler</a>' : ""}
        </div>
      </form>
    </details>
    <h2 class="section-title">Menus et redirections</h2>
    ${groupSections}
    <script>
      (function () {
        let draggedRow = null;

        document.querySelectorAll(".drag-handle").forEach((handle) => {
          handle.addEventListener("dragstart", () => {
            draggedRow = handle.closest("tr");
            draggedRow.classList.add("dragging");
          });

          handle.addEventListener("dragend", () => {
            if (draggedRow) {
              draggedRow.classList.remove("dragging");
            }
            draggedRow = null;
          });
        });

        document.querySelectorAll("tr.draggable-row").forEach((row) => {
          row.addEventListener("dragover", (event) => {
            event.preventDefault();
            if (!draggedRow || draggedRow === row || row.parentNode !== draggedRow.parentNode) {
              return;
            }
            const rect = row.getBoundingClientRect();
            const before = event.clientY - rect.top < rect.height / 2;
            row.parentNode.insertBefore(draggedRow, before ? row : row.nextSibling);
          });

          row.addEventListener("drop", (event) => {
            event.preventDefault();
            if (!draggedRow) {
              return;
            }
            const table = row.closest("table");
            const sources = Array.from(table.querySelectorAll("tr.draggable-row")).map(
              (r) => r.dataset.source
            );

            const form = document.createElement("form");
            form.method = "post";
            form.action = "/admin/redirects/reorder";
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = "order";
            input.value = sources.join("||");
            form.appendChild(input);
            const tabInput = document.createElement("input");
            tabInput.type = "hidden";
            tabInput.name = "tab";
            tabInput.value = table.dataset.tab || "";
            form.appendChild(tabInput);
            document.body.appendChild(form);
            form.submit();
          });
        });
      })();
    </script>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Administration", content, { wide: true }));
}

function renderSiteSettings(res, flash, siteConfig, redirects = []) {
  const messages = renderMessages(flash);
  const groupNames = Array.from(new Set(redirects.map((item) => (item.group || "").trim()).filter(Boolean)));
  const orderedGroups = applyGroupOrder(groupNames, siteConfig.groupOrder);

  const groupOrderSection = orderedGroups.length > 1
    ? `
      <section class="card">
        <h2>Ordre des onglets</h2>
        <p>Cet ordre s'applique aux onglets de groupes sur la page d'accueil publique (et dans l'administration).</p>
        <div class="group-order-list">
          ${orderedGroups
            .map(
              (name, index) => `
                <div class="group-order-row" data-group="${escapeHtml(name)}">
                  <span class="drag-handle" draggable="true" title="Glisser pour reordonner">&#8942;&#8942;</span>
                  <form method="post" action="/admin/site/groups/rename" class="group-rename-form">
                    <input type="hidden" name="oldName" value="${escapeHtml(name)}" />
                    <input type="text" name="newName" value="${escapeHtml(name)}" class="group-rename-input" />
                    <button type="submit" class="secondary">Renommer</button>
                  </form>
                  <div class="group-order-actions">
                    <form method="post" action="/admin/site/groups/move">
                      <input type="hidden" name="name" value="${escapeHtml(name)}" />
                      <input type="hidden" name="direction" value="up" />
                      <button type="submit" class="secondary move-button" ${index === 0 ? "disabled" : ""} title="Monter">&uarr;</button>
                    </form>
                    <form method="post" action="/admin/site/groups/move">
                      <input type="hidden" name="name" value="${escapeHtml(name)}" />
                      <input type="hidden" name="direction" value="down" />
                      <button type="submit" class="secondary move-button" ${index === orderedGroups.length - 1 ? "disabled" : ""} title="Descendre">&darr;</button>
                    </form>
                  </div>
                </div>
              `
            )
            .join("")}
        </div>
        <script>
          (function () {
            let draggedRow = null;
            const list = document.querySelector(".group-order-list");
            if (!list) {
              return;
            }

            list.querySelectorAll(".drag-handle").forEach((handle) => {
              handle.addEventListener("dragstart", () => {
                draggedRow = handle.closest(".group-order-row");
                draggedRow.classList.add("dragging");
              });
              handle.addEventListener("dragend", () => {
                if (draggedRow) {
                  draggedRow.classList.remove("dragging");
                }
                draggedRow = null;
              });
            });

            list.querySelectorAll(".group-order-row").forEach((row) => {
              row.addEventListener("dragover", (event) => {
                event.preventDefault();
                if (!draggedRow || draggedRow === row) {
                  return;
                }
                const rect = row.getBoundingClientRect();
                const before = event.clientY - rect.top < rect.height / 2;
                row.parentNode.insertBefore(draggedRow, before ? row : row.nextSibling);
              });

              row.addEventListener("drop", (event) => {
                event.preventDefault();
                if (!draggedRow) {
                  return;
                }
                const names = Array.from(list.querySelectorAll(".group-order-row")).map(
                  (r) => r.dataset.group
                );
                const form = document.createElement("form");
                form.method = "post";
                form.action = "/admin/site/groups/reorder";
                const input = document.createElement("input");
                input.type = "hidden";
                input.name = "order";
                input.value = names.join("||");
                form.appendChild(input);
                document.body.appendChild(form);
                form.submit();
              });
            });
          })();
        </script>
      </section>
    `
    : "";

  const content = `
    <header class="topbar">
      <div>
        <h1>Personnalisation de la page publique</h1>
        <p>Ces reglages controlent le titre, le texte et le logo affiches sur la page d'accueil publique de vos liens.</p>
      </div>
      <div class="topbar-actions">
        <a href="/" class="link-button secondary" target="_blank" rel="noreferrer">Apercu</a>
        <a href="/admin" class="link-button secondary">Redirections</a>
        <a href="/admin/stats" class="link-button secondary">Statistiques</a>
        <a href="/admin/monitoring" class="link-button secondary">Monitoring</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <section class="card">
      <h2>Identite de la page</h2>
      <form method="post" action="/admin/site" class="form-grid">
        <label>
          <span>Logo (URL d'une image, optionnel)</span>
          <input type="text" name="logoUrl" placeholder="https://exemple.com/mon-logo.png" value="${escapeHtml(siteConfig.logoUrl)}" />
        </label>
        <label>
          <span>Favicon du site (URL d'une image, optionnel)</span>
          <input type="text" name="faviconUrl" placeholder="https://exemple.com/favicon.png" value="${escapeHtml(siteConfig.faviconUrl)}" />
        </label>
        <label>
          <span>Petit badge au-dessus du titre</span>
          <input type="text" name="badge" placeholder="Liens officiels" value="${escapeHtml(siteConfig.badge)}" />
        </label>
        <label>
          <span>Titre</span>
          <input type="text" name="title" placeholder="Rooky" value="${escapeHtml(siteConfig.title)}" required />
        </label>
        <label>
          <span>Texte de presentation</span>
          <input type="text" name="tagline" placeholder="Retrouvez ici tous mes liens et comptes officiels." value="${escapeHtml(siteConfig.tagline)}" />
        </label>
        <div class="form-actions">
          <button type="submit">Enregistrer</button>
          <a href="/" class="link-button secondary" target="_blank" rel="noreferrer">Voir la page publique</a>
        </div>
      </form>
    </section>
    ${groupOrderSection}
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Personnalisation", content));
}

function renderStats(res, redirects, flash, activeTab = "") {
  const messages = renderMessages(flash);
  const sorted = [...redirects].sort((a, b) => (b.clicks || 0) - (a.clicks || 0));

  const renderRow = (item, tabLabel) => {
    const resolvedTarget = resolveRedirectTarget(item.target, redirects, new Set([item.source])) || item.target;
    const platform = detectPlatform(item.source, resolvedTarget);
    const label = item.publicLabel || (item.source.startsWith("*.") ? "" : platform.name);

    return `
      <tr>
        <td>${label ? `<strong>${escapeHtml(label)}</strong>` : "—"}</td>
        <td><code>${escapeHtml(item.source)}</code></td>
        <td>${renderTargetCell(item.target)}</td>
        <td class="clicks-cell">${item.clicks || 0}</td>
        <td class="actions-cell">
          <form method="post" action="/admin/stats/reset">
            <input type="hidden" name="source" value="${escapeHtml(item.source)}" />
            <input type="hidden" name="tab" value="${escapeHtml(tabLabel)}" />
            <button type="submit" class="secondary" ${item.clicks ? "" : "disabled"}>Remettre a zero</button>
          </form>
        </td>
      </tr>
    `;
  };

  const renderTable = (items, tabLabel) => `
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Label</th>
            <th>Source</th>
            <th>Cible</th>
            <th>Clics</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>${
          items.length ? items.map((item) => renderRow(item, tabLabel)).join("") : `<tr><td colspan="5">Aucune redirection enregistree.</td></tr>`
        }</tbody>
      </table>
    </div>
  `;

  let tableSection;
  if (!sorted.length) {
    tableSection = renderTable([], "");
  } else {
    const byGroup = new Map();
    const order = [];
    for (const item of sorted) {
      const key = (item.group || "").trim();
      if (!byGroup.has(key)) {
        byGroup.set(key, []);
        order.push(key);
      }
      byGroup.get(key).push(item);
    }

    if (order.length <= 1) {
      tableSection = renderTable(sorted, "");
    } else {
      const orderedKeys = applyGroupOrder(order, getSiteConfig().groupOrder);
      const tabs = [
        { label: "Tous", content: renderTable(sorted, "Tous") },
        ...orderedKeys.map((key) => {
          const label = key ? key : "Sans groupe";
          return { label, content: renderTable(byGroup.get(key), label) };
        })
      ];
      tableSection = renderCssTabs(tabs, "stats-tab", activeTab || "Tous");
    }
  }

  const content = `
    <header class="topbar">
      <div>
        <h1>Statistiques</h1>
        <p>Nombre de fois ou chaque lien a effectivement redirige un visiteur, depuis la derniere remise a zero.</p>
      </div>
      <div class="topbar-actions">
        <a href="/" class="link-button secondary" target="_blank" rel="noreferrer">Apercu</a>
        <a href="/admin" class="link-button secondary">Redirections</a>
        <a href="/admin/site" class="link-button secondary">Personnalisation</a>
        <a href="/admin/monitoring" class="link-button secondary">Monitoring</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <section class="card">${tableSection}</section>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Statistiques", content, { wide: true }));
}

function renderMonitoring(res, config, flash) {
  const messages = renderMessages(flash);

  const rows = config.bots.length
    ? config.bots
        .map((bot) => {
          const statusClass =
            bot.status === "en ligne" ? "status-ok" : bot.status === "hors ligne" ? "status-missing" : "";
          const lastChecked = bot.lastCheckedAt
            ? new Date(bot.lastCheckedAt).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Paris" })
            : "Jamais verifie";

          return `
            <tr>
              <td><strong>${escapeHtml(bot.name || bot.botUsername || bot.botId)}</strong></td>
              <td><code>${escapeHtml(bot.guildId)}</code></td>
              <td><code>${escapeHtml(bot.botId || bot.botUsername || "")}</code></td>
              <td class="${statusClass}">${escapeHtml(bot.status || "inconnu")}</td>
              <td>${escapeHtml(lastChecked)}${bot.lastError ? `<br /><span class="status-missing">${escapeHtml(bot.lastError)}</span>` : ""}</td>
              <td class="actions-cell">
                <form method="post" action="/admin/monitoring/bots/check">
                  <input type="hidden" name="id" value="${escapeHtml(bot.id)}" />
                  <button type="submit" class="secondary">Verifier</button>
                </form>
                <form method="post" action="/admin/monitoring/bots/delete">
                  <input type="hidden" name="id" value="${escapeHtml(bot.id)}" />
                  <button type="submit" class="danger">Retirer</button>
                </form>
              </td>
            </tr>
          `;
        })
        .join("")
    : `<tr><td colspan="6">Aucun bot surveille pour le moment.</td></tr>`;

  const content = `
    <header class="topbar">
      <div>
        <h1>Monitoring</h1>
        <p>Surveille si vos bots Discord sont en ligne, via le widget public de leur serveur (aucun token requis). Verification automatique toutes les minutes.</p>
      </div>
      <div class="topbar-actions">
        <a href="/admin" class="link-button secondary">Redirections</a>
        <a href="/admin/stats" class="link-button secondary">Statistiques</a>
        <a href="/admin/site" class="link-button secondary">Personnalisation</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <section class="card">
      <h2>Notification Discord</h2>
      <form method="post" action="/admin/monitoring" class="form-grid">
        <label>
          <span>URL du webhook Discord (salon ou envoyer les alertes)</span>
          <input type="text" name="webhookUrl" placeholder="https://discord.com/api/webhooks/..." value="${escapeHtml(config.webhookUrl)}" />
        </label>
        <div class="form-actions">
          <button type="submit">Enregistrer</button>
        </div>
      </form>
    </section>
    <details class="card add-redirect">
      <summary class="add-redirect-summary">Ajouter un bot a surveiller</summary>
      <form method="post" action="/admin/monitoring/bots" class="form-grid">
        <label>
          <span>Nom (optionnel)</span>
          <input type="text" name="name" placeholder="Ex: MonBot" />
        </label>
        <label>
          <span>ID du serveur Discord (widget doit etre active)</span>
          <input type="text" name="guildId" placeholder="123456789012345678" required />
        </label>
        <label>
          <span>ID du bot (optionnel si vous renseignez le nom d'utilisateur)</span>
          <input type="text" name="botId" placeholder="123456789012345678" />
        </label>
        <label>
          <span>Nom d'utilisateur du bot (optionnel si vous renseignez l'ID)</span>
          <input type="text" name="botUsername" placeholder="Ex: MonBot" />
        </label>
        <p>Le widget du serveur doit etre active dans Discord (Parametres du serveur -&gt; Widget) pour que la verification fonctionne.</p>
        <p>Sur les gros serveurs, Discord anonymise parfois les ID dans le widget public : renseignez aussi le nom d'utilisateur du bot pour fiabiliser la detection.</p>
        <div class="form-actions">
          <button type="submit">Ajouter</button>
        </div>
      </form>
    </details>
    <section class="card">
      <h2>Bots surveilles</h2>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Nom</th>
              <th>Serveur</th>
              <th>Bot</th>
              <th>Statut</th>
              <th>Derniere verification</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Monitoring", content, { wide: true }));
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
  },
  {
    name: "Steam",
    color: "#171a21",
    hosts: ["store.steampowered.com", "steamcommunity.com"],
    keyword: "steam",
    icon:
      '<svg viewBox="0 0 24 24" fill="white"><path d="M12 2a10 10 0 0 0-10 9.7l5.4 2.2a2.8 2.8 0 0 1 1.6-.5l2.4-3.5v-.1a3.6 3.6 0 1 1 3.6 3.6h-.1l-3.4 2.4a2.8 2.8 0 0 1-5.5.7l-3.9-1.6A10 10 0 1 0 12 2zm-2.4 15.3-1.2-.5a2.1 2.1 0 0 0 3.9-.4l-1.1-.5a1.2 1.2 0 0 1-1.6 1.4zm6.7-6.9a2.4 2.4 0 1 0 0-4.8 2.4 2.4 0 0 0 0 4.8zm0-.9a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3z"/></svg>'
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

function isPubliclyVisible(item) {
  return Boolean(item.public) && !item.source.startsWith("*.");
}

function buildPublicLinks(redirects) {
  return redirects
    .filter(isPubliclyVisible)
    .map((item) => {
      const resolvedTarget = resolveRedirectTarget(item.target, redirects, new Set([item.source])) || item.target;
      const platform = detectPlatform(item.source, resolvedTarget);
      let targetHostname = "";
      try {
        targetHostname = new URL(resolvedTarget).hostname;
      } catch {
        targetHostname = "";
      }

      return {
        href: `/go?to=${encodeURIComponent(item.source)}`,
        label: item.publicLabel || platform.name,
        group: (item.group || "").trim(),
        platform,
        targetHostname,
        customImageUrl: item.customImageUrl || "",
        spotifyTitle: item.spotifyTitle || "",
        spotifyImage: item.spotifyImage || "",
        steamTitle: item.steamTitle || "",
        steamImage: item.steamImage || ""
      };
    });
}

function applyGroupOrder(items, groupOrder, keyOf = (item) => item) {
  if (!groupOrder || !groupOrder.length) {
    return items;
  }
  const remaining = [...items];
  const ordered = [];
  for (const name of groupOrder) {
    const index = remaining.findIndex((item) => keyOf(item) === name);
    if (index !== -1) {
      ordered.push(remaining.splice(index, 1)[0]);
    }
  }
  return [...ordered, ...remaining];
}

function groupPublicLinks(publicLinks) {
  const groups = [];
  const byKey = new Map();

  for (const link of publicLinks) {
    const key = link.group || "_ungrouped";
    let entry = byKey.get(key);
    if (!entry) {
      entry = { label: link.group || "Autres", links: [] };
      byKey.set(key, entry);
      groups.push(entry);
    }
    entry.links.push(link);
  }

  return groups;
}

function renderLinkRow(link) {
  const isUnknownPlatform = link.platform === DEFAULT_PLATFORM;
  const autoFaviconUrl =
    isUnknownPlatform && link.targetHostname
      ? `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(link.targetHostname)}`
      : "";
  const overrideImageUrl = link.customImageUrl || autoFaviconUrl;

  const iconContent = overrideImageUrl
    ? `
        <span class="fallback-icon">${link.platform.icon}</span>
        <img class="favicon-img" src="${escapeHtml(overrideImageUrl)}" alt="" onerror="this.remove()" />
      `
    : link.platform.icon;

  const header = `
    <span class="link-row-main">
      <span class="link-row-icon" style="background:${link.platform.gradient || link.platform.color}">
        ${iconContent}
      </span>
      <span class="link-row-label">${escapeHtml(link.label)}</span>
      <span class="link-row-arrow" aria-hidden="true">&rsaquo;</span>
    </span>
  `;

  if (link.platform.name === "Spotify" && link.spotifyTitle) {
    const cover = link.customImageUrl || link.spotifyImage;
    return `
      <a class="link-row spotify-card" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">
        <span class="spotify-preview">
          ${cover ? `<img class="spotify-cover" src="${escapeHtml(cover)}" alt="" />` : ""}
          <span class="spotify-text">
            <span class="spotify-track-title">${escapeHtml(link.spotifyTitle)}</span>
            <span class="spotify-subtitle">Ecouter sur Spotify</span>
          </span>
        </span>
      </a>
    `;
  }

  if (link.platform.name === "Steam" && link.steamTitle) {
    const banner = link.customImageUrl || link.steamImage;
    return `
      <a class="link-row steam-card" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">
        ${banner ? `<img class="steam-cover" src="${escapeHtml(banner)}" alt="" />` : ""}
        <span class="steam-text">
          <span class="steam-title">${escapeHtml(link.steamTitle)}</span>
          <span class="steam-subtitle">Voir sur Steam</span>
        </span>
      </a>
    `;
  }

  return `
    <a class="link-row" href="${escapeHtml(link.href)}" target="_blank" rel="noreferrer">
      ${header}
    </a>
  `;
}

function renderCssTabs(tabs, idPrefix, activeLabel = "") {
  if (tabs.length <= 1) {
    return tabs.length ? tabs[0].content : "";
  }

  const activeIndex = Math.max(
    0,
    tabs.findIndex((tab) => tab.label === activeLabel)
  );

  const inputs = tabs
    .map(
      (tab, index) =>
        `<input type="radio" name="${idPrefix}-group" id="${idPrefix}-${index}" class="tab-input" ${index === activeIndex ? "checked" : ""} />`
    )
    .join("");
  const labels = tabs
    .map((tab, index) => `<label for="${idPrefix}-${index}" class="tab-label">${escapeHtml(tab.label)}</label>`)
    .join("");
  const panels = tabs
    .map((tab, index) => `<div class="tab-panel" id="${idPrefix}-panel-${index}">${tab.content}</div>`)
    .join("");
  const visibilityRules = tabs
    .map(
      (tab, index) => `
        #${idPrefix}-${index}:checked ~ .tab-panels #${idPrefix}-panel-${index} { display: block; }
        #${idPrefix}-${index}:checked ~ .tab-labels label[for="${idPrefix}-${index}"] { background: var(--accent); color: #fff; }
      `
    )
    .join("");

  return `
    <div class="tabs">
      ${inputs}
      <div class="tab-labels">${labels}</div>
      <div class="tab-panels">${panels}</div>
      <style>${visibilityRules}</style>
    </div>
  `;
}

function renderLinksSection(publicLinks) {
  if (!publicLinks.length) {
    return "";
  }

  const rawGroups = groupPublicLinks(publicLinks);
  if (rawGroups.length <= 1) {
    return `<div class="links-list">${publicLinks.map(renderLinkRow).join("")}</div>`;
  }

  const groups = applyGroupOrder(rawGroups, getSiteConfig().groupOrder, (group) => group.label);

  const tabs = groups.map((tab) => ({
    label: tab.label,
    content: `<div class="links-list">${tab.links.map(renderLinkRow).join("")}</div>`
  }));

  return renderCssTabs(tabs, "home-tab");
}

function renderHome(res, redirects) {
  const siteConfig = getSiteConfig();
  const publicLinks = buildPublicLinks(redirects);
  const linksList = renderLinksSection(publicLinks);
  const logoMarkup = siteConfig.logoUrl
    ? `<img class="profile-logo" src="${escapeHtml(siteConfig.logoUrl)}" alt="" />`
    : "";
  const content = `
    <section class="profile-card">
      <div class="hero-glow" aria-hidden="true"></div>
      ${logoMarkup}
      <span class="hero-badge">${escapeHtml(siteConfig.badge)}</span>
      <h1>${escapeHtml(siteConfig.title)}</h1>
      <p>${escapeHtml(siteConfig.tagline)}</p>
      ${linksList}
    </section>
    <footer class="site-footer">
      <a href="/admin" class="footer-link">Administration</a>
    </footer>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage(`${siteConfig.title} - Mes liens officiels`, content));
}

function renderNotFound(res, requestHost, pathname) {
  const requestedSource = formatSource(requestHost, pathname);
  res.writeHead(404, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
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

function renderPage(title, content, { wide = false } = {}) {
  const faviconUrl = getSiteConfig().faviconUrl;
  return `<!doctype html>
  <html lang="fr">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${escapeHtml(title)}</title>
      ${faviconUrl ? `<link rel="icon" href="${escapeHtml(faviconUrl)}" />` : ""}
      <style>
        :root {
          --bg: #0b0d12;
          --panel: #161922;
          --ink: #eef0f5;
          --muted: #939aad;
          --line: #262b38;
          --accent: #6d5ef7;
          --accent-dark: #5a4bd6;
          --danger: #f0555f;
          --success: #3ddc84;
        }
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          color: var(--ink);
          background:
            radial-gradient(circle at top left, rgba(109, 94, 247, 0.18) 0, transparent 32%),
            radial-gradient(circle at bottom right, rgba(61, 220, 132, 0.08) 0, transparent 40%),
            linear-gradient(160deg, #0b0d12 0%, #0d1017 55%, #0f1219 100%);
          min-height: 100vh;
        }
        .shell {
          width: min(980px, calc(100% - 32px));
          margin: 40px auto;
        }
        .shell-wide {
          width: min(1400px, calc(100% - 48px));
        }
        .card {
          background: rgba(22, 25, 34, 0.9);
          border: 1px solid var(--line);
          border-radius: 18px;
          padding: 24px;
          box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
          margin-bottom: 20px;
        }
        .auth-card {
          max-width: 460px;
          margin: 80px auto;
        }
        .back-home-link {
          display: block;
          width: fit-content;
          margin: 18px auto 0;
          background: transparent;
          color: var(--muted);
          font-size: 13px;
          padding: 4px 8px;
        }
        .back-home-link:hover {
          background: transparent;
          color: var(--accent);
          text-decoration: underline;
        }
        .profile-card {
          position: relative;
          overflow: hidden;
          max-width: 480px;
          margin: 90px auto 24px;
          padding: 44px 36px;
          text-align: center;
          background: rgba(22, 25, 34, 0.92);
          border: 1px solid var(--line);
          border-radius: 28px;
          box-shadow: 0 24px 50px rgba(0, 0, 0, 0.45);
          animation: hero-rise 0.6s ease-out;
        }
        .hero-glow {
          position: absolute;
          inset: -60% -40% auto -40%;
          height: 260px;
          background: radial-gradient(circle, rgba(109, 94, 247, 0.35), transparent 70%);
          filter: blur(10px);
          animation: hero-glow-move 8s ease-in-out infinite;
          pointer-events: none;
        }
        .profile-logo {
          position: relative;
          display: block;
          width: 84px;
          height: 84px;
          margin: 0 auto 16px;
          border-radius: 50%;
          object-fit: cover;
          border: 3px solid var(--line);
          box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
        }
        .hero-badge {
          position: relative;
          display: inline-block;
          padding: 6px 14px;
          border-radius: 999px;
          background: rgba(109, 94, 247, 0.16);
          color: #b6acff;
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
          flex-direction: column;
          gap: 10px;
          padding: 12px 16px;
          border-radius: 16px;
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid var(--line);
          text-decoration: none;
          color: var(--ink);
          transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease, background 0.15s ease;
        }
        .link-row-main {
          display: flex;
          align-items: center;
          gap: 14px;
        }
        .spotify-preview {
          display: flex;
          align-items: center;
          gap: 16px;
          padding: 6px;
          border-radius: 12px;
          background: linear-gradient(135deg, rgba(29, 185, 84, 0.1), rgba(29, 185, 84, 0.02));
        }
        .spotify-cover {
          flex: 0 0 auto;
          width: 64px;
          height: 64px;
          border-radius: 10px;
          object-fit: cover;
          box-shadow: 0 6px 16px rgba(0, 0, 0, 0.18);
          transition: transform 0.2s ease;
        }
        .link-row:hover .spotify-cover {
          transform: scale(1.05);
        }
        .spotify-text {
          display: flex;
          flex: 1;
          flex-direction: column;
          gap: 2px;
          min-width: 0;
        }
        .spotify-track-title {
          font-size: 16px;
          font-weight: 700;
          color: var(--ink);
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .spotify-subtitle {
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.02em;
          color: #1db954;
        }
        .steam-cover {
          width: 100%;
          aspect-ratio: 460 / 215;
          border-radius: 10px;
          object-fit: cover;
          box-shadow: 0 6px 16px rgba(0, 0, 0, 0.18);
          transition: transform 0.2s ease;
        }
        .link-row:hover .steam-cover {
          transform: scale(1.02);
        }
        .steam-text {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        .steam-title {
          font-size: 16px;
          font-weight: 700;
          color: var(--ink);
        }
        .steam-subtitle {
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.02em;
          color: #66c0f4;
        }
        .link-row:hover {
          transform: translateY(-2px) scale(1.01);
          box-shadow: 0 12px 24px rgba(0, 0, 0, 0.3);
          border-color: var(--accent);
          background: rgba(255, 255, 255, 0.05);
        }
        .link-row-icon {
          position: relative;
          flex: 0 0 auto;
          width: 38px;
          height: 38px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          overflow: hidden;
        }
        .favicon-img {
          position: absolute;
          inset: 0;
          margin: auto;
          width: 20px;
          height: 20px;
          border-radius: 4px;
          object-fit: cover;
          background: #fff;
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
        .tabs {
          position: relative;
          margin-top: 28px;
        }
        .tab-input {
          position: absolute;
          opacity: 0;
          width: 0;
          height: 0;
          pointer-events: none;
        }
        .tab-labels {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          justify-content: center;
          margin-bottom: 18px;
        }
        .tab-label {
          padding: 6px 14px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.06);
          color: var(--muted);
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.15s ease, color 0.15s ease;
        }
        .tab-panel {
          display: none;
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
        .topbar-actions {
          display: flex;
          gap: 10px;
          align-items: center;
          flex-wrap: wrap;
        }
        .section-title {
          margin: 8px 4px 12px;
        }
        .group-card h3 {
          margin-bottom: 14px;
          padding-bottom: 10px;
          border-bottom: 1px solid var(--line);
          color: var(--accent);
        }
        .add-redirect-summary {
          cursor: pointer;
          font-size: 1.1rem;
          font-weight: 700;
          color: var(--accent);
          list-style: none;
        }
        .add-redirect-summary::-webkit-details-marker {
          display: none;
        }
        .add-redirect-summary::before {
          content: "+";
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 22px;
          height: 22px;
          margin-right: 8px;
          border-radius: 50%;
          background: var(--accent);
          color: #fff;
          font-size: 16px;
          transition: transform 0.15s ease;
        }
        .add-redirect[open] .add-redirect-summary::before {
          content: "\\2212";
        }
        .add-redirect .form-grid {
          margin-top: 20px;
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
        .switch {
          position: relative;
          display: inline-flex;
          align-items: center;
          flex: 0 0 auto;
        }
        .switch input {
          position: absolute;
          opacity: 0;
          width: 44px;
          height: 24px;
          margin: 0;
          cursor: pointer;
        }
        .switch-track {
          width: 44px;
          height: 24px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.15);
          position: relative;
          transition: background 0.2s ease;
          pointer-events: none;
        }
        .switch-thumb {
          position: absolute;
          top: 2px;
          left: 2px;
          width: 20px;
          height: 20px;
          border-radius: 50%;
          background: #fff;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
          transition: transform 0.2s ease;
        }
        .switch input:checked + .switch-track {
          background: var(--accent);
        }
        .switch input:checked + .switch-track .switch-thumb {
          transform: translateX(20px);
        }
        .switch input:focus-visible + .switch-track {
          box-shadow: 0 0 0 3px rgba(109, 94, 247, 0.35);
        }
        input, button, .link-button {
          border-radius: 12px;
          font: inherit;
        }
        input, select {
          width: 100%;
          padding: 12px 14px;
          border: 1px solid var(--line);
          background: rgba(255, 255, 255, 0.04);
          color: var(--ink);
        }
        select option {
          background: var(--panel);
          color: var(--ink);
        }
        input:focus, select:focus {
          outline: none;
          border-color: var(--accent);
          box-shadow: 0 0 0 3px rgba(109, 94, 247, 0.25);
        }
        input[type="checkbox"], input[type="radio"] {
          accent-color: var(--accent);
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
          background: rgba(255, 255, 255, 0.08);
          color: var(--ink);
        }
        .secondary:hover {
          background: rgba(255, 255, 255, 0.14);
        }
        .form-actions,
        .actions-cell {
          display: flex;
          gap: 10px;
          align-items: center;
          flex-wrap: nowrap;
          white-space: nowrap;
        }
        .actions-cell form {
          margin: 0;
        }
        .move-button {
          padding: 8px 12px;
          min-width: 36px;
        }
        .clicks-cell {
          font-weight: 700;
          font-variant-numeric: tabular-nums;
        }
        .status-ok {
          color: var(--success);
          font-weight: 700;
        }
        .status-missing {
          color: var(--danger);
          font-weight: 700;
        }
        .drag-handle {
          width: 20px;
          cursor: grab;
          color: var(--muted);
          letter-spacing: -2px;
          user-select: none;
        }
        .draggable-row.dragging {
          opacity: 0.4;
        }
        .group-order-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .group-order-row {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 14px;
          border: 1px solid var(--line);
          border-radius: 12px;
          background: rgba(255, 255, 255, 0.03);
        }
        .group-order-row.dragging {
          opacity: 0.4;
        }
        .group-order-label {
          flex: 1;
          font-weight: 600;
        }
        .group-rename-form {
          display: flex;
          flex: 1;
          gap: 8px;
          align-items: center;
        }
        .group-rename-input {
          flex: 1;
          font-weight: 600;
        }
        .group-order-actions {
          display: flex;
          gap: 8px;
        }
        .move-button[disabled] {
          opacity: 0.35;
          cursor: not-allowed;
        }
        .message {
          padding: 12px 14px;
          border-radius: 12px;
          margin-bottom: 16px;
        }
        .message.error {
          background: rgba(240, 85, 95, 0.15);
          color: #ffb3b9;
        }
        .message.success {
          background: rgba(61, 220, 132, 0.15);
          color: #8ff0b8;
        }
        .table-scroll {
          overflow-x: auto;
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
          background: rgba(255, 255, 255, 0.08);
          color: var(--ink);
          padding: 2px 6px;
          border-radius: 6px;
        }
        a {
          color: #a89bff;
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
      <main class="shell${wide ? " shell-wide" : ""}">${content}</main>
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
