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
const PLANNING_DIR = path.join(STORAGE_DIR, "planning");
// Espace modo : modos deja connectes par « Acces modo » et groupes locaux de visibilite des tickets.
const MODO_USERS_FILE = path.join(STORAGE_DIR, "modo-users.json");
const MODO_GROUPS_FILE = path.join(STORAGE_DIR, "modo-groups.json");

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
      clearCookie(res, "modo");
      redirect(res, "/login");
      return;
    }

    if (pathname === "/planning" && method === "GET") {
      return renderPublicPlanning(res, readPlanning(planningSiteChannel()));
    }

    // Espace modo : connexion par rooky-tv (bot relie), le mot de passe admin reste possible.
    if (pathname === "/modo/login" && method === "GET") {
      const doc = readPlanning(planningSiteChannel());
      if (!doc.channel || !doc.syncKey || !doc.program?.modoUrl) {
        redirect(res, "/login?error=" + encodeURIComponent("Acces modo indisponible : ce site n'est pas encore relie a rooky-tv."));
        return;
      }
      const state = crypto.randomBytes(18).toString("base64url");
      setCookie(res, "modo_state", state, { httpOnly: true, secure: useSecureCookies, maxAge: 600 });
      const target = new URL(doc.program.modoUrl);
      target.searchParams.set("channel", doc.channel);
      target.searchParams.set("site", modoSiteId(doc.syncKey));
      target.searchParams.set("state", state);
      redirect(res, target.toString());
      return;
    }

    if (pathname === "/modo/callback" && method === "GET") {
      const doc = readPlanning(planningSiteChannel());
      const state = parseCookies(req.headers.cookie || "").modo_state || "";
      const claims = verifyModoToken(doc, url.searchParams.get("token") || "", state);
      if (!claims) {
        redirect(res, "/login?error=" + encodeURIComponent("Connexion modo refusee ou expiree : reclique sur Acces modo."));
        return;
      }
      rememberModoUser(claims);
      setCookie(res, "modo", signModoSession({ u: claims.u, n: claims.n, r: claims.r, a: claims.a === true, k: claims.k, c: doc.channel, e: Date.now() + MODO_SESSION_MS }), {
        httpOnly: true,
        secure: useSecureCookies,
        maxAge: Math.round(MODO_SESSION_MS / 1000)
      });
      redirect(res, "/modo");
      return;
    }

    if (pathname === "/modo/logout") {
      clearCookie(res, "modo");
      redirect(res, "/planning");
      return;
    }

    if (pathname === "/modo" || pathname.startsWith("/modo/")) {
      const doc = readPlanning(planningSiteChannel());
      const session = readModoSession(req, doc.channel);
      const fullRights = { stream: "edit", montage: "edit", post: "edit", autre: "edit", tickets: "edit" };
      const viewer = session?.a === true
        ? { ...session, admin: true, k: fullRights }
        : isAuthenticated(req)
          ? { n: "Admin", r: "admin", admin: true, password: true, k: fullRights }
          : session;
      if (!viewer) {
        redirect(res, "/login");
        return;
      }
      const flash = getFlashMessage(url);
      // Admin de rooky-tv : chaine des tickets choisie (cookie), verifiee par rooky-tv.
      if (viewer.admin && viewer.u) {
        const asked = url.searchParams.get("chaine");
        if (asked !== null) {
          const value = /^[a-z0-9_]{1,25}$/.test(asked) ? asked : "";
          setCookie(res, "modo_chaine", value, { httpOnly: true, secure: useSecureCookies, maxAge: value ? MODO_SESSION_MS / 1000 : 1 });
          viewer.ticketChannel = value;
        } else {
          viewer.ticketChannel = parseCookies(req.headers.cookie || "").modo_chaine || "";
        }
      }
      const overview = async () => filterModoLive(await modoApi(doc, viewer, "overview").catch((error) => ({ error: error.message })), viewer, doc);

      if (pathname === "/modo" && method === "GET") {
        const live = await overview();
        return renderModoPlanning(res, doc, viewer, live, flash);
      }

      // Ajout d'une tache (droit "Modifie" sur l'activite) ou suggestion au streamer.
      if (pathname === "/modo/action" && method === "POST") {
        const form = await parseForm(req);
        const action = form.action === "suggest" ? "suggest" : "task.create";
        try {
          await modoApi(doc, viewer, action, { kind: form.kind, title: form.title, date: form.date, time: form.time, notes: form.notes });
          redirect(res, `/modo?success=${encodeURIComponent(action === "suggest" ? "Suggestion envoyee au streamer en MP" : "Ajoute au planning")}`);
        } catch (error) {
          redirect(res, `/modo?error=${encodeURIComponent(error.message)}`);
        }
        return;
      }

      const suggestionMatch = /^\/modo\/suggestions\/(\d{1,12})$/.exec(pathname);
      if (suggestionMatch && method === "POST") {
        const form = await parseForm(req);
        try {
          const result = await modoApi(doc, viewer, "suggestion.decide", { id: Number(suggestionMatch[1]), decision: form.decision === "accept" ? "accept" : "refuse" });
          redirect(res, `/modo?success=${encodeURIComponent(result.text || "Decision enregistree")}`);
        } catch (error) {
          redirect(res, `/modo?error=${encodeURIComponent(error.message)}`);
        }
        return;
      }

      if (pathname === "/modo/tickets" && method === "GET") {
        const live = await overview();
        if (live.rookyAdmin) live.channels = (await modoApi(doc, viewer, "tickets.meta").catch(() => ({}))).channels || null;
        return renderModoTickets(res, doc, viewer, live, flash, url.searchParams.get("vue") || "");
      }

      const ticketMatch = /^\/modo\/tickets\/(\d{1,12})$/.exec(pathname);
      if (ticketMatch && method === "GET") {
        const id = Number(ticketMatch[1]);
        const [live, fetched] = await Promise.all([
          overview(),
          modoApi(doc, viewer, "ticket.get", { id }).catch((error) => ({ error: error.message }))
        ]);
        // Categorie reservee a un groupe local dont la personne n'est pas membre : introuvable.
        const data = fetched.ticket && !canSeeTicket(viewer, fetched, fetched.ticket, doc) ? { error: "Ticket introuvable." } : fetched;
        if (live.rookyAdmin) live.channels = (await modoApi(doc, viewer, "tickets.meta").catch(() => ({}))).channels || null;
        return renderModoTicket(res, doc, viewer, live, data, flash, url.searchParams.get("vue") || "");
      }

      if (ticketMatch && method === "POST") {
        const id = Number(ticketMatch[1]);
        const params = await parseFormParams(req);
        const form = Object.fromEntries(params.entries());
        const back = `/modo/tickets/${id}`;
        try {
          // Meme regle de visibilite que l'affichage, avant toute action.
          const current = await modoApi(doc, viewer, "ticket.get", { id });
          if (!current.ticket || !canSeeTicket(viewer, current, current.ticket, doc)) throw new Error("Ticket introuvable.");
          if (form.action === "propose") {
            // Creneaux proposes a l'invite : streams coches de la semaine (+ fin), et/ou une autre date.
            const streams = params.getAll("stream").map((key) => ({ key, end: params.get(`end_${key}`) || "" }));
            const custom = form.custom_date && form.custom_time ? { date: form.custom_date, time: form.custom_time, end: form.custom_end || "" } : null;
            await modoApi(doc, viewer, "ticket.propose", { id, streams, custom });
            redirect(res, `${back}?success=${encodeURIComponent("Creneaux envoyes en MP a l'invite")}`);
            return;
          }
          if (form.action === "offer_accept" || form.action === "offer_refuse") {
            await modoApi(doc, viewer, "ticket.offer.decide", { id, decision: form.action === "offer_accept" ? "accept" : "refuse" });
            redirect(res, `${back}?success=${encodeURIComponent(form.action === "offer_accept" ? "Creneau valide : programme modifie, l'invite est prevenu en MP" : "Creneau refuse, l'invite est prevenu")}`);
            return;
          }
          if (form.action === "reply") {
            await modoApi(doc, viewer, "ticket.reply", { id, content: form.content });
            redirect(res, `${back}?success=${encodeURIComponent("Reponse envoyee en MP")}`);
          } else if (form.action === "ban") {
            // Ban tickets : inscrit au casier du membre par rooky-tv (meme source que les salons ticket).
            await modoApi(doc, viewer, "ticket.ban", { id, reason: form.reason, duration: form.duration });
            redirect(res, `${back}?success=${encodeURIComponent("Ban tickets inscrit au casier, ticket ferme")}`);
          } else {
            await modoApi(doc, viewer, "ticket.status", { id, status: form.action === "reopen" ? "open" : "closed" });
            redirect(res, `${back}?success=${encodeURIComponent(form.action === "reopen" ? "Ticket rouvert" : "Ticket ferme")}`);
          }
        } catch (error) {
          redirect(res, `${back}?error=${encodeURIComponent(error.message)}`);
        }
        return;
      }

      renderNotFound(res, requestHost, pathname);
      return;
    }

    if (pathname === "/api/planning/sync" && method === "POST") {
      return handlePlanningSync(req, res);
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

    if (pathname === "/admin/monitoring/webhooks" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const name = (form.name || "").trim();
      const url = (form.url || "").trim();

      if (!url || !parseAbsoluteTarget(url)) {
        redirect(res, "/admin/monitoring?error=URL%20de%20webhook%20invalide");
        return;
      }

      const testResult = await sendDiscordEmbed(url, {
        title: "Test de notification",
        description: "Si vous voyez ce message, ce webhook est correctement configure.",
        color: 0x6d5ef7,
        timestamp: new Date().toISOString()
      });

      if (!testResult.ok) {
        console.error(`[monitoring] echec du message de test: ${testResult.status || ""} ${testResult.error || ""}`);
        redirect(
          res,
          `/admin/monitoring?error=${encodeURIComponent(
            `Le message de test a echoue (${testResult.status || testResult.error || "erreur inconnue"}), webhook non enregistre.`
          )}`
        );
        return;
      }

      const config = readMonitorConfig();
      config.webhooks.push({
        id: crypto.randomBytes(4).toString("hex"),
        name: name || "Sans nom",
        url,
        isPrimary: config.webhooks.length === 0
      });
      writeMonitorConfig(config);
      redirect(res, "/admin/monitoring?success=Webhook%20enregistre%20et%20message%20de%20test%20envoye");
      return;
    }

    if (pathname === "/admin/monitoring/webhooks/delete" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const config = readMonitorConfig();
      const wasPrimary = config.webhooks.find((w) => w.id === id)?.isPrimary;
      config.webhooks = config.webhooks.filter((w) => w.id !== id);
      if (wasPrimary && config.webhooks.length) {
        config.webhooks[0].isPrimary = true;
      }
      for (const bot of config.bots) {
        if (bot.webhookId === id) {
          bot.webhookId = "";
        }
      }
      writeMonitorConfig(config);
      redirect(res, "/admin/monitoring?success=Webhook%20retire");
      return;
    }

    if (pathname === "/admin/monitoring/webhooks/primary" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const config = readMonitorConfig();
      for (const webhook of config.webhooks) {
        webhook.isPrimary = webhook.id === id;
      }
      writeMonitorConfig(config);
      redirect(res, "/admin/monitoring?success=Webhook%20principal%20mis%20a%20jour");
      return;
    }

    if (pathname === "/admin/monitoring/maintenance" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const config = readMonitorConfig();
      const webhook = getPrimaryWebhook(config);
      if (!webhook) {
        redirect(res, "/admin/monitoring?error=Aucun%20webhook%20principal%20configure");
        return;
      }

      const sendResult = await sendDiscordEmbed(webhook.url, {
        title: "Maintenance en cours",
        description: "Le serveur est actuellement en maintenance.",
        color: 0xfee75c,
        timestamp: new Date().toISOString()
      });

      redirect(
        res,
        sendResult.ok
          ? "/admin/monitoring?success=Annonce%20de%20maintenance%20envoyee"
          : `/admin/monitoring?error=${encodeURIComponent(`Echec de l'envoi (${sendResult.status || sendResult.error || "erreur"})`)}`
      );
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
      const webhookId = (form.webhookId || "").trim();

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
        webhookId,
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

    if (pathname === "/admin/monitoring/bots/webhook" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const webhookId = (form.webhookId || "").trim();
      const config = readMonitorConfig();
      const bot = config.bots.find((entry) => entry.id === id);
      if (bot) {
        bot.webhookId = webhookId;
        writeMonitorConfig(config);
      }
      redirect(res, "/admin/monitoring?success=Webhook%20du%20bot%20mis%20a%20jour");
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

    if (pathname === "/admin/monitoring/bots/maintenance" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const id = (form.id || "").trim();
      const config = readMonitorConfig();
      const bot = config.bots.find((entry) => entry.id === id);

      if (!bot) {
        redirect(res, "/admin/monitoring?error=Bot%20introuvable");
        return;
      }

      const webhook = getBotWebhook(config, bot);
      if (!webhook) {
        redirect(res, "/admin/monitoring?error=Aucun%20webhook%20configure%20pour%20ce%20bot");
        return;
      }

      const label = bot.name || bot.botUsername || bot.botId;
      const sendResult = await sendDiscordEmbed(webhook.url, {
        title: label,
        description: "Ce bot est actuellement en maintenance.",
        color: 0xfee75c,
        timestamp: new Date().toISOString()
      });

      redirect(
        res,
        sendResult.ok
          ? "/admin/monitoring?success=Annonce%20de%20maintenance%20envoyee"
          : `/admin/monitoring?error=${encodeURIComponent(`Echec de l'envoi (${sendResult.status || sendResult.error || "erreur"})`)}`
      );
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

    // Tickets : groupes locaux (qui voit quelle categorie) et chaine des tickets pour les admins.
    if (pathname === "/admin/tickets" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }
      const doc = readPlanning(planningSiteChannel());
      const viewer = adminViewer(req, doc);
      const meta = await modoApi(doc, viewer, "tickets.meta").catch((error) => ({ error: error.message }));
      return renderAdminTickets(res, doc, viewer, meta, getFlashMessage(url));
    }

    if (pathname === "/admin/tickets" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }
      const params = await parseFormParams(req);
      const action = params.get("action") || "";
      const groups = readModoGroups();
      const back = (key, message) => redirect(res, `/admin/tickets?${key}=${encodeURIComponent(message)}`);
      if (action === "add") {
        const name = String(params.get("name") || "").trim().slice(0, 40);
        if (!name) return back("error", "Donne un nom au groupe.");
        if (groups.length >= 30) return back("error", "30 groupes maximum.");
        groups.push({ id: crypto.randomBytes(5).toString("hex"), name, reasons: [], members: [], roles: [] });
        writeModoGroups(groups);
        return back("success", `Groupe « ${name} » cree : coche ses categories et ses membres.`);
      }
      const group = groups.find((g) => g.id === params.get("id"));
      if (!group) return back("error", "Groupe introuvable.");
      if (action === "delete") {
        writeModoGroups(groups.filter((g) => g !== group));
        return back("success", `Groupe « ${group.name} » supprime : ses categories redeviennent visibles par tous les modos.`);
      }
      group.name = String(params.get("name") || group.name).trim().slice(0, 40) || group.name;
      group.reasons = [...new Set(params.getAll("reason").map((r) => String(r).slice(0, 120)))].slice(0, 50);
      group.members = [...new Set(params.getAll("member").filter((id) => /^\d{5,25}$/.test(id)))].slice(0, 200);
      group.roles = /^\d{5,25}$/.test(params.get("role") || "") ? [params.get("role")] : [];
      writeModoGroups(groups);
      return back("success", `Groupe « ${group.name} » enregistre.`);
    }

    if (pathname === "/admin/planning" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      return renderPlanning(res, readPlanning(planningSiteChannel()), getFlashMessage(url), requestOrigin(req));
    }

    if (pathname === "/admin/planning/image.png" && method === "GET") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      try {
        const png = await renderPlanningImage({ ...readPlanning(planningSiteChannel()), siteUrl: requestOrigin(req) });
        res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "no-store" });
        res.end(png);
      } catch (error) {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
        res.end(error.message);
      }
      return;
    }

    if (pathname === "/admin/planning/image" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const back = (key, message) => `/admin/planning?${key}=${encodeURIComponent(message)}`;
      const channel = planningSiteChannel();
      if (!channel) {
        redirect(res, back("error", "Indique d'abord la chaine Twitch de ce site."));
        return;
      }
      const doc = readPlanning(channel);
      const next = { ...doc, siteUrl: requestOrigin(req) };
      if (form.action === "remove") {
        if (doc.imageWebhookUrl && doc.imageMessageId) {
          await planningImageCall(planningImageThread(`${doc.imageWebhookUrl}/messages/${doc.imageMessageId}`, doc.imageThreadId), "DELETE");
        }
        writePlanning({ ...next, imageWebhookUrl: "", imageMessageId: "", imageThreadId: "", imageKey: "", imageError: "" });
        redirect(res, back("success", "Webhook retire, image effacee"));
        return;
      }
      const url = String(form.webhookUrl || "").trim();
      if (url && !PLANNING_WEBHOOK.test(url)) {
        redirect(res, back("error", "Ce n'est pas une adresse de webhook Discord (https://discord.com/api/webhooks/...)."));
        return;
      }
      const name = String(form.webhookName || "").replace(/\s+/g, " ").trim().slice(0, 80);
      if (/discord|clyde/i.test(name)) {
        redirect(res, back("error", "Discord refuse les noms de webhook qui contiennent « discord » ou « clyde »."));
        return;
      }
      const changedUrl = url && url !== doc.imageWebhookUrl;
      if (changedUrl && doc.imageWebhookUrl && doc.imageMessageId) {
        // Nouveau salon : l'image de l'ancien salon est effacee.
        await planningImageCall(planningImageThread(`${doc.imageWebhookUrl}/messages/${doc.imageMessageId}`, doc.imageThreadId), "DELETE");
      }
      writePlanning({
        ...next,
        imageWebhookUrl: changedUrl ? url : doc.imageWebhookUrl,
        imageWebhookName: name,
        ...(changedUrl ? { imageMessageId: "", imageThreadId: "", imageKey: "" } : {})
      });
      try {
        // Premier webhook ou "Republier" : nouveau message (avec la mention choisie) ; sinon mise a jour.
        const fresh = changedUrl || form.action === "publish";
        await queuePlanningImage(fresh ? "new" : "update", { ping: form.ping || "" });
        redirect(res, back("success", fresh ? "Image publiee sur Discord : elle suivra le planning toute seule" : "Enregistre, image mise a jour"));
      } catch (error) {
        redirect(res, back("error", error.message));
      }
      return;
    }

    if (pathname === "/admin/planning" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const back = (key, message) => `/admin/planning?${key}=${encodeURIComponent(message)}`;
      const channel = normalizePlanningChannel(form.channel || "") || planningSiteChannel();
      if (!channel) {
        redirect(res, back("error", "Indique la chaine Twitch de ce site."));
        return;
      }
      if (channel !== planningSiteChannel()) {
        writeSiteConfig({ planningChannel: channel });
      }
      const doc = readPlanning(channel);
      const newKey = form.action === "newkey" || !doc.syncKey;
      writePlanning({ ...doc, syncKey: newKey ? crypto.randomBytes(24).toString("base64url") : doc.syncKey });
      redirect(
        res,
        back("success", form.action === "newkey" ? "Nouveau code cree : colle-le dans rooky-tv (l'ancien ne marche plus)" : "Enregistre")
      );
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
    fs.writeFileSync(MONITORS_FILE, JSON.stringify({ webhooks: [], bots: [] }, null, 2) + "\n", "utf8");
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

  // Image Discord du programme : passe au jour suivant ("Aujourd'hui", jours passes) meme sans envoi.
  // (startServer tourne avant l'initialisation des constantes du bas du fichier : valeur ecrite ici.)
  setInterval(() => {
    queuePlanningImage("auto").catch(() => {});
  }, 10 * 60 * 1000);
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
    sourcePath === "/go" ||
    sourcePath === "/planning" ||
    sourcePath.startsWith("/api/")
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
  const token = signed ? verifyToken(signed) : "";
  if (token && sessions.has(token)) {
    return true;
  }
  // Owner / admin de rooky-tv connecte par Discord (« Acces modo ») : administration aussi.
  return readModoSession(req, planningSiteChannel())?.a === true;
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
  if (options.maxAge) {
    parts.push(`Max-Age=${options.maxAge}`);
  }
  appendSetCookie(res, parts.join("; "));
}

function clearCookie(res, name) {
  const secureFlag = useSecureCookies ? "; Secure" : "";
  appendSetCookie(res, `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly${secureFlag}`);
}

// Ajoute un cookie sans effacer ceux deja poses dans la reponse (connexion + deconnexion).
function appendSetCookie(res, value) {
  const previous = res.getHeader("Set-Cookie");
  res.setHeader("Set-Cookie", [...(Array.isArray(previous) ? previous : previous ? [String(previous)] : []), value]);
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
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(MONITORS_FILE, "utf8"));
  } catch {
    parsed = {};
  }

  let webhooks = Array.isArray(parsed?.webhooks) ? parsed.webhooks : [];

  // Migration depuis l'ancien format a un seul webhook.
  const legacyUrl = String(parsed?.webhookUrl || "").trim();
  if (!webhooks.length && legacyUrl) {
    webhooks = [{ id: crypto.randomBytes(4).toString("hex"), name: "Principal", url: legacyUrl, isPrimary: true }];
  }

  if (webhooks.length && !webhooks.some((w) => w.isPrimary)) {
    webhooks[0].isPrimary = true;
  }

  return {
    webhooks,
    bots: Array.isArray(parsed?.bots) ? parsed.bots : []
  };
}

function writeMonitorConfig(config) {
  fs.writeFileSync(MONITORS_FILE, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

function getPrimaryWebhook(config) {
  return config.webhooks.find((w) => w.isPrimary) || config.webhooks[0] || null;
}

function getBotWebhook(config, bot) {
  const assigned = bot.webhookId ? config.webhooks.find((w) => w.id === bot.webhookId) : null;
  return assigned || getPrimaryWebhook(config);
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

  const webhook = getBotWebhook(config, bot);
  if (webhook && previousStatus !== "inconnu") {
    const sendResult = await sendDiscordEmbed(webhook.url, {
      title: label,
      description: result.status === "en ligne" ? "Le bot est maintenant en ligne." : "Le bot est maintenant hors ligne.",
      color: result.status === "en ligne" ? 0x3ddc84 : 0xf0555f,
      timestamp: new Date().toISOString()
    });
    if (sendResult.ok) {
      console.log(`[monitoring] ${label}: embed envoye vers "${webhook.name}"`);
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

async function parseForm(req) {
  return Object.fromEntries((await parseFormParams(req)).entries());
}

// Comme parseForm, mais garde les champs repetes (lignes du programme).
function parseFormParams(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 1e6) {
        reject(new Error("Requete trop volumineuse."));
      }
    });

    req.on("end", () => {
      resolve(new URLSearchParams(body));
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
      ${
        readPlanning(planningSiteChannel()).program?.modoUrl
          ? `<a href="/modo/login" class="link-button" style="display:flex;justify-content:center;margin-top:14px;">\ud83d\udee1\ufe0f Acces modo (connexion avec rooky-tv)</a>
      <p style="margin:8px 0 0;font-size:13px;color:var(--muted);text-align:center;">Pour l'equipe de la chaine : planning sur plusieurs semaines et taches reservees aux modos.</p>`
          : ""
      }
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
        <a href="/admin/planning" class="link-button secondary">Planning</a>
        <a href="/modo" class="link-button secondary">Espace modo</a>
        <a href="/admin/tickets" class="link-button secondary">Tickets</a>
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
        <a href="/admin/planning" class="link-button secondary">Planning</a>
        <a href="/modo" class="link-button secondary">Espace modo</a>
        <a href="/admin/tickets" class="link-button secondary">Tickets</a>
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
        <a href="/admin/planning" class="link-button secondary">Planning</a>
        <a href="/modo" class="link-button secondary">Espace modo</a>
        <a href="/admin/tickets" class="link-button secondary">Tickets</a>
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

  const webhookOptions = [`<option value="">(Webhook principal)</option>`]
    .concat(
      config.webhooks.map(
        (w) => `<option value="${escapeHtml(w.id)}">${escapeHtml(w.name)}${w.isPrimary ? " (principal)" : ""}</option>`
      )
    )
    .join("");

  const webhookRows = config.webhooks.length
    ? config.webhooks
        .map(
          (w) => `
            <tr>
              <td><strong>${escapeHtml(w.name)}</strong>${w.isPrimary ? ' <span class="hero-badge" style="margin:0;">Principal</span>' : ""}</td>
              <td><code>${escapeHtml(w.url)}</code></td>
              <td class="actions-cell">
                ${
                  w.isPrimary
                    ? ""
                    : `<form method="post" action="/admin/monitoring/webhooks/primary">
                        <input type="hidden" name="id" value="${escapeHtml(w.id)}" />
                        <button type="submit" class="secondary">Definir principal</button>
                      </form>`
                }
                <form method="post" action="/admin/monitoring/webhooks/delete">
                  <input type="hidden" name="id" value="${escapeHtml(w.id)}" />
                  <button type="submit" class="danger">Retirer</button>
                </form>
              </td>
            </tr>
          `
        )
        .join("")
    : `<tr><td colspan="3">Aucun webhook enregistre.</td></tr>`;

  const rows = config.bots.length
    ? config.bots
        .map((bot) => {
          const statusClass =
            bot.status === "en ligne" ? "status-ok" : bot.status === "hors ligne" ? "status-missing" : "";
          const lastChecked = bot.lastCheckedAt
            ? new Date(bot.lastCheckedAt).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Paris" })
            : "Jamais verifie";
          const webhook = getBotWebhook(config, bot);

          return `
            <tr>
              <td><strong>${escapeHtml(bot.name || bot.botUsername || bot.botId)}</strong></td>
              <td><code>${escapeHtml(bot.guildId)}</code></td>
              <td><code>${escapeHtml(bot.botId || bot.botUsername || "")}</code></td>
              <td class="${statusClass}">${escapeHtml(bot.status || "inconnu")}</td>
              <td>${escapeHtml(lastChecked)}${bot.lastError ? `<br /><span class="status-missing">${escapeHtml(bot.lastError)}</span>` : ""}</td>
              <td>
                <form method="post" action="/admin/monitoring/bots/webhook">
                  <input type="hidden" name="id" value="${escapeHtml(bot.id)}" />
                  <select name="webhookId" onchange="this.form.submit()">${[`<option value="">(Webhook principal)</option>`]
                    .concat(
                      config.webhooks.map(
                        (w) =>
                          `<option value="${escapeHtml(w.id)}" ${bot.webhookId === w.id ? "selected" : ""}>${escapeHtml(w.name)}</option>`
                      )
                    )
                    .join("")}</select>
                </form>
                <span style="font-size:12px;color:var(--muted);">${webhook ? escapeHtml(webhook.name) : "aucun"}</span>
              </td>
              <td class="actions-cell">
                <form method="post" action="/admin/monitoring/bots/check">
                  <input type="hidden" name="id" value="${escapeHtml(bot.id)}" />
                  <button type="submit" class="secondary">Verifier</button>
                </form>
                <form method="post" action="/admin/monitoring/bots/maintenance">
                  <input type="hidden" name="id" value="${escapeHtml(bot.id)}" />
                  <button type="submit" class="warning">Maintenance</button>
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
    : `<tr><td colspan="7">Aucun bot surveille pour le moment.</td></tr>`;

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
        <a href="/admin/planning" class="link-button secondary">Planning</a>
        <a href="/modo" class="link-button secondary">Espace modo</a>
        <a href="/admin/tickets" class="link-button secondary">Tickets</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <section class="card">
      <h2>Serveur en maintenance</h2>
      <p>Envoie une annonce de maintenance generale au webhook principal.</p>
      <form method="post" action="/admin/monitoring/maintenance">
        <button type="submit" class="warning warning-large">Le serveur est en maintenance</button>
      </form>
    </section>
    <section class="card">
      <h2>Webhooks</h2>
      <p>Chaque bot peut notifier un webhook different (utile si une autre personne veut etre notifiee sur son propre serveur pour son bot). Le webhook principal reste utilise par defaut.</p>
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Nom</th>
              <th>URL</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>${webhookRows}</tbody>
        </table>
      </div>
      <details class="add-redirect" style="margin-top:16px;">
        <summary class="add-redirect-summary">Ajouter un webhook</summary>
        <form method="post" action="/admin/monitoring/webhooks" class="form-grid">
          <label>
            <span>Nom du webhook</span>
            <input type="text" name="name" placeholder="Ex: Serveur de Julien" />
          </label>
          <label>
            <span>URL du webhook Discord</span>
            <input type="text" name="url" placeholder="https://discord.com/api/webhooks/..." required />
          </label>
          <p>Un message de test est envoye immediatement pour verifier que ca fonctionne.</p>
          <div class="form-actions">
            <button type="submit">Ajouter</button>
          </div>
        </form>
      </details>
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
        <label>
          <span>Webhook a notifier pour ce bot</span>
          <select name="webhookId">${webhookOptions}</select>
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
              <th>Webhook</th>
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

/* ------------------------------ Planning ---------------------------------- */
// Page publique /planning : le programme du stream de la chaine, tel que rooky-tv le montre dans son
// message Discord « Programme du stream ». Rien ne se saisit ici : rooky-tv envoie le programme sur
// POST /api/planning/sync avec le code de liaison du site (page /admin/planning), a chaque changement.

const PLANNING_PARIS = "Europe/Paris";
const PLANNING_MAX_BODY = 1024 * 1024;

function normalizePlanningChannel(value) {
  const channel = String(value || "")
    .trim()
    .replace(/^https?:\/\/(www\.)?twitch\.tv\//i, "")
    .replace(/^#/, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
  return /^[a-z0-9_]{1,25}$/.test(channel) ? channel : "";
}

// Chaine Twitch de ce site (gardee dans site-config.json).
function planningSiteChannel() {
  return normalizePlanningChannel(readSiteConfig().planningChannel || "");
}

const planningFile = (channel) => path.join(PLANNING_DIR, `${channel}.json`);

function readPlanning(channel) {
  channel = normalizePlanningChannel(channel);
  let parsed = {};
  try {
    parsed = channel ? JSON.parse(fs.readFileSync(planningFile(channel), "utf8")) || {} : {};
  } catch {
    parsed = {};
  }
  return {
    channel,
    syncKey: parsed.syncKey || "",
    program: parsed.program && typeof parsed.program === "object" ? parsed.program : null,
    receivedAt: parsed.receivedAt || 0,
    siteUrl: parsed.siteUrl || "",
    // Image du programme sur Discord (webhook) : l'adresse est un secret, jamais renvoyee au navigateur.
    imageWebhookUrl: parsed.imageWebhookUrl || "",
    imageWebhookName: parsed.imageWebhookName || "",
    imagePostedName: parsed.imagePostedName || "",
    imageMessageId: parsed.imageMessageId || "",
    imageThreadId: parsed.imageThreadId || "",
    imageKey: parsed.imageKey || "",
    imagePublishedAt: parsed.imagePublishedAt || 0,
    imageError: parsed.imageError || ""
  };
}

function writePlanning(doc) {
  const channel = normalizePlanningChannel(doc.channel);
  if (!channel || channel !== planningSiteChannel()) {
    throw new Error("Planning sans chaine valide : rien n'est enregistre.");
  }
  fs.mkdirSync(PLANNING_DIR, { recursive: true });
  fs.writeFileSync(planningFile(channel), `${JSON.stringify({ ...doc, channel }, null, 2)}\n`, "utf8");
}

function requestOrigin(req) {
  const host = String(req.headers.host || "localhost");
  const forwarded = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const proto = forwarded || (/^(localhost|127\.|\[::1\])/.test(host) ? "http" : "https");
  return `${proto}://${host}`;
}

// Garde seulement ce que la page affiche, avec des tailles bornees.
function cleanPlanningProgram(body) {
  const str = (value, max) => (typeof value === "string" ? value.slice(0, max) : "");
  const httpsUrl = (value) => (/^https:\/\/\S+$/i.test(String(value || "")) ? String(value).slice(0, 1000) : "");
  const date = (value) => (/^\d{4}-\d{2}-\d{2}$/.test(String(value || "")) ? value : "");
  const time = (value) => (/^\d{2}:\d{2}$/.test(String(value || "")) ? value : "");
  const list = (value, max) => (Array.isArray(value) ? value.slice(0, max) : []);
  const cleanItem = (item) => ({
    time: time(item?.time),
    subject: str(item?.subject, 200),
    category: str(item?.category, 100),
    thumbnail: httpsUrl(item?.thumbnail),
    status: ["current", "done", "planning"].includes(item?.status) ? item.status : "upcoming",
    // Titre masque sur Discord (rooky-tv) : dans l'image seulement, pas sur la page /planning.
    imageOnly: item?.imageOnly === true
  });
  const modoUrl = /^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1)[:/])\S+$/i.test(String(body.modoUrl || "")) ? String(body.modoUrl).slice(0, 500) : "";
  const modo = body.modo && typeof body.modo === "object"
    ? {
        from: date(body.modo.from),
        to: date(body.modo.to),
        streams: list(body.modo.streams, 80)
          .map((day) => ({
            date: date(day?.date),
            time: time(day?.time),
            cancelled: day?.cancelled === true,
            postponed: day?.postponed === true,
            quiet: day?.quiet === true,
            // Cle du stream ("AAAA-MM-JJ" ou "AAAA-MM-JJ#2") et duree (min) : creneaux proposes dans les tickets.
            key: /^\d{4}-\d{2}-\d{2}(#[2-9])?$/.test(String(day?.key || "")) ? day.key : "",
            duration: Number.isFinite(Number(day?.duration)) && Number(day.duration) > 0 ? Math.min(1440, Math.round(Number(day.duration))) : null,
            description: str(day?.description, 1500),
            items: list(day?.items, 30).map(cleanItem).filter((item) => item.subject)
          }))
          .filter((day) => day.date),
        tasks: list(body.modo.tasks, 200)
          .map((task) => ({
            kind: ["post", "montage", "autre"].includes(task?.kind) ? task.kind : "autre",
            title: str(task?.title, 200),
            date: date(task?.date),
            time: time(task?.time),
            late: task?.late === true,
            recurring: task?.recurring === true
          }))
          .filter((task) => task.date && task.title)
      }
    : null;
  return {
    modoUrl,
    modo,
    live: body.live === true ? true : body.live === false ? false : null,
    scheduleText: str(body.scheduleText, 1000),
    imageUrl: httpsUrl(body.imageUrl),
    vacation: body.vacation && date(body.vacation.until) ? { until: body.vacation.until, message: str(body.vacation.message, 500) } : null,
    // history : rooky-tv a pu lire les streams passes (agenda de la chaine) ; sinon jours passes muets.
    history: body.history === true,
    days: list(body.days, 28)
      .map((day) => ({
        date: date(day?.date),
        time: time(day?.time),
        past: day?.past === true,
        cancelled: day?.cancelled === true,
        postponed: day?.postponed === true,
        description: str(day?.description, 1500),
        items: list(day?.items, 30)
          .map(cleanItem)
          .filter((item) => item.subject)
      }))
      .filter((day) => day.date)
  };
}

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

// Reception du programme envoye par rooky-tv :
// { channel, event: "hello" | "program", live, scheduleText, imageUrl, vacation, days: [{ date, time,
//   cancelled, postponed, description, items: [{ time, subject, category, thumbnail, status }] }] }.
async function handlePlanningSync(req, res) {
  let raw = "";
  try {
    raw = await new Promise((resolve, reject) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString("utf8");
        if (body.length > PLANNING_MAX_BODY) {
          reject(new Error("too_large"));
          req.destroy();
        }
      });
      req.on("end", () => resolve(body));
      req.on("error", reject);
    });
  } catch {
    return sendJson(res, 413, { error: "Programme trop volumineux." });
  }

  const channel = planningSiteChannel();
  if (!channel) {
    return sendJson(res, 409, { error: "Ce site redirection n'a pas encore de chaine : renseigne-la dans sa page Planning." });
  }
  const doc = readPlanning(channel);
  const given = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = Buffer.from(given);
  const b = Buffer.from(doc.syncKey || "");
  if (!doc.syncKey || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return sendJson(res, 401, { error: "Code de liaison refuse : recopie le code affiche dans la page Planning du site redirection." });
  }

  let body;
  try {
    body = JSON.parse(raw || "{}");
  } catch {
    return sendJson(res, 400, { error: "Programme illisible." });
  }
  if (normalizePlanningChannel(body.channel) !== channel) {
    return sendJson(res, 409, { error: `Ce site redirection est celui de #${channel}.` });
  }
  if (body.event === "hello") {
    return sendJson(res, 200, { ok: true, channel });
  }
  if (body.event !== "program") {
    return sendJson(res, 400, { error: "Evenement inconnu." });
  }
  writePlanning({ ...doc, program: cleanPlanningProgram(body), receivedAt: Date.now() });
  // L'image Discord suit le planning (modifiee sur place, seulement si elle change) ; programme publie
  // sur Discord par rooky-tv : toujours mise a jour.
  queuePlanningImage(body.reason === "publish" ? "update" : "auto").catch(() => {});
  return sendJson(res, 200, { ok: true });
}

// Mise en forme Discord minimale : **gras**, *italique*, caracteres echappes, retours a la ligne.
function planningMarkdown(text) {
  const kept = [];
  let html = String(text || "").replace(/\\([*_~`|\\])/g, (_, char) => {
    kept.push(char);
    return `\u0000${kept.length - 1}\u0000`;
  });
  html = escapeHtml(html)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(/\u0000(\d+)\u0000/g, (_, i) => escapeHtml(kept[Number(i)]));
  return html.replace(/\n/g, "<br />");
}

const PLANNING_DAYS = ["Dimanche", "Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi"];
const PLANNING_MONTHS_SHORT = ["janv.", "fevr.", "mars", "avr.", "mai", "juin", "juil.", "aout", "sept.", "oct.", "nov.", "dec."];
const planningHour = (time) => String(time || "").replace(":", "h");

function planningToday() {
  return new Date().toLocaleDateString("fr-CA", { timeZone: PLANNING_PARIS });
}

function planningAddDays(date, offset) {
  const [y, m, d] = date.split("-").map(Number);
  const next = new Date(Date.UTC(y, m - 1, d + offset, 12));
  return next.toISOString().slice(0, 10);
}

function planningDayParts(date) {
  const [y, m, d] = date.split("-").map(Number);
  const weekday = new Date(Date.UTC(y, m - 1, d, 12)).getUTCDay();
  return { name: PLANNING_DAYS[weekday], short: `${d} ${PLANNING_MONTHS_SHORT[m - 1]}`, weekday };
}

function renderPlanningItem(item) {
  const icon = item.status === "current" ? "\u25b6\ufe0f" : item.status === "done" ? "\u2705" : item.status === "planning" ? "\ud83d\udccc" : "";
  return `
    <li class="pw-item pw-${item.status}">
      ${
        item.thumbnail
          ? `<img src="${escapeHtml(item.thumbnail)}" alt="" loading="lazy" referrerpolicy="no-referrer" />`
          : `<span class="pw-noimg" aria-hidden="true"></span>`
      }
      <div>
        <div class="pw-subject">${icon ? `${icon} ` : ""}${escapeHtml(item.subject)}</div>
        <div class="pw-meta">${escapeHtml([item.time ? planningHour(item.time) : "", item.category].filter(Boolean).join(" \u00b7 "))}${
          item.status === "current" ? ` <strong class="pw-now">En cours</strong>` : ""
        }</div>
      </div>
    </li>`;
}

// Grille de la semaine, du lundi au dimanche, toujours complete pour ne jamais etre vide : jours passes =
// streams termines (agenda de la chaine, via rooky-tv), aujourd'hui et apres = planning. Partagee par
// la page publique et l'image Discord.
function planningWeek(program) {
  const today = planningToday();
  // Lundi -> dimanche ; le week-end, la semaine qui arrive : samedi -> vendredi.
  const weekday = planningDayParts(today).weekday;
  const monday = weekday === 6 ? today : weekday === 0 ? planningAddDays(today, -1) : planningAddDays(today, -((weekday + 6) % 7));
  const lastDay = planningAddDays(monday, 6);
  const vacation = program?.vacation || null;
  const streamsByDay = new Map();
  for (const stream of program?.days || []) {
    if (stream.date < monday || stream.date > lastDay) {
      continue;
    }
    // Jour passe : seulement les streams termines ; aujourd'hui et apres : seulement le planning.
    if ((stream.date < today) !== stream.past) {
      continue;
    }
    if (!streamsByDay.has(stream.date)) {
      streamsByDay.set(stream.date, []);
    }
    streamsByDay.get(stream.date).push(stream);
  }
  const days = Array.from({ length: 7 }, (_, i) => {
    const date = planningAddDays(monday, i);
    const { name, short } = planningDayParts(date);
    return {
      date,
      name,
      short,
      isToday: date === today,
      isPast: date < today,
      streams: streamsByDay.get(date) || [],
      emptyText:
        date < today
          ? program?.history ? "Pas de stream" : "—"
          : !program ? "Programme bientot disponible" : vacation ? "En vacances" : "Pas de stream"
    };
  });
  return { today, monday, lastDay, vacation, days };
}

// Page publique /planning : sans les titres d'organisation ni ceux masques sur Discord, qui ne
// figurent que dans l'image du programme.
const publicItems = (stream) => (stream.items || []).filter((item) => item.status !== "planning" && !item.imageOnly);

function renderPublicPlanning(res, doc) {
  const siteConfig = getSiteConfig();
  const program = doc.program;
  const today = planningToday();
  const channel = doc.channel;
  const updated = doc.receivedAt
    ? new Date(doc.receivedAt).toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short", timeZone: PLANNING_PARIS })
    : "";

  const week = planningWeek(program);
  const vacation = week.vacation;

  const columns = week.days
    .map(({ date, name, short, streams, isToday, isPast, emptyText }) => {
      const body = !streams.length
        ? `<p class="pw-off">${emptyText}</p>`
        : streams
            .map((stream) => {
              const badges = [
                isToday && program?.live === true && !stream.cancelled ? `<span class="pw-badge pw-live">\ud83d\udd34 En direct</span>` : "",
                stream.cancelled ? `<span class="pw-badge pw-cancel">Annule</span>` : "",
                stream.past && !stream.cancelled ? `<span class="pw-badge">✔ Termine</span>` : "",
                stream.postponed ? `<span class="pw-badge">Reporte</span>` : ""
              ].join("");
              return `
            <div class="pw-stream${stream.cancelled ? " is-cancelled" : ""}">
              <div class="pw-time">${stream.time ? escapeHtml(planningHour(stream.time)) : "Heure a venir"}</div>
              ${badges ? `<div class="pw-badges">${badges}</div>` : ""}
              ${stream.description ? `<p class="pw-desc">${planningMarkdown(stream.description)}</p>` : ""}
              ${
                stream.cancelled
                  ? ""
                  : publicItems(stream).length
                    ? `<ul class="pw-items">${publicItems(stream).map(renderPlanningItem).join("")}</ul>`
                    : stream.past
                      ? ""
                      : `<p class="pw-empty">Programme bientot annonce</p>`
              }
            </div>`;
            })
            .join("");
      return `
      <section class="pw-day${isToday ? " is-today" : ""}${isPast ? " is-past" : ""}${streams.length ? " has-stream" : ""}"${
        streams.length ? ` tabindex="0" role="button" aria-label="Voir ${isToday ? "aujourd'hui" : escapeHtml(name)} en grand"` : ""
      }>
        <header class="pw-day-head">
          <span class="pw-day-name">${isToday ? "Aujourd'hui" : name}</span>
          <span class="pw-day-date">${escapeHtml(short)}</span>
        </header>
        ${body}
      </section>`;
    })
    .join("");

  const status =
    program?.live === true
      ? `<span class="pw-badge pw-live">\ud83d\udd34 En direct</span>`
      : program?.live === false
        ? `<span class="pw-badge">\u26ab Hors ligne</span>`
        : "";

  const content = `
    <style>
      .pw { display: grid; gap: 18px; }
      .pw-hero {
        display: flex; gap: 18px; align-items: center; justify-content: space-between;
        background: rgba(22, 25, 34, 0.92); border: 1px solid var(--line); border-radius: 20px; padding: 22px 24px;
      }
      .pw-hero h1 { margin: 0 0 6px; font-size: 1.7rem; }
      .pw-hero p { margin: 0; color: var(--muted); line-height: 1.55; }
      .pw-hero-side { display: flex; align-items: center; gap: 14px; flex: 0 0 auto; }
      .pw-hero img { width: 84px; height: 84px; border-radius: 16px; object-fit: cover; }
      .pw-hero-status { display: flex; gap: 8px; align-items: center; margin: 10px 0 0; flex-wrap: wrap; }
      .pw-vacation { background: rgba(254, 231, 92, 0.1); border: 1px solid rgba(254, 231, 92, 0.35); border-radius: 16px; padding: 16px 20px; }
      .pw-vacation strong { color: #fee75c; }
      .pw-week { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 10px; align-items: stretch; }
      .pw-day {
        background: rgba(22, 25, 34, 0.55); border: 1px dashed var(--line); border-radius: 16px; padding: 12px;
        display: grid; gap: 10px; align-content: start; min-height: 170px;
      }
      .pw-day.has-stream { background: rgba(22, 25, 34, 0.95); border: 1px solid rgba(69, 224, 210, 0.4); }
      .pw-day:not(.has-stream) .pw-day-name { color: var(--muted); }
      .pw-day.is-past { opacity: 0.6; }
      .pw-day.is-past.has-stream { border-color: var(--line); }
      .pw-day.is-past .pw-time { color: var(--muted); }
      .pw-day.is-today { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent) inset; }
      .pw-day-head { display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
      .pw-day-name { font-weight: 700; }
      .pw-day.is-today .pw-day-name { color: var(--accent); }
      .pw-day-date { font-size: 12px; color: var(--muted); }
      .pw-off { margin: 0; color: var(--muted); font-size: 13px; opacity: 0.7; }
      .pw-stream { display: grid; gap: 8px; }
      .pw-stream.is-cancelled .pw-time { text-decoration: line-through; opacity: 0.6; }
      .pw-time { font-size: 1.35rem; font-weight: 800; color: #45e0d2; letter-spacing: 0.01em; }
      .pw-badges { display: flex; gap: 6px; flex-wrap: wrap; }
      .pw-badge { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; font-weight: 600; padding: 3px 8px; border-radius: 999px; background: rgba(255, 255, 255, 0.08); color: var(--ink); }
      .pw-live { background: rgba(255, 107, 135, 0.18); color: #ff6b87; }
      .pw-cancel { background: rgba(240, 85, 95, 0.18); color: var(--danger); }
      .pw-desc { margin: 0; font-size: 13px; line-height: 1.5; color: var(--ink); }
      .pw-empty { margin: 0; font-size: 13px; color: var(--muted); font-style: italic; }
      .pw-items { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
      .pw-item { display: flex; gap: 8px; align-items: center; }
      .pw-item img, .pw-noimg { width: 34px; height: 45px; border-radius: 5px; object-fit: cover; flex: 0 0 auto; background: rgba(255, 255, 255, 0.06); }
      .pw-subject {
        font-size: 13px; font-weight: 600; line-height: 1.3; overflow-wrap: anywhere;
        display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
      }
      .pw-meta { font-size: 12px; color: var(--muted); }
      .pw-now { color: #ff6b87; font-weight: 700; }
      .pw-done { opacity: 0.55; }
      .pw-current .pw-subject { color: #ff6b87; }
      .pw-foot { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 13px; }
      .pw-foot a { color: var(--muted); }
      .pw-day.has-stream { cursor: pointer; transition: border-color 0.15s, transform 0.15s; }
      .pw-day.has-stream:hover, .pw-day.has-stream:focus-visible { border-color: #45e0d2; transform: translateY(-2px); outline: none; }
      .pw-zoom {
        width: min(560px, calc(100vw - 32px)); max-height: calc(100vh - 48px); padding: 0; border: 0;
        background: transparent; color: var(--ink); overflow: visible;
      }
      .pw-zoom::backdrop { background: rgba(5, 6, 10, 0.75); backdrop-filter: blur(3px); }
      .pw-zoom-box { position: relative; max-height: calc(100vh - 48px); overflow-y: auto; border-radius: 20px; }
      .pw-zoom .pw-day { opacity: 1; padding: 22px 24px; gap: 16px; min-height: 0; cursor: default; transform: none; display: grid; }
      .pw-zoom .pw-day-name { font-size: 1.5rem; }
      .pw-zoom .pw-day-date { font-size: 15px; }
      .pw-zoom .pw-time { font-size: 2.2rem; }
      .pw-zoom .pw-desc { font-size: 15px; }
      .pw-zoom .pw-items { gap: 14px; }
      .pw-zoom .pw-item { gap: 14px; }
      .pw-zoom .pw-item img, .pw-zoom .pw-noimg { width: 72px; height: 96px; border-radius: 8px; }
      .pw-zoom .pw-subject { font-size: 17px; -webkit-line-clamp: unset; display: block; }
      .pw-zoom .pw-meta { font-size: 14px; margin-top: 4px; }
      .pw-zoom-close {
        position: absolute; top: 12px; right: 12px; width: 36px; height: 36px; border-radius: 50%; border: 0;
        background: rgba(255, 255, 255, 0.08); color: var(--ink); font-size: 20px; line-height: 1; cursor: pointer;
      }
      .pw-zoom-close:hover { background: rgba(255, 255, 255, 0.16); }
      .pw-zoom .pw-day-head { padding-right: 44px; justify-content: flex-start; gap: 12px; }
      @media (max-width: 1100px) { .pw-week { grid-template-columns: repeat(4, minmax(0, 1fr)); } }
      @media (max-width: 760px) {
        .pw-week { grid-template-columns: 1fr; }
        .pw-day { min-height: 0; }
        .pw-day:not(.has-stream) { display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; }
        .pw-day:not(.has-stream) .pw-day-head { gap: 10px; justify-content: flex-start; }
        .pw-hero { flex-direction: column-reverse; align-items: flex-start; }
      }
    </style>
    <main class="pw">
      <section class="pw-hero">
        <div>
          <h1>Programme de la semaine</h1>
          ${program?.scheduleText ? `<p>${planningMarkdown(program.scheduleText)}</p>` : ""}
          <div class="pw-hero-status">
            ${status}
            ${channel ? `<a class="link-button" href="https://twitch.tv/${escapeHtml(channel)}" target="_blank" rel="noreferrer">Regarder sur Twitch</a>` : ""}
          </div>
        </div>
        ${program?.imageUrl ? `<div class="pw-hero-side"><img src="${escapeHtml(program.imageUrl)}" alt="" referrerpolicy="no-referrer" /></div>` : ""}
      </section>
      ${
        vacation
          ? `<section class="pw-vacation"><strong>\ud83c\udfd6\ufe0f En vacances</strong> \u2014 retour le ${escapeHtml(vacation.until.split("-").reverse().join("/"))}${
              vacation.message ? `<br />${planningMarkdown(vacation.message)}` : ""
            }</section>`
          : ""
      }
      <div class="pw-week">${columns}</div>
      <footer class="pw-foot">
        <span>${updated ? `Mis a jour le ${escapeHtml(updated)}` : ""}</span>
        <span>${program?.modoUrl ? `<a href="/modo">Acces modo</a> · ` : ""}<a href="/">Retour a ${escapeHtml(siteConfig.title)}</a></span>
      </footer>
    </main>
    <dialog class="pw-zoom" aria-label="Programme du jour">
      <div class="pw-zoom-box"><button type="button" class="pw-zoom-close" aria-label="Fermer">×</button><div class="pw-zoom-day"></div></div>
    </dialog>
    <script>
      (() => {
        // Clic sur un jour : le meme contenu, en grand, dans une fenetre (Echap, croix ou clic a cote ferme).
        const dialog = document.querySelector(".pw-zoom");
        if (!dialog || typeof dialog.showModal !== "function") return;
        const slot = dialog.querySelector(".pw-zoom-day");
        const open = (day) => {
          const copy = day.cloneNode(true);
          copy.removeAttribute("tabindex");
          copy.removeAttribute("role");
          copy.removeAttribute("aria-label");
          slot.replaceChildren(copy);
          dialog.showModal();
        };
        document.querySelectorAll(".pw-week .pw-day.has-stream").forEach((day) => {
          day.addEventListener("click", (event) => {
            if (event.target.closest("a")) return;
            open(day);
          });
          day.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              open(day);
            }
          });
        });
        dialog.querySelector(".pw-zoom-close").addEventListener("click", () => dialog.close());
        dialog.addEventListener("click", (event) => {
          if (event.target === dialog) dialog.close();
        });
      })();
    </script>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Programme de la semaine", content, { wide: true }));
}

/* ------------------------------ Espace modo ------------------------------ */
// L'equipe de la chaine (streamer et modos) se connecte par rooky-tv : /modo/login envoie sur
// rooky-tv (adresse donnee par la synchro), qui verifie la personne et revient sur /modo/callback avec
// un jeton signe par la cle de liaison (secret partage avec rooky-tv seulement), valable 5 minutes et
// lie au navigateur (cookie modo_state). Session : cookie signe, 12 h, avec les activites que la
// personne voit sur le planning rooky-tv (k : stream, montage, post, autre).
const MODO_SESSION_MS = 12 * 60 * 60 * 1000;

const modoSiteId = (syncKey) => crypto.createHash("sha256").update(String(syncKey)).digest("hex").slice(0, 16);

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function verifyModoToken(doc, token, state) {
  if (!doc.channel || !doc.syncKey || !state) return null;
  const [payload, sig] = String(token).split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", doc.syncKey).update(payload).digest("base64url");
  if (!safeEqual(sig, expected)) return null;
  let claims;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!claims || claims.c !== doc.channel || !safeEqual(claims.s || "", state) || !(claims.e > Date.now())) return null;
  return claims;
}

function signModoSession(data) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  return `${payload}.${crypto.createHmac("sha256", `modo:${SESSION_SECRET}`).update(payload).digest("base64url")}`;
}

function readModoSession(req, channel) {
  const value = parseCookies(req.headers.cookie || "").modo || "";
  const [payload, sig] = value.split(".");
  if (!payload || !sig) return null;
  if (!safeEqual(sig, crypto.createHmac("sha256", `modo:${SESSION_SECRET}`).update(payload).digest("base64url"))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return data && data.c === channel && data.e > Date.now() ? data : null;
  } catch {
    return null;
  }
}

const MODO_KINDS = {
  montage: { label: "Montage", emoji: "\ud83c\udfac" },
  post: { label: "Poster", emoji: "\ud83d\udcf2" },
  autre: { label: "Autre", emoji: "\ud83d\udcdd" }
};

function renderModoPlanning(res, doc, viewer, live = {}, flash = {}) {
  const modo = doc.program?.modo || null;
  const today = planningToday();
  const rights = modoRights(viewer, live);
  const can = (kind) => rights[kind] === "view" || rights[kind] === "edit";
  const streams = (modo?.streams || []).filter((s) => s.date >= today && can("stream"));
  const tasks = (modo?.tasks || []).filter((t) => (t.date >= today || t.late) && can(t.kind));
  const last = modo?.to && modo.to >= today ? modo.to : planningAddDays(today, 27);
  const updated = doc.receivedAt
    ? new Date(doc.receivedAt).toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short", timeZone: PLANNING_PARIS })
    : "";

  const tag = (text, cls = "") => `<span class="md-tag${cls ? ` ${cls}` : ""}">${text}</span>`;
  const renderStream = (stream) => `
    <div class="md-stream${stream.cancelled ? " is-cancelled" : ""}">
      <div class="md-line">
        <span class="md-time">${stream.time ? escapeHtml(planningHour(stream.time)) : "?"}</span>
        <strong>\ud83d\udd34 Stream</strong>
        ${stream.cancelled ? tag("Annule", "bad") : ""}${stream.postponed ? tag("Reporte") : ""}${stream.quiet ? tag("Pas encore annonce") : ""}
      </div>
      ${stream.description ? `<p class="md-desc">${planningMarkdown(stream.description)}</p>` : ""}
      ${
        stream.items.length
          ? `<ul class="md-items">${stream.items
              .map(
                (item) => `<li>
                  ${item.thumbnail ? `<img src="${escapeHtml(item.thumbnail)}" alt="" loading="lazy" referrerpolicy="no-referrer" />` : `<span class="md-noimg"></span>`}
                  <span>${escapeHtml(item.subject)}<small>${escapeHtml([item.time ? planningHour(item.time) : "", item.category].filter(Boolean).join(" \u00b7 "))}</small>
                  ${item.status === "planning" ? tag("Organisation") : ""}${item.imageOnly ? tag("Masque sur Discord") : ""}</span>
                </li>`
              )
              .join("")}</ul>`
          : `<p class="md-empty">Programme pas encore prepare</p>`
      }
    </div>`;
  const renderTask = (task) => `
    <div class="md-task">
      <span class="md-time">${task.time ? escapeHtml(planningHour(task.time)) : ""}</span>
      <span>${MODO_KINDS[task.kind].emoji} ${escapeHtml(task.title)}</span>
      ${tag(MODO_KINDS[task.kind].label)}${task.recurring ? tag("Repete") : ""}${task.late ? tag("En retard", "bad") : ""}
    </div>`;

  // Semaines du lundi au dimanche, de la semaine en cours jusqu'a la fin de ce que rooky-tv envoie.
  const weekday = planningDayParts(today).weekday;
  let monday = planningAddDays(today, -((weekday + 6) % 7));
  const weeks = [];
  while (monday <= last) {
    const days = [];
    for (let i = 0; i < 7; i++) {
      const date = planningAddDays(monday, i);
      if (date < today || date > last) continue;
      const dayStreams = streams.filter((s) => s.date === date);
      const dayTasks = tasks.filter((t) => t.date === date);
      const { name, short } = planningDayParts(date);
      days.push(`
        <section class="md-day${date === today ? " is-today" : ""}${dayStreams.length || dayTasks.length ? "" : " is-empty"}">
          <header><strong>${date === today ? "Aujourd'hui" : name}</strong> <span>${escapeHtml(short)}</span></header>
          ${dayStreams.map(renderStream).join("")}${dayTasks.map(renderTask).join("")}
          ${dayStreams.length || dayTasks.length ? "" : `<p class="md-empty">Rien de prevu</p>`}
        </section>`);
    }
    const end = planningAddDays(monday, 6);
    // Numero de semaine ISO (celui des calendriers francais) : la semaine du jeudi.
    const [ty, tm, td] = planningAddDays(monday, 3).split("-").map(Number);
    const weekNumber = Math.floor((Date.UTC(ty, tm - 1, td) - Date.UTC(ty, 0, 1)) / 86400000 / 7) + 1;
    weeks.push(`
      <section class="md-week">
        <h2>Semaine ${weekNumber} <span class="md-week-dates">· du ${escapeHtml(planningDayParts(monday).short)} au ${escapeHtml(planningDayParts(end).short)}</span></h2>
        <div class="md-days">${days.join("")}</div>
      </section>`);
    monday = planningAddDays(monday, 7);
  }

  const editKinds = ["stream", "montage", "post", "autre"].filter((k) => rights[k] === "edit");
  const kindOptions = (kinds) => kinds.map((k) => `<option value="${k}">${MODO_ALL_KINDS[k]}</option>`).join("");
  const suggestions = Array.isArray(live.suggestions) ? live.suggestions : [];
  const suggestionStatus = { pending: "En attente du streamer", accepted: "Ajoutee au planning", refused: "Refusee" };
  const forms = `
    <section class="md-forms">
      <form method="post" action="/modo/action" class="md-form">
        <h2>Ajouter au planning</h2>
        <div class="md-form-row">
          <select name="kind" aria-label="Type">${kindOptions(editKinds.length ? editKinds : ["autre"])}</select>
          <input type="text" name="title" maxlength="120" placeholder="Titre" required />
        </div>
        <div class="md-form-row">
          <input type="date" name="date" min="${today}" value="${today}" required />
          <input type="time" name="time" value="12:00" required />
        </div>
        <textarea name="notes" maxlength="800" rows="2" placeholder="Notes (optionnel)"></textarea>
        <div class="md-form-row">
          ${editKinds.length ? `<button type="submit" name="action" value="add">Ajouter</button>` : ""}
          <button type="submit" name="action" value="suggest" class="secondary">Suggerer au streamer</button>
        </div>
        <p class="md-hint">${editKinds.length ? "Ajouter : directement dans le planning (et l'agenda Google de la chaine, sans compte Google a connecter). " : ""}Suggerer : le streamer recoit un MP du bot et accepte ou refuse.</p>
      </form>
      <div class="md-form">
        <h2>Suggestions</h2>
        ${
          suggestions.length
            ? `<ul class="md-sugg">${suggestions
                .map(
                  (sg) => `<li><span>${escapeHtml(MODO_ALL_KINDS[sg.kind] || sg.kind)} <strong>${escapeHtml(sg.title)}</strong><small>${escapeHtml(modoDateTime(sg.dueAt))} · par ${escapeHtml(sg.author || "?")}</small>${sg.notes ? `<small>${escapeHtml(sg.notes)}</small>` : ""}</span>${
                    live.canDecide && sg.status === "pending"
                      ? `<form method="post" action="/modo/suggestions/${Number(sg.id)}" class="md-decide"><button type="submit" name="decision" value="accept">Ajouter</button><button type="submit" name="decision" value="refuse" class="secondary">Refuser</button></form>`
                      : `<span class="md-tag${sg.status === "refused" ? " bad" : sg.status === "accepted" ? " ok" : ""}">${suggestionStatus[sg.status] || sg.status}</span>`
                  }</li>`
                )
                .join("")}</ul>`
            : `<p class="md-empty">Aucune suggestion en cours.</p>`
        }
      </div>
    </section>`;

  const content = `
    <style>
      ${MODO_CSS}
      .md { display: grid; gap: 18px; }
      .md-hero { background: rgba(22, 25, 34, 0.92); border: 1px solid var(--line); border-radius: 20px; padding: 20px 22px; display: flex; justify-content: space-between; gap: 14px; flex-wrap: wrap; align-items: center; }
      .md-hero h1 { margin: 0 0 4px; font-size: 1.5rem; }
      .md-hero p { margin: 0; color: var(--muted); }
      .md-week h2 { font-size: 1.05rem; margin: 6px 0 10px; color: var(--ink); }
      .md-week-dates { color: var(--muted); font-weight: 400; }
      .md-days { display: grid; gap: 8px; }
      .md-day { background: rgba(22, 25, 34, 0.9); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; display: grid; gap: 10px; }
      .md-day.is-today { border-color: var(--accent); }
      .md-day.is-empty { opacity: 0.55; padding: 8px 14px; display: flex; justify-content: space-between; align-items: center; }
      .md-day header span { color: var(--muted); font-size: 13px; margin-left: 6px; }
      .md-line, .md-task { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
      .md-time { font-weight: 800; color: #45e0d2; min-width: 48px; }
      .md-stream.is-cancelled .md-time { text-decoration: line-through; opacity: 0.6; }
      .md-tag { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 999px; background: rgba(255, 255, 255, 0.08); }
      .md-tag.bad { background: rgba(240, 85, 95, 0.18); color: var(--danger); }
      .md-desc { margin: 6px 0 0 56px; font-size: 13px; }
      .md-items { list-style: none; margin: 8px 0 0 56px; padding: 0; display: grid; gap: 6px; }
      .md-items li { display: flex; gap: 8px; align-items: center; font-size: 13px; }
      .md-items li > span { display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: center; min-width: 0; overflow-wrap: anywhere; }
      .md-items small { color: var(--muted); }
      .md-items img, .md-noimg { width: 26px; height: 35px; border-radius: 4px; object-fit: cover; flex: 0 0 auto; background: rgba(255, 255, 255, 0.06); }
      .md-empty { margin: 0; color: var(--muted); font-size: 13px; font-style: italic; }
      .md-day.is-empty .md-empty { font-style: normal; }
      .md-foot { color: var(--muted); font-size: 13px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
      .md-foot a { color: var(--muted); }
      @media (max-width: 640px) { .md-desc, .md-items { margin-left: 0; } }
    </style>
    <main class="md">
      <section class="md-hero">
        <div>
          <h1>Espace modo${doc.channel ? ` \u00b7 #${escapeHtml(doc.channel)}` : ""}</h1>
          <p>Connecte : ${escapeHtml(viewer.n || "")}${viewer.password ? " (mot de passe)" : viewer.admin ? " (admin, par Discord)" : viewer.r === "streamer" ? " (streamer)" : " (modo)"}. Visible seulement par l'equipe de la chaine.</p>
        </div>
        <span style="display:flex;gap:8px;flex-wrap:wrap;">${viewer.admin ? `<a class="link-button secondary" href="/admin">Administration</a>` : ""}<a class="link-button secondary" href="${viewer.password ? "/logout" : viewer.admin ? "/logout" : "/modo/logout"}">Se deconnecter</a></span>
      </section>
      ${modoNav("planning", live, rights)}
      ${renderMessages(flash)}
      ${live.error ? `<div class="message error">rooky-tv : ${escapeHtml(live.error)}</div>` : ""}
      ${forms}
      ${!modo ? `<p class="md-empty">Rien recu de rooky-tv pour l'instant : le planning arrive au prochain changement.</p>` : weeks.join("")}
      <footer class="md-foot">
        <span>${updated ? `Mis a jour le ${escapeHtml(updated)}` : ""}</span>
        <a href="/planning">Page publique du planning</a>
      </footer>
    </main>
  `;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Espace modo", content, { wide: true }));
}

const MODO_ALL_KINDS = {
  stream: "\ud83d\udd34 Stream",
  montage: "\ud83c\udfac Montage",
  post: "\ud83d\udcf2 Poster",
  autre: "\ud83d\udcdd Autre"
};

// Droits affiches : ceux renvoyes en direct par rooky-tv, sinon ceux de la connexion (anciennes
// sessions : true = "view"). rooky-tv reverifie de toute facon chaque action.
function modoRights(viewer, live) {
  const level = (v) => (v === true ? "view" : v === "view" || v === "edit" ? v : "none");
  const source = live?.rights ? { ...live.rights.kinds, tickets: live.rights.tickets } : viewer.k || {};
  return Object.fromEntries(["stream", "montage", "post", "autre", "tickets"].map((k) => [k, level(source[k])]));
}

function modoDateTime(value) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: PLANNING_PARIS });
}

/**
 * Appel a rooky-tv (pages/api/redirection/modo.js), signe avec la cle de liaison. La personne
 * connectee est transmise (id Discord, ou admin du site), rooky-tv verifie ses droits.
 */
async function modoApi(doc, viewer, action, extra = {}) {
  if (!doc.channel || !doc.syncKey || !doc.program?.modoUrl) throw new Error("Site pas encore relie a rooky-tv.");
  const endpoint = new URL("/api/redirection/modo", doc.program.modoUrl).toString();
  const body = JSON.stringify({
    ...extra,
    channel: doc.channel,
    site: modoSiteId(doc.syncKey),
    ts: Date.now(),
    action,
    ...(viewer.ticketChannel ? { ticketChannel: viewer.ticketChannel } : {}),
    user: viewer.admin ? { admin: true, ...(viewer.u ? { id: viewer.u } : {}), name: viewer.password ? "Admin du site" : viewer.n || "Admin" } : { id: viewer.u, name: viewer.n }
  });
  const signature = crypto.createHmac("sha256", doc.syncKey).update(body).digest("base64url");
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Modo-Signature": signature },
    body,
    signal: AbortSignal.timeout(10000)
  }).catch(() => null);
  if (!res) throw new Error("rooky-tv ne repond pas.");
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `rooky-tv a refuse (${res.status}).`);
  return data;
}

const MODO_CSS = `
  .md-nav { display: flex; gap: 8px; flex-wrap: wrap; }
  .md-nav a { padding: 8px 14px; border-radius: 999px; border: 1px solid var(--line); color: var(--ink); text-decoration: none; font-weight: 600; }
  .md-nav a.on { border-color: var(--accent); color: var(--accent); }
  .md-count { background: #ff6b87; color: #fff; border-radius: 999px; padding: 0 7px; font-size: 12px; margin-left: 4px; }
  .md-forms { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
  .md-form { background: rgba(22, 25, 34, 0.9); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px; display: grid; gap: 8px; align-content: start; }
  .md-form h2 { margin: 0; font-size: 1.05rem; }
  .md-form-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .md-form-row > * { flex: 1 1 120px; min-width: 0; }
  .md-form textarea { width: 100%; box-sizing: border-box; }
  .md-hint { margin: 0; font-size: 12px; color: var(--muted); }
  .md-sugg { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
  .md-sugg li { display: flex; justify-content: space-between; gap: 8px; align-items: center; font-size: 13px; }
  .md-sugg li > span:first-child { display: grid; min-width: 0; overflow-wrap: anywhere; }
  .md-sugg small { color: var(--muted); }
  .md-decide { display: flex; gap: 6px; flex: 0 0 auto; }
  .md-slot { display: flex; gap: 10px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
  .md-slot input[type=checkbox] { width: 18px; height: 18px; flex: 0 0 auto; margin: 0; }
  .md-slot > span:nth-child(2) { display: grid; flex: 1 1 200px; min-width: 0; overflow-wrap: anywhere; }
  .md-slot small { color: var(--muted); }
  .md-slot-end { display: flex; gap: 6px; align-items: center; color: var(--muted); font-size: 13px; }
  .md-decide button { padding: 6px 10px; font-size: 13px; }
  .md-tag { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 999px; background: rgba(255, 255, 255, 0.08); white-space: nowrap; }
  .md-tag.bad { background: rgba(240, 85, 95, 0.18); color: var(--danger); }
  .md-tag.ok { background: rgba(69, 224, 210, 0.15); color: #45e0d2; }
  .mt-list { display: grid; gap: 8px; }
  .mt-row { display: flex; justify-content: space-between; gap: 10px; align-items: center; background: rgba(22, 25, 34, 0.9); border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; color: var(--ink); text-decoration: none; }
  .mt-row.unread { border-color: #ff6b87; }
  .mt-row.closed { opacity: 0.6; }
  .mt-row > span:first-child { display: grid; gap: 2px; min-width: 0; overflow-wrap: anywhere; }
  .mt-row small { color: var(--muted); }
  .mt-chat { display: grid; gap: 10px; }
  .mt-msg { max-width: 80%; padding: 10px 14px; border-radius: 14px; background: rgba(22, 25, 34, 0.95); border: 1px solid var(--line); overflow-wrap: anywhere; white-space: pre-wrap; }
  .mt-msg.out { justify-self: end; background: rgba(69, 224, 210, 0.12); border-color: rgba(69, 224, 210, 0.35); }
  .mt-msg.system { justify-self: center; background: transparent; border-style: dashed; color: var(--muted); font-size: 13px; }
  .mt-msg small { display: block; color: var(--muted); font-size: 11px; margin-top: 4px; white-space: normal; }
  .mt-msg img { max-width: 100%; max-height: 260px; border-radius: 8px; margin-top: 6px; display: block; }
  .mt-reply { display: grid; gap: 8px; }
  .mt-reply textarea { width: 100%; box-sizing: border-box; }
  .mt-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  @media (max-width: 640px) { .mt-msg { max-width: 100%; } }
`;

function modoNav(active, live, rights) {
  const tickets = Array.isArray(live?.tickets) ? live.tickets : [];
  const unread = tickets.filter((t) => t.status === "open" && t.unread).length;
  const canTickets = rights.tickets === "view" || rights.tickets === "edit";
  return `<nav class="md-nav">
    <a href="/modo" class="${active === "planning" ? "on" : ""}">\ud83d\udcc5 Planning</a>
    ${canTickets ? `<a href="/modo/tickets" class="${active === "tickets" ? "on" : ""}">\ud83c\udfab Tickets${unread ? `<span class="md-count">${unread}</span>` : ""}</a>` : ""}
  </nav>`;
}

function modoShell(doc, viewer, inner) {
  return `
    <style>
      ${MODO_CSS}
      .md { display: grid; gap: 18px; }
      .md-hero { background: rgba(22, 25, 34, 0.92); border: 1px solid var(--line); border-radius: 20px; padding: 20px 22px; display: flex; justify-content: space-between; gap: 14px; flex-wrap: wrap; align-items: center; }
      .md-hero h1 { margin: 0 0 4px; font-size: 1.5rem; }
      .md-hero p { margin: 0; color: var(--muted); }
      .md-empty { margin: 0; color: var(--muted); font-size: 13px; font-style: italic; }
    </style>
    <main class="md">
      <section class="md-hero">
        <div>
          <h1>Espace modo${doc.channel ? ` \u00b7 #${escapeHtml(doc.channel)}` : ""}</h1>
          <p>Connecte : ${escapeHtml(viewer.n || "")}${viewer.password ? " (mot de passe)" : viewer.admin ? " (admin, par Discord)" : viewer.r === "streamer" ? " (streamer)" : " (modo)"}.</p>
        </div>
        <span style="display:flex;gap:8px;flex-wrap:wrap;">${viewer.admin ? `<a class="link-button secondary" href="/admin">Administration</a>` : ""}<a class="link-button secondary" href="${viewer.password ? "/logout" : viewer.admin ? "/logout" : "/modo/logout"}">Se deconnecter</a></span>
      </section>
      ${inner}
    </main>`;
}

function renderModoTickets(res, doc, viewer, live, flash, tab = "") {
  return renderTicketDesk(res, doc, viewer, live, null, flash, tab);
}

// Creneaux proposes a l'invite (rooky-tv src/siteTickets.js) : etat, choix a valider, et formulaire
// de proposition (streams des 7 prochains jours + autre date) pour le streamer et les admins.
function renderSlotOffer(doc, ticket, canDecide) {
  const offer = ticket.offer;
  const statusText = {
    proposed: "En attente du choix de l'invite (en MP)",
    chosen: "L'invite a choisi : a valider",
    accepted: "Valide",
    refused: "Refuse"
  };
  const offerBox = offer
    ? `<section class="md-form">
        <h2>\ud83d\udcc5 Creneaux <span class="md-tag${offer.status === "chosen" ? " bad" : offer.status === "accepted" ? " ok" : ""}">${statusText[offer.status] || escapeHtml(offer.status)}</span></h2>
        <ul class="md-sugg">${(offer.streams || [])
          .map((st) => `<li><span><strong>${escapeHtml(planningDayParts(st.date).name)} ${escapeHtml(planningDayParts(st.date).short)} · ${escapeHtml(planningHour(st.start))} \u2192 ${escapeHtml(planningHour(st.end))}</strong>${st.titles.length ? `<small>${st.titles.map(escapeHtml).join(" · ")}</small>` : `<small>${st.custom ? "Autre date" : "Programme libre"}</small>`}</span></li>`)
          .join("")}</ul>
        ${offer.choice ? `<p><strong>Choix de l'invite :</strong> ${escapeHtml(offer.choice.text)}${offer.choice.early ? " <span class=\"md-tag\">avant le debut</span>" : ""}</p>` : ""}
        ${
          canDecide && offer.status === "chosen"
            ? `<form method="post" class="mt-actions"><button type="submit" name="action" value="offer_accept">Valider (modifie le programme)</button><button type="submit" name="action" value="offer_refuse" class="secondary">Refuser</button></form>
               <p class="md-hint">Valider : l'heure du titre change pour ce stream${offer.choice?.early ? ", le debut du stream est avance" : ""} — sans le nom de l'invite. Il recoit la validation en MP.</p>`
            : ""
        }
      </section>`
    : "";
  if (!canDecide || ticket.status !== "open" || offer?.status === "chosen") return offerBox;
  const today = planningToday();
  const last = planningAddDays(today, 6);
  const streams = (doc.program?.modo?.streams || []).filter((st) => st.key && st.date >= today && st.date <= last && !st.cancelled);
  const endOf = (st) => {
    const [h, m] = String(st.time || "21:00").split(":").map(Number);
    const total = (h * 60 + m + (Number(st.duration) || 360)) % 1440;
    return `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
  };
  const form = `
    <details class="md-form">
      <summary>\ud83d\udcc5 ${offer ? "Proposer d'autres creneaux" : "Proposer des creneaux"}</summary>
      <form method="post" class="mt-reply" style="margin-top:8px;">
        ${
          streams.length
            ? streams
                .map(
                  (st) => `<label class="md-slot"><input type="checkbox" name="stream" value="${escapeHtml(st.key)}" />
                    <span><strong>${escapeHtml(planningDayParts(st.date).name)} ${escapeHtml(planningDayParts(st.date).short)} · ${escapeHtml(planningHour(st.time))}</strong>
                    <small>${(st.items || []).filter((it) => it.status !== "planning").map((it) => escapeHtml(it.subject)).join(" · ") || "Programme libre"}</small></span>
                    <span class="md-slot-end">fin <input type="time" name="end_${escapeHtml(st.key)}" value="${endOf(st)}" /></span></label>`
                )
                .join("")
            : `<p class="md-empty">Aucun stream au planning dans les 7 prochains jours.</p>`
        }
        <div class="md-form-row"><span class="md-hint" style="flex:0 0 100%;">Autre date (optionnel) :</span>
          <input type="date" name="custom_date" min="${today}" />
          <input type="time" name="custom_time" aria-label="Debut" />
          <input type="time" name="custom_end" aria-label="Fin" />
        </div>
        <p class="md-hint">L'invite recoit ces streams en MP avec leurs titres (sans les titres d'organisation) et choisit le titre et son heure, jusqu'a 2 h avant le debut du stream. Tu valides ensuite ici.</p>
        <div class="mt-actions"><button type="submit" name="action" value="propose">Envoyer les creneaux en MP</button></div>
      </form>
    </details>`;
  return offerBox + form;
}

function renderModoTicket(res, doc, viewer, live, data, flash, tab = "") {
  return renderTicketDesk(res, doc, viewer, live, data || {}, flash, tab);
}

const TICKET_DESK_CSS = `
  .td { display: grid; grid-template-columns: 330px minmax(0, 1fr); min-height: 70vh; height: calc(100vh - 230px); border: 1px solid var(--line); border-radius: 18px; overflow: hidden; background: rgba(14, 16, 23, 0.92); }
  .td-list { border-right: 1px solid var(--line); display: flex; flex-direction: column; min-height: 0; }
  .td-tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; margin: 12px; padding: 4px; border-radius: 10px; background: rgba(255, 255, 255, 0.04); }
  .td-tabs a { text-align: center; padding: 8px; border-radius: 8px; color: var(--muted); text-decoration: none; font-weight: 600; font-size: 14px; }
  .td-tabs a.on { background: rgba(124, 92, 255, 0.22); color: var(--ink); }
  .td-scroll { overflow-y: auto; min-height: 0; flex: 1; padding-bottom: 10px; }
  .td-chan { margin: 12px 12px 0; }
  .td-chan select { width: 100%; }
  .td-group { margin: 10px 14px 4px; font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); display: flex; gap: 6px; align-items: center; }
  .td-group b { color: var(--ink); }
  .td-item { display: flex; gap: 10px; align-items: center; padding: 9px 14px; margin: 2px 8px; border-radius: 10px; border-left: 3px solid transparent; color: var(--ink); text-decoration: none; }
  .td-item:hover { background: rgba(255, 255, 255, 0.04); }
  .td-item.on { background: rgba(124, 92, 255, 0.14); border-left-color: #f5c542; }
  .td-avatar { width: 34px; height: 34px; border-radius: 50%; flex: 0 0 auto; display: grid; place-items: center; font-weight: 700; font-size: 14px; background: rgba(124, 92, 255, 0.3); color: #fff; }
  .td-item-main { min-width: 0; flex: 1; display: grid; gap: 2px; }
  .td-item-top { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; }
  .td-name { font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .td-item.unread .td-name { font-weight: 700; }
  .td-id { font-size: 11px; color: var(--muted); font-family: ui-monospace, monospace; flex: 0 0 auto; }
  .td-sub { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: flex; gap: 6px; align-items: center; }
  .td-dot { width: 7px; height: 7px; border-radius: 50%; flex: 0 0 auto; background: #57f287; }
  .td-dot.new { background: #f5c542; }
  .td-dot.off { background: #6b7280; }
  .td-none { margin: 14px; color: var(--muted); font-size: 13px; }
  .td-pane { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
  .td-empty { flex: 1; display: grid; place-content: center; justify-items: center; gap: 6px; text-align: center; color: var(--muted); padding: 20px; }
  .td-empty-icon { width: 46px; height: 46px; border-radius: 50%; display: grid; place-items: center; background: rgba(255, 255, 255, 0.06); font-size: 20px; }
  .td-empty strong { color: var(--ink); }
  .td-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; padding: 14px 18px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
  .td-head-main { display: flex; gap: 12px; align-items: center; min-width: 0; }
  .td-head h2 { margin: 0; font-size: 1.05rem; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .td-head p { margin: 2px 0 0; font-size: 12px; color: var(--muted); }
  .td-head form { display: flex; gap: 6px; }
  .td-body { flex: 1; overflow-y: auto; min-height: 0; padding: 14px 18px; display: grid; gap: 12px; align-content: start; }
  .td-compose { border-top: 1px solid var(--line); padding: 12px 18px; display: grid; gap: 8px; }
  .td-compose textarea { width: 100%; box-sizing: border-box; resize: vertical; min-height: 64px; background: rgba(255, 255, 255, 0.04); color: var(--ink); border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; font: inherit; }
  .td-compose textarea:focus { outline: none; border-color: rgba(124, 92, 255, 0.7); }
  .td-body details.md-form > summary { cursor: pointer; font-weight: 600; }
  .td-compose-row { display: flex; gap: 8px; justify-content: space-between; align-items: center; flex-wrap: wrap; }
  .td-back { display: none; }
  @media (max-width: 860px) {
    .td { grid-template-columns: 1fr; height: auto; min-height: 0; }
    .td-list { border-right: 0; }
    .td.has-ticket .td-list { display: none; }
    .td:not(.has-ticket) .td-pane { display: none; }
    .td-back { display: inline-block; }
    .td-body { max-height: none; }
  }
`;

// Tickets en deux colonnes : la liste (Ouverts / Fermes, nouveaux messages en premier) et la
// conversation du ticket choisi, ou « Aucun ticket ouvert ».
function renderTicketDesk(res, doc, viewer, live, data, flash, tab) {
  const rights = modoRights(viewer, live);
  const canReply = rights.tickets === "edit";
  const tickets = Array.isArray(live.tickets) ? live.tickets : null;
  const ticket = data?.ticket || null;
  const closedTab = tab === "fermes" || (!tab && ticket && ticket.status !== "open");
  const q = closedTab ? "?vue=fermes" : "";
  const initial = (name) => escapeHtml((String(name || "?").trim()[0] || "?").toUpperCase());
  const item = (t) => {
    const unread = t.status === "open" && t.unread;
    const dot = t.status !== "open" ? "off" : unread ? "new" : "";
    const sub = unread ? t.lastMessage || "Nouveau message" : t.reason || t.lastMessage || "Sans raison";
    return `<a class="td-item${ticket && ticket.id === t.id ? " on" : ""}${unread ? " unread" : ""}" href="/modo/tickets/${t.id}${q}">
      <span class="td-avatar" aria-hidden="true">${initial(t.owner)}</span>
      <span class="td-item-main">
        <span class="td-item-top"><span class="td-name">${escapeHtml(t.owner)}</span><span class="td-id">#${t.id}</span></span>
        <span class="td-sub"><span class="td-dot ${dot}"></span>${unread ? "<strong>Nouveau message</strong> · " : ""}${escapeHtml(sub)}</span>
      </span>
    </a>`;
  };
  const open = (tickets || []).filter((t) => t.status === "open");
  const fresh = open.filter((t) => t.unread);
  const ongoing = open.filter((t) => !t.unread);
  const closed = (tickets || []).filter((t) => t.status !== "open");
  const group = (label, list) => (list.length ? `<div class="td-group">${label} <b>${list.length}</b></div>${list.map(item).join("")}` : "");
  const listHtml = tickets === null
    ? `<p class="td-none">Tu n'as pas acces aux tickets (droit « Tickets » des groupes d'acces du planning).</p>`
    : closedTab
      ? group("Fermes", closed) || `<p class="td-none">Aucun ticket ferme.</p>`
      : group("Nouveaux messages", fresh) + group("En cours", ongoing) || `<p class="td-none">Aucun ticket ouvert. Les tickets ouverts sur le Discord (en MP) arrivent ici.</p>`;

  let pane = `<div class="td-empty"><span class="td-empty-icon">💬</span><strong>Aucun ticket ouvert</strong><span>Choisis un ticket dans la liste pour lire sa conversation.</span></div>`;
  if (data?.error && !ticket) {
    pane = `<div class="td-empty"><span class="td-empty-icon">⚠️</span><strong>Ticket indisponible</strong><span>${escapeHtml(data.error)}</span></div>`;
  }
  if (ticket) {
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const bubbles = messages
      .map((m) => {
        const images = (m.attachments || [])
          .filter((a) => /^https:\/\//.test(a.url || ""))
          .map((a) =>
            /^image\//.test(a.type || "")
              ? `<a href="${escapeHtml(a.url)}" target="_blank" rel="noreferrer"><img src="${escapeHtml(a.url)}" alt="" referrerpolicy="no-referrer" /></a>`
              : `<a href="${escapeHtml(a.url)}" target="_blank" rel="noreferrer">📎 ${escapeHtml(a.name || "piece jointe")}</a>`
          )
          .join("");
        const who = m.direction === "in" ? ticket.owner || "Membre" : m.direction === "out" ? `${m.author || "Equipe"} (equipe)` : "";
        return `<div class="mt-msg ${m.direction}">${escapeHtml(m.content)}${images}<small>${escapeHtml([who, modoDateTime(m.at)].filter(Boolean).join(" · "))}</small></div>`;
      })
      .join("");
    const ban = ticket.ban
      ? `<div class="message error">🚫 Banni des tickets (casier, fiche #${escapeHtml(String(ticket.ban.ficheId))}${
          ticket.ban.expiresInSeconds ? `, encore ${escapeHtml(String(Math.ceil(ticket.ban.expiresInSeconds / 3600)))} h` : ", definitif"
        })${ticket.ban.reason ? ` : ${escapeHtml(ticket.ban.reason)}` : ""}</div>`
      : "";
    const banForm = canReply && !ticket.ban
      ? `<details class="md-form">
          <summary>🚫 Bannir des tickets</summary>
          <form method="post" class="mt-reply" style="margin-top:8px;">
            <input type="text" name="reason" maxlength="500" placeholder="Motif (obligatoire)" required />
            <input type="text" name="duration" maxlength="12" placeholder="Duree : 30m, 12h, 7j, 2sem — vide = definitif" />
            <p class="md-hint">Inscrit au casier du membre, comme le ban tickets des salons Discord : il ne pourra plus ouvrir de ticket, ni en salon ni en MP. Le ticket est ferme.</p>
            <div class="mt-actions"><button type="submit" name="action" value="ban" class="danger">Bannir des tickets</button></div>
          </form>
        </details>`
      : "";
    pane = `
      <header class="td-head">
        <div class="td-head-main">
          <a class="td-back" href="/modo/tickets${q}">←</a>
          <span class="td-avatar" aria-hidden="true">${initial(ticket.owner)}</span>
          <div>
            <h2>${escapeHtml(ticket.owner)} <span class="td-id">#${ticket.id}</span> ${ticket.status === "open" ? `<span class="md-tag ok">Ouvert</span>` : `<span class="md-tag">Ferme${ticket.closedBy ? ` par ${escapeHtml(ticket.closedBy)}` : ""}</span>`}</h2>
            <p>${escapeHtml(ticket.reason || "Sans raison")} · ouvert le ${escapeHtml(modoDateTime(ticket.createdAt))} · echange en MP avec le bot</p>
          </div>
        </div>
        ${
          canReply
            ? `<form method="post">${ticket.status === "open" ? `<button type="submit" name="action" value="close" class="secondary">Fermer le ticket</button>` : `<button type="submit" name="action" value="reopen" class="secondary">Rouvrir le ticket</button>`}</form>`
            : ""
        }
      </header>
      <div class="td-body" id="td-body">
        ${renderMessages(flash)}
        ${data.error ? `<div class="message error">${escapeHtml(data.error)}</div>` : ""}
        ${ban}
        ${renderSlotOffer(doc, ticket, data.canDecide === true)}
        <div class="mt-chat">${bubbles || `<p class="md-empty">Pas encore de message.</p>`}</div>
        ${banForm}
      </div>
      ${
        canReply
          ? ticket.status === "open"
            ? `<form method="post" class="td-compose mt-reply">
                <textarea name="content" rows="3" maxlength="3500" placeholder="Ta reponse (envoyee en MP au membre, signee « l'equipe »)"></textarea>
                <div class="td-compose-row"><span class="md-hint">Le membre recoit ta reponse en MP.</span><button type="submit" name="action" value="reply">Envoyer</button></div>
              </form>`
            : ""
          : `<div class="td-compose"><p class="md-empty">Lecture seule : ton groupe peut lire les tickets, pas y repondre.</p></div>`
      }`;
  }

  const inner = `
    <style>${TICKET_DESK_CSS}</style>
    ${modoNav("tickets", live, rights)}
    ${!ticket ? renderMessages(flash) : ""}
    ${live.error ? `<div class="message error">rooky-tv : ${escapeHtml(live.error)}</div>` : ""}
    <section class="td${ticket || data?.error ? " has-ticket" : ""}">
      <aside class="td-list">
        ${
          live.rookyAdmin && Array.isArray(live.channels)
            ? `<form method="get" action="/modo/tickets" class="td-chan"><select name="chaine" aria-label="Chaine des tickets" onchange="this.form.submit()">
                <option value="">#${escapeHtml(doc.channel || "")} (ce site)</option>
                ${live.channels
                  .filter((c) => c.channel !== doc.channel)
                  .map((c) => `<option value="${escapeHtml(c.channel)}"${live.ticketChannel === c.channel ? " selected" : ""}>#${escapeHtml(c.channel)}${c.open ? ` (${Number(c.open)})` : ""}</option>`)
                  .join("")}
              </select><noscript><button type="submit">OK</button></noscript></form>`
            : ""
        }
        <nav class="td-tabs"><a href="/modo/tickets${ticket ? `/${ticket.id}` : ""}" class="${closedTab ? "" : "on"}">Ouverts${open.length ? ` (${open.length})` : ""}</a><a href="/modo/tickets${ticket ? `/${ticket.id}` : ""}?vue=fermes" class="${closedTab ? "on" : ""}">Fermes</a></nav>
        <div class="td-scroll">${listHtml}</div>
      </aside>
      <div class="td-pane">${pane}</div>
    </section>
    <script>
      (() => {
        // Conversation en bas ; nouveaux messages : rechargement tant que rien n'est en cours de saisie.
        const body = document.getElementById("td-body");
        if (body) body.scrollTop = body.scrollHeight;
        let touched = false;
        document.addEventListener("input", () => { touched = true; });
        document.addEventListener("change", () => { touched = true; });
        document.querySelectorAll(".td details").forEach((d) => d.addEventListener("toggle", () => { touched = true; }));
        setInterval(() => { if (!touched) location.reload(); }, ${ticket ? 20000 : 30000});
      })();
    </script>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage(ticket ? `Ticket #${ticket.id}` : "Tickets", modoShell(doc, viewer, inner), { wide: true }));
}

/* ------------------------- Groupes locaux (visibilite des tickets) ------------------------- */
// Une categorie (raison du ticket) cochee dans un groupe local devient reservee aux membres de ce(s)
// groupe(s). Une categorie qu'aucun groupe ne reserve reste visible par tous les modos (droit
// « Tickets » de rooky-tv), sans groupe. Le streamer, les admins (mot de passe ou rooky-tv) voient tout.

function readJsonFile(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function readModoGroups() {
  const raw = readJsonFile(MODO_GROUPS_FILE, []);
  return (Array.isArray(raw) ? raw : []).map((g) => ({
    id: String(g?.id || ""),
    name: String(g?.name || "Groupe"),
    reasons: Array.isArray(g?.reasons) ? g.reasons.map(String) : [],
    members: Array.isArray(g?.members) ? g.members.map(String) : [],
    // Role Discord lie (facultatif) : l'avoir sur le serveur = membre du groupe. N'en donne aucun.
    roles: Array.isArray(g?.roles) ? g.roles.map(String).filter((id) => /^\d{5,25}$/.test(id)) : []
  })).filter((g) => g.id);
}

function writeModoGroups(groups) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
  fs.writeFileSync(MODO_GROUPS_FILE, `${JSON.stringify(groups, null, 2)}\n`, "utf8");
}

function readModoUsers() {
  const raw = readJsonFile(MODO_USERS_FILE, []);
  return Array.isArray(raw) ? raw.filter((u) => /^\d{5,25}$/.test(String(u?.id || ""))) : [];
}

function rememberModoUser(claims) {
  if (!/^\d{5,25}$/.test(String(claims?.u || ""))) return;
  const users = readModoUsers().filter((u) => u.id !== claims.u);
  users.unshift({ id: claims.u, name: String(claims.n || "").slice(0, 60), role: claims.a ? "admin" : claims.r || "modo", lastAt: Date.now() });
  try {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
    fs.writeFileSync(MODO_USERS_FILE, `${JSON.stringify(users.slice(0, 300), null, 2)}\n`, "utf8");
  } catch {}
}

const ticketCategory = (ticket) => String(ticket?.reason || "").trim();

function canSeeTicket(viewer, live, ticket, doc) {
  if (viewer.admin || live?.seeAll) return true;
  // Tickets d'une autre chaine (admin seulement) : hors des groupes locaux de ce site.
  if (live?.ticketChannel && doc && live.ticketChannel !== doc.channel) return true;
  const category = ticketCategory(ticket);
  const groups = readModoGroups();
  const owners = groups.filter((g) => g.reasons.includes(category));
  if (!owners.length) return true;
  const roles = Array.isArray(live?.userRoles) ? live.userRoles.map(String) : [];
  return owners.some((g) => g.members.includes(String(viewer.u || "")) || g.roles.some((r) => roles.includes(r)));
}

function filterModoLive(live, viewer, doc) {
  if (Array.isArray(live?.tickets)) live.tickets = live.tickets.filter((t) => canSeeTicket(viewer, live, t, doc));
  return live;
}

// Personne connectee a l'administration : admin par Discord (avec son id) ou par mot de passe.
function adminViewer(req, doc) {
  const session = readModoSession(req, doc.channel);
  return session?.a === true ? { ...session, admin: true } : { n: "Admin", r: "admin", admin: true, password: true };
}

function renderAdminTickets(res, doc, viewer, meta, flash) {
  const groups = readModoGroups();
  const users = readModoUsers();
  const reasons = [...new Set([...(Array.isArray(meta.reasons) ? meta.reasons : []), ...groups.flatMap((g) => g.reasons)])];
  const reasonLabel = (r) => (r ? escapeHtml(r) : "<em>Sans raison</em>");
  const reservedBy = (r) => groups.filter((g) => g.reasons.includes(r)).map((g) => g.name);
  const groupCards = groups
    .map(
      (g) => `<form method="post" class="card ag-card">
        <input type="hidden" name="id" value="${escapeHtml(g.id)}" />
        <div class="ag-head"><input type="text" name="name" value="${escapeHtml(g.name)}" maxlength="40" aria-label="Nom du groupe" /></div>
        <div class="ag-cols">
          <fieldset><legend>Categories reservees a ce groupe</legend>
            ${
              reasons.length
                ? reasons.map((r) => `<label class="ag-check"><input type="checkbox" name="reason" value="${escapeHtml(r)}"${g.reasons.includes(r) ? " checked" : ""} /> ${reasonLabel(r)}</label>`).join("")
                : `<p class="ag-hint">Aucune categorie connue : ajoute des raisons dans « Questions ticket » sur bot.rooky.fr.</p>`
            }
          </fieldset>
          <fieldset><legend>Membres</legend>
            <label class="ag-role"><span>Role Discord lie (facultatif)</span>
              <select name="role">
                <option value="">Aucun role : membres coches a la main</option>
                ${(Array.isArray(meta.roles) ? meta.roles : [])
                  .filter((r) => r.name !== "@everyone")
                  .map((r) => `<option value="${escapeHtml(r.id)}"${g.roles.includes(String(r.id)) ? " selected" : ""}>@${escapeHtml(r.name)}</option>`)
                  .join("")}
                ${g.roles.length && !(meta.roles || []).some((r) => g.roles.includes(String(r.id))) ? `<option value="${escapeHtml(g.roles[0])}" selected>Role ${escapeHtml(g.roles[0])}</option>` : ""}
              </select>
            </label>
            <p class="ag-hint">Avec un role : toute personne qui l'a sur le serveur fait partie du groupe (verifie a chaque visite). Etre dans le groupe ne donne aucun role Discord.</p>
            ${
              users.length
                ? users.map((u) => `<label class="ag-check"><input type="checkbox" name="member" value="${escapeHtml(u.id)}"${g.members.includes(u.id) ? " checked" : ""} /> ${escapeHtml(u.name || u.id)} <small>${escapeHtml(u.role || "")}</small></label>`).join("")
                : `<p class="ag-hint">Aucun modo connecte pour l'instant : ils apparaissent ici apres leur premier « Acces modo ».</p>`
            }
          </fieldset>
        </div>
        <div class="ag-actions"><button type="submit" name="action" value="save">Enregistrer</button><button type="submit" name="action" value="delete" class="secondary danger">Supprimer</button></div>
      </form>`
    )
    .join("");
  const summary = reasons.length
    ? `<ul class="ag-summary">${reasons
        .map((r) => {
          const by = reservedBy(r);
          return `<li>${reasonLabel(r)} — ${by.length ? `reservee a <strong>${by.map(escapeHtml).join(", ")}</strong>` : "visible par tous les modos"}</li>`;
        })
        .join("")}</ul>`
    : "";
  const content = `
    <style>
      .ag { display: grid; gap: 16px; }
      .ag-card { display: grid; gap: 12px; }
      .ag-head input { font-weight: 700; font-size: 1.05rem; }
      .ag-cols { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
      .ag-cols fieldset { border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; display: grid; gap: 6px; align-content: start; max-height: 320px; overflow-y: auto; }
      .ag-cols legend { padding: 0 6px; font-weight: 600; font-size: 13px; color: var(--muted); }
      .ag-check { display: flex; gap: 8px; align-items: center; font-size: 14px; }
      .ag-check input { width: 18px; height: 18px; flex: 0 0 auto; margin: 0; }
      .ag-check small { color: var(--muted); }
      .ag-role { display: grid; gap: 4px; font-size: 13px; color: var(--muted); }
      .ag-hint { margin: 0; color: var(--muted); font-size: 13px; }
      .ag-actions { display: flex; gap: 8px; flex-wrap: wrap; }
      .ag-add { display: flex; gap: 8px; flex-wrap: wrap; }
      .ag-add input { flex: 1 1 220px; }
      .ag-summary { margin: 0; padding-left: 18px; display: grid; gap: 4px; font-size: 14px; }
    </style>
    <main class="ag">
      <section class="card">
        <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;">
          <h1 style="margin:0;">Tickets · groupes locaux</h1>
          <span style="display:flex;gap:8px;flex-wrap:wrap;"><a href="/admin" class="link-button secondary">Administration</a><a href="/modo/tickets" class="link-button secondary">Voir les tickets</a></span>
        </div>
        <p class="ag-hint" style="margin-top:8px;">Une categorie cochee dans un groupe est reservee a ses membres. Les categories qu'aucun groupe ne reserve restent visibles par tous les modos, sans groupe. Le streamer et les admins voient tout. Les droits « Tickets » de rooky-tv (voir / repondre) s'appliquent en plus.</p>
        ${renderMessages(flash)}
        ${meta.error ? `<div class="message error">rooky-tv : ${escapeHtml(meta.error)}</div>` : ""}
        ${summary}
        <p class="ag-hint" style="margin-top:8px;">Modos connectes (${users.length}) : ${users.length ? users.map((u) => escapeHtml(u.name || u.id)).join(", ") : "aucun pour l'instant — ils apparaissent apres leur premier « Acces modo »."}</p>
      </section>
      ${groupCards}
      <form method="post" class="card ag-add">
        <input type="text" name="name" maxlength="40" placeholder="Nom du nouveau groupe (ex. Collabs)" required />
        <button type="submit" name="action" value="add">Creer le groupe</button>
      </form>
    </main>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Tickets", content, { wide: true }));
}

/* ------------------------- Image du programme (Discord) ------------------------- */
// Le programme de la semaine dessine en image (meme grille que /planning) et publie par webhook dans
// un salon Discord. L'image suit le planning : a chaque programme recu de rooky-tv (et au changement
// de jour), le message est modifie sur place, sans notification. SVG -> PNG avec sharp (police
// DejaVu installee dans l'image Docker) ; jaquettes telechargees et integrees dans l'image.

const PLANNING_WEBHOOK = /^https:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+$/;
const IMG = {
  width: 1600,
  pad: 40,
  gap: 12,
  font: "DejaVu Sans, Segoe UI, Arial, sans-serif",
  bg: "#0b0d12",
  panel: "#161922",
  panelSoft: "#11141b",
  line: "#262b38",
  ink: "#eef0f5",
  muted: "#939aad",
  accent: "#6d5ef7",
  cyan: "#45e0d2",
  rose: "#ff6b87",
  danger: "#f0555f"
};

const svgText = (value) => escapeHtml(value);
// Pas d'emoji dans l'image (police sans emoji) ; pas de mise en forme Discord.
function imagePlain(value) {
  return String(value || "")
    .replace(/\\([*_~`|\\])/g, "$1")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/\*(.+?)\*/g, "$1")
    .replace(/[\p{Extended_Pictographic}\u{1F1E6}-\u{1F1FF}‍️⃣]/gu, "")
    .replace(/[ \t]+/g, " ")
    .trim();
}

// Decoupe en lignes d'apres une largeur moyenne de caractere (DejaVu Sans ~0,6 em).
function imageWrap(text, maxWidth, size, maxLines, ratio = 0.6) {
  const maxChars = Math.max(4, Math.floor(maxWidth / (size * ratio)));
  const lines = [];
  for (const paragraph of imagePlain(text).split("\n")) {
    let line = "";
    for (let word of paragraph.split(" ").filter(Boolean)) {
      while (word.length > maxChars) {
        if (line) {
          lines.push(line);
          line = "";
        }
        lines.push(word.slice(0, maxChars));
        word = word.slice(maxChars);
      }
      if (!line) {
        line = word;
      } else if (line.length + 1 + word.length <= maxChars) {
        line += ` ${word}`;
      } else {
        lines.push(line);
        line = word;
      }
    }
    if (line) {
      lines.push(line);
    }
  }
  if (lines.length > maxLines) {
    const kept = lines.slice(0, maxLines);
    kept[maxLines - 1] = `${kept[maxLines - 1].slice(0, Math.max(1, maxChars - 1))}…`;
    return kept;
  }
  return lines;
}

// Jaquettes telechargees pour l'image. Seules les reussites sont gardees : un echec (delai depasse,
// erreur passagere du CDN) n'est retenu que 5 min, sinon la jaquette manquait jusqu'au redemarrage.
const imageThumbCache = new Map();
const imageThumbFailed = new Map(); // url -> date de l'echec
const IMAGE_THUMB_RETRY_MS = 5 * 60_000;
async function fetchImageThumb(url) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(8000), headers: { "User-Agent": "Mozilla/5.0 (planning)" } });
      const type = res.headers.get("content-type") || "";
      if (res.ok && /^image\/(png|jpeg|webp|gif)/.test(type)) {
        return `data:${type.split(";")[0]};base64,${Buffer.from(await res.arrayBuffer()).toString("base64")}`;
      }
      if (res.status >= 400 && res.status < 500 && res.status !== 429) {
        return "";
      }
    } catch {
      // nouvelle tentative
    }
  }
  return "";
}
async function imageThumb(url) {
  if (!url) {
    return "";
  }
  if (imageThumbCache.has(url)) {
    return imageThumbCache.get(url);
  }
  if (Date.now() - (imageThumbFailed.get(url) || 0) < IMAGE_THUMB_RETRY_MS) {
    return "";
  }
  const data = await fetchImageThumb(url);
  if (!data) {
    imageThumbFailed.set(url, Date.now());
    return "";
  }
  imageThumbFailed.delete(url);
  if (imageThumbCache.size > 300) {
    imageThumbCache.clear();
  }
  imageThumbCache.set(url, data);
  return data;
}

function imagePill(x, y, label, fill, color) {
  const width = Math.round(label.length * 7.4 + 20);
  return {
    width,
    svg: `<rect x="${x}" y="${y}" width="${width}" height="24" rx="12" fill="${fill}"/><text x="${x + width / 2}" y="${y + 16.5}" font-size="12" font-weight="700" fill="${color}" text-anchor="middle" letter-spacing="0.6">${svgText(label)}</text>`
  };
}

// Ce que montre l'image : elle n'est regeneree / republiee que si ca change (ou au changement de jour).
function planningImageKey(doc) {
  const program = doc.program;
  return crypto
    .createHash("sha1")
    .update(JSON.stringify({ week: planningWeek(program).days, live: program?.live, schedule: program?.scheduleText, image: program?.imageUrl, channel: doc.channel }))
    .digest("hex");
}

// Vrai si la derniere image generee n'a pas pu recuperer toutes ses jaquettes : elle sera refaite.
let planningThumbsMissing = false;

async function buildPlanningSvg(doc) {
  const program = doc.program;
  const week = planningWeek(program);
  // Jaquettes telechargees en parallele (le dessin les relit ensuite dans le cache).
  const thumbUrls = [...new Set(week.days.flatMap((day) => (day.streams || []).flatMap((s) => (s.items || []).map((i) => i.thumbnail))).filter(Boolean))];
  const thumbResults = await Promise.all(thumbUrls.map((url) => imageThumb(url)));
  planningThumbsMissing = thumbResults.some((data) => !data);
  const { width, pad, gap } = IMG;
  const colW = (width - pad * 2 - gap * 6) / 7;
  const inner = colW - 28;
  const out = [];
  let defs = "";
  let clipId = 0;

  // En-tete
  const first = planningDayParts(week.monday);
  const last = planningDayParts(week.lastDay);
  const range = `Semaine du ${first.short.split(" ")[0]}${first.short.split(" ")[1] === last.short.split(" ")[1] ? "" : ` ${first.short.split(" ")[1]}`} au ${last.short}`;
  const scheduleLines = program?.scheduleText ? imageWrap(program.scheduleText, width - pad * 2 - 260, 20, 2, 0.55) : [];
  let y = pad;
  out.push(`<text x="${pad}" y="${y + 42}" font-size="42" font-weight="700" fill="${IMG.ink}">Programme de la semaine</text>`);
  out.push(
    `<text x="${pad}" y="${y + 78}" font-size="21" fill="${IMG.cyan}" font-weight="700">${svgText(doc.channel ? `twitch.tv/${doc.channel}` : "")}<tspan fill="${IMG.muted}" font-weight="400">${doc.channel ? "  ·  " : ""}${svgText(range)}</tspan></text>`
  );
  scheduleLines.forEach((line, i) => out.push(`<text x="${pad}" y="${y + 112 + i * 27}" font-size="20" fill="${IMG.muted}">${svgText(line)}</text>`));
  if (program?.live === true) {
    const pill = imagePill(0, 0, "EN DIRECT", "rgba(255,107,135,0.18)", IMG.rose);
    const px = width - pad - pill.width - 18;
    out.push(`<g transform="translate(${px},${y + 22})">${pill.svg.replace(`x="0"`, `x="0"`)}<circle cx="-12" cy="12" r="7" fill="${IMG.rose}"/></g>`);
  }
  y += 112 + Math.max(0, scheduleLines.length) * 27 + (scheduleLines.length ? 8 : -10);
  if (week.vacation) {
    out.push(`<rect x="${pad}" y="${y}" width="${width - pad * 2}" height="44" rx="12" fill="rgba(254,231,92,0.10)" stroke="rgba(254,231,92,0.35)"/>`);
    out.push(
      `<text x="${pad + 18}" y="${y + 28}" font-size="17" fill="#fee75c" font-weight="700">En vacances — retour le ${svgText(week.vacation.until.split("-").reverse().join("/"))}<tspan fill="${IMG.ink}" font-weight="400">${week.vacation.message ? `  ${svgText(imageWrap(week.vacation.message, width - 600, 17, 1)[0] || "")}` : ""}</tspan></text>`
    );
    y += 60;
  }
  const gridTop = y;

  // Colonnes : contenu a des positions relatives, hauteur commune = la plus haute.
  const columns = [];
  for (const day of week.days) {
    const parts = [];
    let cy = 0;
    parts.push({ y: cy + 24, svg: (ox, oy) => `<text x="${ox}" y="${oy}" font-size="19" font-weight="700" fill="${day.isToday ? IMG.accent : day.streams.length ? IMG.ink : IMG.muted}">${svgText(day.isToday ? "Aujourd'hui" : day.name)}</text>` });
    parts.push({ y: cy + 44, svg: (ox, oy) => `<text x="${ox}" y="${oy}" font-size="13" fill="${IMG.muted}">${svgText(day.short)}</text>` });
    cy += 60;
    if (!day.streams.length) {
      parts.push({ y: cy + 18, svg: (ox, oy) => `<text x="${ox}" y="${oy}" font-size="15" fill="${IMG.muted}" opacity="0.8">${svgText(day.emptyText)}</text>` });
      cy += 30;
    }
    for (const stream of day.streams) {
      const timeText = stream.time ? planningHour(stream.time) : "Heure a venir";
      const timeColor = day.isPast || stream.cancelled ? IMG.muted : IMG.cyan;
      parts.push({
        y: cy + 30,
        svg: (ox, oy) =>
          `<text x="${ox}" y="${oy}" font-size="30" font-weight="700" fill="${timeColor}">${svgText(timeText)}</text>` +
          (stream.cancelled ? `<line x1="${ox}" y1="${oy - 10}" x2="${ox + timeText.length * 18}" y2="${oy - 10}" stroke="${IMG.danger}" stroke-width="3"/>` : "")
      });
      cy += 42;
      const pills = [];
      if (day.isToday && program?.live === true && !stream.cancelled) pills.push(["EN DIRECT", "rgba(255,107,135,0.18)", IMG.rose]);
      if (stream.cancelled) pills.push(["ANNULE", "rgba(240,85,95,0.18)", IMG.danger]);
      if (stream.past && !stream.cancelled) pills.push(["TERMINE", "rgba(255,255,255,0.08)", IMG.muted]);
      if (stream.postponed) pills.push(["REPORTE", "rgba(255,255,255,0.08)", IMG.ink]);
      if (pills.length) {
        parts.push({
          y: cy,
          svg: (ox, oy) => {
            let px = ox;
            return pills
              .map(([label, fill, color]) => {
                const pill = imagePill(px, oy, label, fill, color);
                px += pill.width + 6;
                return pill.svg;
              })
              .join("");
          }
        });
        cy += 34;
      }
      if (stream.description && !stream.cancelled) {
        const lines = imageWrap(stream.description, inner, 14, 3);
        lines.forEach((line, i) => parts.push({ y: cy + 15 + i * 19, svg: (ox, oy) => `<text x="${ox}" y="${oy}" font-size="14" fill="${IMG.ink}">${svgText(line)}</text>` }));
        cy += lines.length * 19 + 10;
      }
      if (!stream.cancelled) {
        if (!stream.items.length && !stream.past) {
          parts.push({ y: cy + 15, svg: (ox, oy) => `<text x="${ox}" y="${oy}" font-size="14" font-style="italic" fill="${IMG.muted}">Programme bientot annonce</text>` });
          cy += 26;
        }
        for (const item of stream.items) {
          const thumb = await imageThumb(item.thumbnail);
          const subjectLines = imageWrap(item.subject, inner - 46, 14, 2);
          const meta = [item.time ? planningHour(item.time) : "", item.category].filter(Boolean).join(" · ");
          const metaLine = imageWrap(meta, inner - 46, 12, 1)[0] || "";
          const subjectColor = item.status === "current" ? IMG.rose : IMG.ink;
          const faded = item.status === "done" ? ` opacity="0.55"` : "";
          const id = `c${clipId++}`;
          const current = item.status === "current";
          const blockH = Math.max(48, subjectLines.length * 18 + (metaLine ? 18 : 0) + (current ? 17 : 0) + 4);
          parts.push({
            y: cy,
            svg: (ox, oy) => {
              defs += `<clipPath id="${id}"><rect x="${ox}" y="${oy}" width="36" height="48" rx="5"/></clipPath>`;
              const image = thumb
                ? `<image href="${thumb}" x="${ox}" y="${oy}" width="36" height="48" preserveAspectRatio="xMidYMid slice" clip-path="url(#${id})"/>`
                : `<rect x="${ox}" y="${oy}" width="36" height="48" rx="5" fill="rgba(255,255,255,0.06)"/>`;
              const tx = ox + 46;
              const subject = subjectLines
                .map((line, i) => `<text x="${tx}" y="${oy + 15 + i * 18}" font-size="14" font-weight="700" fill="${subjectColor}">${svgText(line)}</text>`)
                .join("");
              const metaY = oy + 15 + subjectLines.length * 18;
              const metaSvg = metaLine ? `<text x="${tx}" y="${metaY}" font-size="12" fill="${IMG.muted}">${svgText(metaLine)}</text>` : "";
              const currentSvg = current
                ? `<text x="${tx}" y="${metaY + (metaLine ? 17 : 0)}" font-size="12" font-weight="700" fill="${IMG.rose}">En cours</text>`
                : "";
              return `<g${faded}>${image}${subject}${metaSvg}${currentSvg}</g>`;
            }
          });
          cy += blockH + 10;
        }
      }
      cy += 8;
    }
    columns.push({ day, parts, height: cy });
  }
  const colH = Math.max(220, ...columns.map((c) => c.height + 20));
  columns.forEach((column, i) => {
    const x = pad + i * (colW + gap);
    const { day } = column;
    const stroke = day.isToday ? IMG.accent : day.streams.length && !day.isPast ? "rgba(69,224,210,0.45)" : IMG.line;
    out.push(
      `<g${day.isPast ? ` opacity="0.62"` : ""}><rect x="${x}" y="${gridTop}" width="${colW}" height="${colH}" rx="16" fill="${day.streams.length ? IMG.panel : IMG.panelSoft}" stroke="${stroke}" stroke-width="${day.isToday ? 2 : 1}"${
        day.streams.length || day.isToday ? "" : ` stroke-dasharray="6 5"`
      }/>${column.parts.map((part) => part.svg(x + 14, gridTop + 14 + part.y)).join("")}</g>`
    );
  });

  // Pied
  const footY = gridTop + colH + 34;
  const updated = doc.receivedAt
    ? `Mis a jour le ${new Date(doc.receivedAt).toLocaleString("fr-FR", { dateStyle: "long", timeStyle: "short", timeZone: PLANNING_PARIS })}`
    : "";
  out.push(`<text x="${pad}" y="${footY}" font-size="15" fill="${IMG.muted}">${svgText(updated)}</text>`);
  if (doc.siteUrl) {
    out.push(`<text x="${width - pad}" y="${footY}" font-size="15" fill="${IMG.muted}" text-anchor="end">${svgText(`${doc.siteUrl.replace(/^https?:\/\//, "")}/planning`)}</text>`);
  }
  const height = footY + pad - 10;

  return `<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" font-family="${IMG.font}">
<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#14112a"/><stop offset="0.45" stop-color="${IMG.bg}"/><stop offset="1" stop-color="#0c1512"/></linearGradient>${defs}</defs>
<rect width="${width}" height="${height}" fill="url(#bg)"/>
${out.join("\n")}
</svg>`;
}

async function renderPlanningImage(doc) {
  let sharp;
  try {
    sharp = require("sharp");
  } catch {
    throw new Error("La generation d'image n'est pas installee (module sharp) : redeploie le site.");
  }
  const svg = await buildPlanningSvg(doc);
  return sharp(Buffer.from(svg)).png({ compressionLevel: 9 }).toBuffer();
}

const planningImageThread = (url, threadId) => (threadId ? `${url}${url.includes("?") ? "&" : "?"}thread_id=${threadId}` : url);

async function planningImageCall(url, method, payload, png) {
  let body;
  let headers = {};
  if (png) {
    body = new FormData();
    body.append("payload_json", JSON.stringify(payload));
    body.append("files[0]", new Blob([png], { type: "image/png" }), "programme.png");
  } else if (payload) {
    body = JSON.stringify(payload);
    headers = { "Content-Type": "application/json" };
  }
  const res = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(20000) }).catch(() => null);
  const data = res ? await res.json().catch(() => null) : null;
  return { res, data };
}

function planningImageError(res, data) {
  if (!res) {
    return new Error("Discord ne repond pas.");
  }
  if (data?.code === 10015 || res.status === 401) {
    return new Error("Discord ne reconnait pas ce webhook : il a ete supprime ou son adresse est incomplete.");
  }
  return new Error(`Discord a refuse l'image (${res.status}${data?.message ? ` : ${data.message}` : ""}).`);
}

// Mention a la publication manuelle : "" (personne), "everyone", "here" ou l'id d'un role.
function planningImagePing(ping) {
  const value = String(ping || "").trim().replace(/^<@&(\d+)>$/, "$1").replace(/^@/, "");
  if (value === "everyone" || value === "here") {
    return { content: `@${value}`, allowed_mentions: { parse: ["everyone"] } };
  }
  if (/^\d{5,25}$/.test(value)) {
    return { content: `<@&${value}>`, allowed_mentions: { parse: [], roles: [value] } };
  }
  return { allowed_mentions: { parse: [] } };
}

// mode "new" : efface l'ancien message et en poste un nouveau (mention possible) ; "update" : modifie
// le message sur place sans notification (nouveau message s'il n'existe plus).
async function publishPlanningImage(doc, { mode = "update", ping = "" } = {}) {
  if (!doc.imageWebhookUrl) {
    throw new Error("Renseigne d'abord le webhook du salon.");
  }
  const png = await renderPlanningImage(doc);
  const message = {
    embeds: [
      {
        title: "Programme de la semaine",
        ...(doc.siteUrl ? { url: `${doc.siteUrl}/planning` } : {}),
        color: 0x6d5ef7,
        image: { url: "attachment://programme.png" }
      }
    ],
    attachments: [{ id: 0, filename: "programme.png" }]
  };
  let messageId = doc.imageMessageId;
  let threadId = doc.imageThreadId || "";

  // Bouton lien « Aller voir le planning » sous l'image (webhook : ?with_components=true). Refuse par
  // Discord (formulaire invalide) : l'image part sans le bouton.
  const button = /^https?:\/\/\S+$/.test(doc.siteUrl || "")
    ? [{ type: 1, components: [{ type: 2, style: 5, label: "Aller voir le planning", url: `${doc.siteUrl}/planning` }] }]
    : null;
  const withComponents = (url) => `${url}${url.includes("?") ? "&" : "?"}with_components=true`;
  const call = async (url, method, payload) => {
    if (button) {
      const first = await planningImageCall(withComponents(url), method, { ...payload, components: button }, png);
      const rejected = first.res && first.res.status === 400 && ![220001, 10003].includes(first.data?.code);
      if (!rejected) {
        return first;
      }
      console.error(`[planning] bouton refuse par Discord : ${first.data?.message || first.res.status}`);
    }
    return planningImageCall(url, method, { ...payload, components: [] }, png);
  };

  if (mode === "update" && messageId) {
    const { res, data } = await call(
      planningImageThread(`${doc.imageWebhookUrl}/messages/${messageId}`, threadId),
      "PATCH",
      { ...message, allowed_mentions: { parse: [] } }
    );
    if (res?.ok) {
      return { messageId, threadId, edited: true };
    }
    if (!(res && res.status === 404)) {
      throw planningImageError(res, data);
    }
    messageId = ""; // supprime a la main : on en reposte un
  }
  if (mode === "new" && messageId) {
    await planningImageCall(planningImageThread(`${doc.imageWebhookUrl}/messages/${messageId}`, threadId), "DELETE");
  }
  const payload = { ...message, ...(mode === "new" ? planningImagePing(ping) : { allowed_mentions: { parse: [] } }) };
  const base = `${doc.imageWebhookUrl}?wait=true`;
  let { res, data } = await call(planningImageThread(base, threadId), "POST", payload);
  // Salon forum : Discord exige un post (220001), ou le post connu a ete supprime (10003).
  if (res && !res.ok && (data?.code === 220001 || (threadId && data?.code === 10003))) {
    ({ res, data } = await call(base, "POST", { ...payload, thread_name: "Programme de la semaine" }));
    threadId = res?.ok && data?.channel_id ? String(data.channel_id) : "";
  }
  if (!res || !res.ok) {
    throw planningImageError(res, data);
  }
  return { messageId: data?.id ? String(data.id) : "", threadId, edited: false };
}

// Nom du webhook sur Discord : le renomme s'il porte un autre nom que celui choisi (vide = garder le
// sien). Renvoie le nom actuel.
async function planningEnsureWebhookName(url, wanted) {
  const res = await fetch(url, { signal: AbortSignal.timeout(10000) }).catch(() => null);
  if (!res || !res.ok) {
    if (res && (res.status === 401 || res.status === 404)) {
      throw new Error("Discord ne reconnait pas ce webhook : il a ete supprime ou son adresse est incomplete.");
    }
    throw new Error(`Discord ne repond pas pour ce webhook${res ? ` (${res.status})` : ""}.`);
  }
  const info = await res.json().catch(() => ({}));
  const name = String(wanted || "").trim();
  if (!name || info.name === name) {
    return String(info.name || "");
  }
  const renamed = await fetch(url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
    signal: AbortSignal.timeout(10000)
  }).catch(() => null);
  if (!renamed || !renamed.ok) {
    const data = renamed ? await renamed.json().catch(() => null) : null;
    throw new Error(`Discord a refuse de renommer le webhook${renamed ? ` (${renamed.status}${data?.message ? ` : ${data.message}` : ""})` : ""}.`);
  }
  return name;
}

// Une publication a la fois. mode "auto" : seulement si l'image a change (programme recu, nouveau jour).
let planningImageQueue = Promise.resolve();
function queuePlanningImage(mode = "auto", options = {}) {
  const run = planningImageQueue.catch(() => {}).then(async () => {
    const channel = planningSiteChannel();
    if (!channel) {
      return null;
    }
    const doc = readPlanning(channel);
    if (!doc.imageWebhookUrl) {
      return null;
    }
    try {
      // Nom du webhook remis a jour a chaque fois (renomme sur Discord si besoin).
      const webhookName = await planningEnsureWebhookName(doc.imageWebhookUrl, doc.imageWebhookName);
      // Un message garde le nom qu'il avait a sa publication : nom change -> nouveau message.
      const renamed = !!doc.imageMessageId && webhookName !== doc.imagePostedName;
      const key = planningImageKey(doc);
      if (mode === "auto" && doc.imageMessageId && doc.imageKey === key && !renamed) {
        if (webhookName !== doc.imageWebhookName) {
          writePlanning({ ...readPlanning(channel), imageWebhookName: webhookName });
        }
        return null;
      }
      const result = await publishPlanningImage(doc, { mode: mode === "new" || renamed ? "new" : "update", ping: mode === "new" ? options.ping : "" });
      writePlanning({
        ...readPlanning(channel),
        imageWebhookName: webhookName,
        imagePostedName: webhookName,
        imageMessageId: result.messageId,
        imageThreadId: result.threadId,
        // Jaquette manquante : cle differente -> l'image est refaite au prochain passage automatique.
        imageKey: planningThumbsMissing ? `${key}|jaquettes` : key,
        imagePublishedAt: Date.now(),
        imageError: ""
      });
      return result;
    } catch (error) {
      console.error(`[planning:${channel}] image : ${error.message}`);
      writePlanning({ ...readPlanning(channel), imageError: error.message });
      if (mode !== "auto") {
        throw error;
      }
      return null;
    }
  });
  planningImageQueue = run;
  return run;
}

function renderPlanning(res, doc, flash, origin) {
  const messages = renderMessages(flash);
  const code = doc.channel && doc.syncKey ? `${origin}/api/planning/sync#${doc.syncKey}` : "";
  const received = doc.receivedAt
    ? new Date(doc.receivedAt).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: PLANNING_PARIS })
    : "";
  const today = planningToday();
  const lastDay = planningAddDays(today, 6);
  const upcoming = (doc.program?.days || []).filter((day) => day.date >= today && day.date <= lastDay);

  const content = `
    <style>
      .planning-steps { margin: 0; padding-left: 20px; color: var(--muted); line-height: 1.8; }
      .planning-steps strong { color: var(--ink); }
      .planning-code { display: flex; gap: 8px; }
      .planning-code input { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
      .planning-hint { font-size: 13px; color: var(--muted); margin: 0; }
      .planning-state { display: grid; gap: 6px; font-size: 14px; color: var(--muted); }
      .planning-state strong { color: var(--ink); }
      .planning-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    </style>
    <header class="topbar">
      <div>
        <h1>Planning</h1>
        <p>Affiche le programme du stream de rooky-tv sur la page publique <a href="/planning" target="_blank" rel="noreferrer">/planning</a>.</p>
      </div>
      <div class="topbar-actions">
        <a href="/admin" class="link-button secondary">Redirections</a>
        <a href="/admin/stats" class="link-button secondary">Statistiques</a>
        <a href="/admin/site" class="link-button secondary">Personnalisation</a>
        <a href="/admin/monitoring" class="link-button secondary">Monitoring</a>
        <a href="/logout" class="link-button">Deconnexion</a>
      </div>
    </header>
    ${messages}
    <section class="card">
      <h2>Comment ca marche</h2>
      <ol class="planning-steps">
        <li>Indique la <strong>chaine Twitch</strong> de ce site et enregistre.</li>
        <li>Copie le <strong>code de liaison</strong> ci-dessous.</li>
        <li>Sur <strong>rooky-tv</strong> : Programme &rarr; Programme sur Discord &rarr; <strong>Sites redirection</strong>, colle le code puis \u00ab Relier \u00bb.</li>
        <li>Le programme s'affiche sur <a href="/planning" target="_blank" rel="noreferrer">/planning</a> et se met a jour a chaque changement sur rooky-tv.</li>
      </ol>
    </section>
    <form method="post" action="/admin/planning" class="card">
      <h2>Liaison</h2>
      <div class="form-grid">
        <label>
          <span>Chaine Twitch de ce site</span>
          <input type="text" name="channel" value="${escapeHtml(doc.channel)}" placeholder="ex : rooky" required />
        </label>
        ${
          code
            ? `<label>
                <span>Code de liaison (a coller dans rooky-tv, a garder pour toi)</span>
                <div class="planning-code">
                  <input type="text" id="planning-code" value="${escapeHtml(code)}" readonly />
                  <button type="button" class="secondary" id="planning-copy">Copier</button>
                </div>
              </label>`
            : ""
        }
        <div class="planning-actions">
          <button type="submit" name="action" value="save">Enregistrer</button>
          ${
            code
              ? `<button type="submit" name="action" value="newkey" class="secondary" onclick="return confirm('L\\'ancien code ne marchera plus : il faudra recoller le nouveau dans rooky-tv. Continuer ?')">Nouveau code</button>`
              : ""
          }
        </div>
      </div>
    </form>
    ${
      doc.channel
        ? `<form method="post" action="/admin/planning/image" class="card">
      <h2>Image sur Discord</h2>
      <p class="planning-hint" style="margin-bottom:14px;">Le programme de la semaine en image, publie par webhook dans un salon Discord. L'image <strong>suit le planning toute seule</strong> : a chaque changement sur rooky-tv (et chaque nouveau jour), le message est mis a jour sur place, sans notification.</p>
      <div class="form-grid">
        <label>
          <span>Webhook du salon ${doc.imageWebhookUrl ? "(enregistre ✔, vide = le garder)" : ""}</span>
          <input type="password" name="webhookUrl" autocomplete="off" placeholder="https://discord.com/api/webhooks/..." />
        </label>
        <label>
          <span>Nom du webhook sur Discord (vide = garder son nom actuel)</span>
          <input type="text" name="webhookName" value="${escapeHtml(doc.imageWebhookName)}" maxlength="80" placeholder="Nom du webhook" />
        </label>
        <label>
          <span>Mentionner quand tu cliques sur Republier (optionnel)</span>
          <input type="text" name="ping" placeholder="everyone, here ou ID d'un role" />
        </label>
        <div class="planning-actions">
          <button type="submit" name="action" value="save">${doc.imageWebhookUrl ? "Enregistrer" : "Enregistrer et publier"}</button>
          ${
            doc.imageWebhookUrl
              ? `<button type="submit" name="action" value="publish" class="secondary">Republier (nouveau message)</button>
                 <button type="submit" name="action" value="remove" class="danger" formnovalidate onclick="return confirm('Retirer le webhook et effacer l\\'image du salon ?')">Retirer</button>`
              : ""
          }
        </div>
        <div class="planning-state">
          <div>${
            doc.imageError
              ? `<span class="status-missing">Derniere publication en echec : ${escapeHtml(doc.imageError)}</span>`
              : doc.imagePublishedAt
                ? `<strong>Image a jour</strong> le ${escapeHtml(new Date(doc.imagePublishedAt).toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short", timeZone: PLANNING_PARIS }))}`
                : "Pas encore publiee."
          }</div>
        </div>
        <details>
          <summary style="cursor:pointer;color:var(--muted);">Apercu de l'image</summary>
          <img src="/admin/planning/image.png?t=${Date.now()}" alt="Apercu du programme" loading="lazy" style="width:100%;margin-top:12px;border-radius:12px;border:1px solid var(--line);" />
        </details>
      </div>
    </form>`
        : ""
    }
    <section class="card">
      <h2>Etat</h2>
      <div class="planning-state">
        <div>${received ? `<strong>Dernier programme recu</strong> le ${escapeHtml(received)}` : "Aucun programme recu pour l'instant."}</div>
        ${
          upcoming.length
            ? `<div>${escapeHtml(
                `${upcoming.length} stream${upcoming.length > 1 ? "s" : ""} cette semaine : ${upcoming
                  .map((day) => `${planningDayParts(day.date).name} ${day.time ? planningHour(day.time) : ""}${day.cancelled ? " (annule)" : ""}`.trim())
                  .join(" \u00b7 ")}`
              )}</div>`
            : doc.receivedAt
              ? "<div>Aucun stream prevu dans les 7 prochains jours.</div>"
              : ""
        }
      </div>
    </section>
    <script>
      (function () {
        var button = document.getElementById("planning-copy");
        if (!button) return;
        button.addEventListener("click", function () {
          var input = document.getElementById("planning-code");
          input.select();
          var done = function () { button.textContent = "Copie !"; setTimeout(function () { button.textContent = "Copier"; }, 1500); };
          if (navigator.clipboard) navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand("copy"); done(); });
          else { document.execCommand("copy"); done(); }
        });
      })();
    </script>
  `;

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(renderPage("Planning", content));
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
      ${
        // Bouton vers la page publique du programme, des que le site a une chaine (page Planning).
        planningSiteChannel()
          ? `<a href="/planning" class="link-button" style="position:relative;display:flex;width:100%;margin:18px 0 6px;padding:14px 18px;font-weight:700;gap:8px;">📅 Programme de la semaine</a>`
          : ""
      }
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
        .warning {
          background: #fee75c;
          color: #4a3b00;
        }
        .warning:hover {
          background: #f5d942;
        }
        .warning-large {
          padding: 16px 24px;
          font-size: 1.05rem;
          font-weight: 700;
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
