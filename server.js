const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, "data");
const REDIRECTS_FILE = path.join(DATA_DIR, "redirects.json");

loadEnv(path.join(ROOT_DIR, ".env"));

const PORT = Number(process.env.PORT || 3000);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-moi";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-moi-aussi";
const sessions = new Map();

ensureDataFile();

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = normalizeRoute(url.pathname);
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
        setCookie(res, "session", signToken(token), { httpOnly: true });
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
      return renderAdmin(res, redirects, getFlashMessage(url));
    }

    if (pathname === "/admin/redirects" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const source = normalizeRoute(form.source || "");
      const target = (form.target || "").trim();

      const error = validateRedirectInput(source, target);
      if (error) {
        redirect(res, `/admin?error=${encodeURIComponent(error)}`);
        return;
      }

      const redirects = readRedirects().filter((item) => item.source !== source);
      redirects.push({
        source,
        target,
        code: 301,
        updatedAt: new Date().toISOString()
      });
      redirects.sort((a, b) => a.source.localeCompare(b.source));
      writeRedirects(redirects);
      redirect(res, "/admin?success=Redirection%20enregistree");
      return;
    }

    if (pathname === "/admin/redirects/delete" && method === "POST") {
      if (!isAuthenticated(req)) {
        redirect(res, "/login");
        return;
      }

      const form = await parseForm(req);
      const source = normalizeRoute(form.source || "");
      const redirects = readRedirects().filter((item) => item.source !== source);
      writeRedirects(redirects);
      redirect(res, "/admin?success=Redirection%20supprimee");
      return;
    }

    const match = readRedirects().find((item) => item.source === pathname);
    if (match) {
      res.writeHead(301, { Location: match.target });
      res.end();
      return;
    }

    renderNotFound(res, pathname);
  } catch (error) {
    res.writeHead(500, { "Content-Type": "text/html; charset=utf-8" });
    res.end(renderPage("Erreur", `<p>Erreur interne: ${escapeHtml(error.message)}</p>`));
  }
});

server.listen(PORT, () => {
  console.log(`Application disponible sur http://localhost:${PORT}`);
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
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(REDIRECTS_FILE)) {
    fs.writeFileSync(REDIRECTS_FILE, "[]\n", "utf8");
  }
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

function normalizeRoute(input) {
  const trimmed = (input || "").trim();
  if (!trimmed || trimmed === "/") {
    return "/";
  }

  const withoutDomain = trimmed.replace(/^https?:\/\/[^/]+/i, "");
  const withLeadingSlash = withoutDomain.startsWith("/") ? withoutDomain : `/${withoutDomain}`;
  return withLeadingSlash.replace(/\/+$/, "") || "/";
}

function validateRedirectInput(source, target) {
  if (!source) {
    return "Le chemin source est requis.";
  }

  if (source === "/admin" || source.startsWith("/admin/") || source === "/login" || source === "/logout") {
    return "Ce chemin est reserve a l'administration.";
  }

  try {
    const parsed = new URL(target);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return "La cible doit utiliser http ou https.";
    }

    if (isLocalTarget(parsed)) {
      return "La cible doit etre un site externe.";
    }
  } catch {
    return "La cible doit etre une URL absolue valide.";
  }

  return "";
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
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`);
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

function renderAdmin(res, redirects, flash) {
  const messages = renderMessages(flash);
  const rows = redirects.length
    ? redirects
        .map(
          (item) => `
            <tr>
              <td><code>${escapeHtml(item.source)}</code></td>
              <td><a href="${escapeHtml(item.target)}" target="_blank" rel="noreferrer">${escapeHtml(item.target)}</a></td>
              <td>${item.code}</td>
              <td>
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
        <p>Ajoutez une source, une cible, et l'application renverra un code 301.</p>
      </div>
      <a href="/logout" class="link-button">Deconnexion</a>
    </header>
    ${messages}
    <section class="card">
      <h2>Nouvelle redirection</h2>
      <form method="post" action="/admin/redirects" class="form-grid">
        <label>
          <span>URL souhaitee</span>
          <input type="text" name="source" placeholder="/mon-chemin" required />
        </label>
        <label>
          <span>Cible externe</span>
          <input type="url" name="target" placeholder="https://exemple.com/page" required />
        </label>
        <label>
          <span>Code</span>
          <input type="text" value="301" disabled />
        </label>
        <button type="submit">Enregistrer</button>
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

function renderNotFound(res, pathname) {
  res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
  res.end(
    renderPage(
      "Non trouve",
      `
        <section class="card auth-card">
          <h1>404</h1>
          <p>Aucune redirection definie pour <code>${escapeHtml(pathname)}</code>.</p>
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
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

