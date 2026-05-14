require("events").EventEmitter.defaultMaxListeners = 50;

const crypto = require("crypto");
const fs = require("fs-extra");
const path = require("path");
const zlib = require("zlib");
const axios = require("axios");
const express = require("express");
const pino = require("pino");
const NodeCache = require("node-cache");
const Database = require("better-sqlite3");
const {
    default: giftedConnect,
    fetchLatestWaWebVersion,
    makeCacheableSignalKeyStore,
    initAuthCreds,
    BufferJSON,
    DisconnectReason,
} = require("gifted-baileys");
const { Boom } = require("@hapi/boom");
const config = require("./config");

const PORT = process.env.PORT || 5000;
const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RECONNECT_DELAY_MS = 5000;
const MAX_RECONNECT_ATTEMPTS = 50;
const sessionDir = path.join(__dirname, "gift", "session");
const sessionDbPath = path.join(sessionDir, "session.db");
const credsPath = path.join(sessionDir, "creds.json");

const app = express();
const logger = pino({ level: "silent" });
const userDevicesCache = new NodeCache({ stdTTL: 1800, useClones: false });
const otpStore = new Map();

let Gifted;
let reconnectAttempts = 0;
let isWhatsAppOnline = false;

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function normalizePhoneNumber(input) {
    const number = String(input || "").replace(/[^0-9]/g, "");
    if (number.length < 8 || number.length > 15) {
        throw new Error("Please provide a valid WhatsApp number with country code.");
    }
    return number;
}

function makeOtp() {
    return crypto.randomInt(100000, 1000000).toString();
}

function otpMessage(otp) {
    return `🌸 *Your OTP is: ${otp}*\n\n⏳ Expires in 5 minutes.\n⚠️ Never share this code with anyone.`;
}

function renderOtpPage(number, otp) {
    const safeNumber = escapeHtml(number);
    const safeOtp = escapeHtml(otp);

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OTP Sent</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #fff7fb; color: #24131d; display: grid; min-height: 100vh; place-items: center; margin: 0; }
    main { width: min(92vw, 440px); background: white; border: 1px solid #ffd6e8; border-radius: 24px; box-shadow: 0 18px 50px rgba(214, 51, 132, .16); padding: 32px; text-align: center; }
    .flower { font-size: 40px; }
    h1 { margin: 12px 0 6px; font-size: 28px; }
    p { color: #6f5262; line-height: 1.5; }
    .otp { letter-spacing: .18em; font-size: 38px; font-weight: 800; background: #fff0f7; border: 1px dashed #ff8fc4; border-radius: 18px; padding: 18px; margin: 22px 0; color: #c2185b; }
    button { border: 0; border-radius: 999px; padding: 14px 22px; font-size: 16px; font-weight: 700; color: white; background: linear-gradient(135deg, #ec4899, #be185d); cursor: pointer; }
    button:active { transform: translateY(1px); }
    .meta { font-size: 14px; }
  </style>
</head>
<body>
  <main>
    <div class="flower">🌸</div>
    <h1>OTP sent</h1>
    <p>WhatsApp OTP has been sent to <strong>${safeNumber}</strong>.</p>
    <div id="otp" class="otp">${safeOtp}</div>
    <button type="button" onclick="copyOtp()">Copy OTP</button>
    <p id="copyStatus" class="meta">⏳ Expires in 5 minutes.</p>
  </main>
  <script>
    async function copyOtp() {
      const otp = document.getElementById('otp').textContent.trim();
      await navigator.clipboard.writeText(otp);
      document.getElementById('copyStatus').textContent = '✅ OTP copied.';
    }
  </script>
</body>
</html>`;
}

async function loadSession() {
    if (!config.SESSION_ID || typeof config.SESSION_ID !== "string") {
        throw new Error("SESSION_ID is missing or invalid.");
    }

    await fs.ensureDir(sessionDir);
    const sessionFiles = await fs.readdir(sessionDir).catch(() => []);
    await Promise.all(
        sessionFiles.map((file) => fs.remove(path.join(sessionDir, file)).catch(() => {})),
    );

    let sessionId = config.SESSION_ID.trim();
    const [headerCheck, b64Check] = sessionId.split("~");
    if (headerCheck !== "Gifted" || !b64Check) {
        throw new Error("Invalid session format. Expected 'Gifted~.....'.");
    }

    if (!b64Check.startsWith("H4sI")) {
        const serverUrl = `https://session.giftedtech.co.ke/session/${b64Check}`;
        const response = await axios.get(serverUrl, { timeout: 15000 });
        sessionId = String(response.data || "").trim();
    }

    const [header, b64data] = sessionId.split("~");
    if (header !== "Gifted" || !b64data) {
        throw new Error("Session server returned invalid data.");
    }

    const compressedData = Buffer.from(b64data.replace("...", ""), "base64");
    const decompressedData = zlib.gunzipSync(compressedData);
    await fs.writeFile(credsPath, decompressedData, "utf8");
    console.log("✅ Session loaded");
}

function useSQLiteAuthState(databasePath) {
    fs.ensureDirSync(path.dirname(databasePath));

    const db = new Database(databasePath);
    db.pragma("journal_mode = WAL");
    db.exec(`CREATE TABLE IF NOT EXISTS session (id TEXT PRIMARY KEY, value TEXT)`);

    const readData = (id) => {
        const row = db.prepare("SELECT value FROM session WHERE id = ?").get(id);
        return row ? JSON.parse(row.value, BufferJSON.reviver) : null;
    };

    const writeData = (id, value) => {
        db.prepare("INSERT OR REPLACE INTO session (id, value) VALUES (?, ?)").run(
            id,
            JSON.stringify(value, BufferJSON.replacer),
        );
    };

    const removeData = (id) => {
        db.prepare("DELETE FROM session WHERE id = ?").run(id);
    };

    if (fs.existsSync(credsPath)) {
        const credsData = fs.readFileSync(credsPath, "utf8");
        writeData("creds", JSON.parse(credsData, BufferJSON.reviver));
        fs.removeSync(credsPath);
    }

    const creds = readData("creds") || initAuthCreds();

    return {
        state: {
            creds,
            keys: {
                get: async (type, ids) => {
                    const data = {};
                    for (const id of ids) {
                        const value = readData(`${type}-${id}`);
                        if (value) data[id] = value;
                    }
                    return data;
                },
                set: async (data) => {
                    for (const category in data) {
                        for (const id in data[category]) {
                            const key = `${category}-${id}`;
                            const value = data[category][id];
                            if (value) writeData(key, value);
                            else removeData(key);
                        }
                    }
                },
            },
        },
        saveCreds: () => writeData("creds", creds),
        close: () => db.close(),
    };
}

function createSocketConfig(version, state) {
    return {
        version,
        logger,
        browser: ["Ubuntu", "Chrome", "22.04.4"],
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, logger),
        },
        userDevicesCache,
        connectTimeoutMs: 15000,
        defaultQueryTimeoutMs: 20000,
        keepAliveIntervalMs: 20000,
        fireInitQueries: false,
        markOnlineOnConnect: true,
        syncFullHistory: false,
        shouldSyncHistoryMessage: () => false,
        retryRequestDelayMs: 50,
        maxMsgRetryCount: 2,
        getMessage: async () => undefined,
        emitOwnEvents: true,
    };
}

async function sendOtp(number, otp) {
    if (!Gifted || !isWhatsAppOnline) {
        throw new Error("WhatsApp session is not connected yet. Please try again shortly.");
    }

    await Gifted.sendMessage(`${number}@s.whatsapp.net`, { text: otpMessage(otp) });
}

function scheduleReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.error("Max reconnection attempts reached. Exiting...");
        process.exit(1);
    }

    reconnectAttempts += 1;
    const delay = Math.min(RECONNECT_DELAY_MS * 2 ** (reconnectAttempts - 1), 300000);
    console.log(`🕗 Reconnection attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} in ${delay}ms...`);
    setTimeout(() => startWhatsApp().catch((error) => console.error("Reconnect failed:", error)), delay);
}

async function startWhatsApp() {
    const { version } = await fetchLatestWaWebVersion();
    const { state, saveCreds } = useSQLiteAuthState(sessionDbPath);

    Gifted = giftedConnect(createSocketConfig(version, state));

    Gifted.ev.process(async (events) => {
        if (events["creds.update"]) saveCreds();
    });

    Gifted.ev.on("connection.update", async (update) => {
        const { connection, lastDisconnect } = update;

        if (connection === "connecting") {
            console.log("🕗 Connecting WhatsApp session...");
        }

        if (connection === "open") {
            isWhatsAppOnline = true;
            reconnectAttempts = 0;
            console.log("✅ WhatsApp OTP API is online");
        }

        if (connection === "close") {
            isWhatsAppOnline = false;
            const reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
            console.log(`Connection closed due to: ${reason}`);

            if (
                reason === DisconnectReason.badSession ||
                reason === DisconnectReason.connectionReplaced ||
                reason === DisconnectReason.loggedOut
            ) {
                await fs.remove(sessionDir).catch(() => {});
                console.error("Session is invalid or logged out. Add a fresh SESSION_ID and restart.");
                process.exit(1);
            }

            scheduleReconnect();
        }
    });
}

app.get("/", (req, res) => {
    res.type("html").send(`<!doctype html><html><head><title>OTP API</title></head><body><h1>WhatsApp OTP API</h1><p>Use <code>/num=COUNTRY_CODE_NUMBER</code> to send an OTP.</p></body></html>`);
});

app.get("/health", (req, res) => {
    res.status(200).json({
        status: "alive",
        whatsapp: isWhatsAppOnline ? "connected" : "connecting",
        uptime: process.uptime(),
    });
});

app.get(/^\/num=(.+)$/, async (req, res) => {
    try {
        const number = normalizePhoneNumber(req.params[0]);
        const otp = makeOtp();
        const expiresAt = Date.now() + OTP_EXPIRY_MS;

        otpStore.set(number, { otp, expiresAt });
        setTimeout(() => {
            const saved = otpStore.get(number);
            if (saved?.otp === otp) otpStore.delete(number);
        }, OTP_EXPIRY_MS).unref();

        await sendOtp(number, otp);

        const wantsJson = req.query.format === "json" || /application\/json/i.test(req.get("accept") || "");
        if (!wantsJson) {
            return res.type("html").send(renderOtpPage(number, otp));
        }

        return res.status(200).json({
            success: true,
            number,
            otp,
            expiresInSeconds: OTP_EXPIRY_MS / 1000,
            message: "OTP sent on WhatsApp.",
        });
    } catch (error) {
        return res.status(400).json({ success: false, error: error.message });
    }
});

app.get("/verify", (req, res) => {
    try {
        const number = normalizePhoneNumber(req.query.num || req.query.number);
        const otp = String(req.query.otp || "").trim();
        const saved = otpStore.get(number);

        if (!saved || saved.expiresAt < Date.now()) {
            otpStore.delete(number);
            return res.status(400).json({ success: false, verified: false, error: "OTP expired or not found." });
        }

        if (saved.otp !== otp) {
            return res.status(400).json({ success: false, verified: false, error: "Invalid OTP." });
        }

        otpStore.delete(number);
        return res.status(200).json({ success: true, verified: true, message: "OTP verified." });
    } catch (error) {
        return res.status(400).json({ success: false, verified: false, error: error.message });
    }
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));

setInterval(() => {
    const used = process.memoryUsage();
    if (used.heapUsed > 400 * 1024 * 1024 && global.gc) global.gc();
}, 60000);

(async () => {
    try {
        await loadSession();
        await startWhatsApp();
    } catch (error) {
        console.error("Startup error:", error.message);
        process.exit(1);
    }
})();
