```js
const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = process.env.PORT || 3000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DISCORD_REDIRECT_URI ||
    !SESSION_SECRET
) {
    console.error("Missing required environment variables.");
    process.exit(1);
}

/* =========================================================
   RENDER / PROXY
========================================================= */

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================================================
   SESSION
========================================================= */

app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 1000 * 60 * 60 * 24
        }
    })
);

/* =========================================================
   LOG DIRECTORY
========================================================= */

const logsDirectory = path.join(__dirname, "logs");
const loginLogsFile = path.join(logsDirectory, "login-logs.json");

if (!fs.existsSync(logsDirectory)) {
    fs.mkdirSync(logsDirectory, {
        recursive: true
    });
}

if (!fs.existsSync(loginLogsFile)) {
    fs.writeFileSync(loginLogsFile, "[]", "utf8");
}

/* =========================================================
   IP
========================================================= */

function getClientIP(req) {
    const forwarded = req.headers["x-forwarded-for"];

    if (forwarded) {
        return forwarded.split(",")[0].trim();
    }

    return (
        req.headers["x-real-ip"] ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}

/* =========================================================
   LOGGING
========================================================= */

function saveLoginLog(user, req) {
    let logs = [];

    try {
        logs = JSON.parse(
            fs.readFileSync(loginLogsFile, "utf8")
        );

        if (!Array.isArray(logs)) {
            logs = [];
        }
    } catch {
        logs = [];
    }

    const entry = {
        id: Date.now().toString(),

        discord: {
            id: user.id,
            username: user.username,
            globalName: user.global_name || null,
            email: user.email || null
        },

        ip: getClientIP(req),

        userAgent:
            req.headers["user-agent"] || "unknown",

        browserLanguage:
            req.headers["accept-language"] || "unknown",

        timestamp: new Date().toISOString()
    };

    logs.push(entry);

    /*
      Prevent the log file from growing forever.
      Keeps the latest 10,000 entries.
    */

    if (logs.length > 10000) {
        logs = logs.slice(-10000);
    }

    fs.writeFileSync(
        loginLogsFile,
        JSON.stringify(logs, null, 2),
        "utf8"
    );

    console.log(
        `[LOGIN] ${user.username} | ${user.id} | ${entry.ip} | ${entry.timestamp}`
    );
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireDiscordLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/auth/discord");
    }

    next();
}

/* =========================================================
   DISCORD LOGIN
========================================================= */

app.get("/auth/discord", (req, res) => {
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,

        response_type: "code",

        redirect_uri: DISCORD_REDIRECT_URI,

        scope: "identify email"
    });

    const discordURL =
        `https://discord.com/oauth2/authorize?${params.toString()}`;

    res.redirect(discordURL);
});

/* =========================================================
   DISCORD CALLBACK
========================================================= */

app.get("/auth/discord/callback", async (req, res) => {
    const code = req.query.code;

    if (!code) {
        return res.status(400).send("Missing Discord OAuth code.");
    }

    try {
        /* ---------------------------------------------
           Exchange authorization code for access token
        --------------------------------------------- */

        const tokenResponse = await fetch(
            "https://discord.com/api/oauth2/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    client_id: DISCORD_CLIENT_ID,

                    client_secret:
                        DISCORD_CLIENT_SECRET,

                    grant_type:
                        "authorization_code",

                    code,

                    redirect_uri:
                        DISCORD_REDIRECT_URI
                })
            }
        );

        if (!tokenResponse.ok) {
            const errorText =
                await tokenResponse.text();

            console.error(
                "Discord token error:",
                errorText
            );

            return res
                .status(500)
                .send("Discord authentication failed.");
        }

        const tokenData =
            await tokenResponse.json();

        /* ---------------------------------------------
           Get Discord user
        --------------------------------------------- */

        const userResponse = await fetch(
            "https://discord.com/api/users/@me",
            {
                headers: {
                    Authorization:
                        `${tokenData.token_type} ${tokenData.access_token}`
                }
            }
        );

        if (!userResponse.ok) {
            const errorText =
                await userResponse.text();

            console.error(
                "Discord user error:",
                errorText
            );

            return res
                .status(500)
                .send("Unable to retrieve Discord account.");
        }

        const discordUser =
            await userResponse.json();

        /* ---------------------------------------------
           Store only required user information
        --------------------------------------------- */

        const user = {
            id: discordUser.id,

            username:
                discordUser.username,

            global_name:
                discordUser.global_name || null,

            email:
                discordUser.email || null,

            avatar:
                discordUser.avatar || null
        };

        /* ---------------------------------------------
           Create authenticated session
        --------------------------------------------- */

        req.session.user = user;

        /* ---------------------------------------------
           Save login log
        --------------------------------------------- */

        saveLoginLog(user, req);

        console.log(
            `[DISCORD LOGIN] ${user.username} (${user.id})`
        );

        /* ---------------------------------------------
           Redirect to website
        --------------------------------------------- */

        return res.redirect("/");
    } catch (error) {
        console.error(
            "Discord OAuth exception:",
            error
        );

        return res
            .status(500)
            .send("Authentication error.");
    }
});

/* =========================================================
   CURRENT USER API
========================================================= */

app.get(
    "/api/me",
    requireDiscordLogin,
    (req, res) => {
        res.json({
            authenticated: true,

            user: req.session.user
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/auth/discord");
    });
});

/* =========================================================
   PROTECT ALL WEBSITE FILES
========================================================= */

/*
   IMPORTANT:

   express.static() is placed AFTER requireDiscordLogin.

   Therefore nobody can access:

   /index.html
   /style.css
   /script.js
   /images/...
   etc.

   until Discord authentication succeeds.
*/

app.use(
    requireDiscordLogin,

    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================================
   ROOT FALLBACK
========================================================= */

app.get("/", requireDiscordLogin, (req, res) => {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
    res.status(404).send("404 - Page Not Found");
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
    console.error(err);

    res.status(500).send(
        "Internal Server Error"
    );
});

/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log(
            `CIA RP server running on port ${PORT}`
        );
    }
);
```
