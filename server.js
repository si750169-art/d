const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const {
    DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET,
    DISCORD_REDIRECT_URI,
    SESSION_SECRET
} = process.env;

if (
    !DISCORD_CLIENT_ID ||
    !DISCORD_CLIENT_SECRET ||
    !DISCORD_REDIRECT_URI ||
    !SESSION_SECRET
) {
    console.error("Missing required environment variables.");
    process.exit(1);
}

// Render is behind a proxy
app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================================================
// SESSION
// =====================================================

app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// =====================================================
// LOG DIRECTORIES
// =====================================================

const logsDir = path.join(__dirname, "logs");

const visitLogsFile = path.join(
    logsDir,
    "visit-logs.json"
);

const loginLogsFile = path.join(
    logsDir,
    "login-logs.json"
);

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, {
        recursive: true
    });
}

if (!fs.existsSync(visitLogsFile)) {
    fs.writeFileSync(
        visitLogsFile,
        "[]",
        "utf8"
    );
}

if (!fs.existsSync(loginLogsFile)) {
    fs.writeFileSync(
        loginLogsFile,
        "[]",
        "utf8"
    );
}

// =====================================================
// GET CLIENT IP
// =====================================================

function getClientIP(req) {
    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {
        return forwarded
            .split(",")[0]
            .trim();
    }

    return (
        req.headers["x-real-ip"] ||
        req.ip ||
        req.socket?.remoteAddress ||
        "unknown"
    );
}

// =====================================================
// SAVE VISITOR LOG
// =====================================================

function saveVisitLog(req) {
    let logs = [];

    try {
        logs = JSON.parse(
            fs.readFileSync(
                visitLogsFile,
                "utf8"
            )
        );

        if (!Array.isArray(logs)) {
            logs = [];
        }
    } catch {
        logs = [];
    }

    const entry = {
        type: "site_visit",

        ip: getClientIP(req),

        timestamp:
            new Date().toISOString(),

        userAgent:
            req.headers["user-agent"] ||
            "unknown",

        language:
            req.headers["accept-language"] ||
            "unknown",

        path:
            req.originalUrl || "/"
    };

    logs.push(entry);

    // Keep latest 10,000 visits
    if (logs.length > 10000) {
        logs = logs.slice(-10000);
    }

    fs.writeFileSync(
        visitLogsFile,
        JSON.stringify(
            logs,
            null,
            2
        ),
        "utf8"
    );

    console.log(
        `[SITE VISIT] ${entry.ip} | ${entry.timestamp}`
    );
}

// =====================================================
// SAVE DISCORD LOGIN LOG
// =====================================================

function saveLoginLog(user, req) {
    let logs = [];

    try {
        logs = JSON.parse(
            fs.readFileSync(
                loginLogsFile,
                "utf8"
            )
        );

        if (!Array.isArray(logs)) {
            logs = [];
        }
    } catch {
        logs = [];
    }

    const entry = {
        type: "discord_login",

        discord: {
            id: user.id,
            username: user.username,
            globalName:
                user.global_name || null,
            email:
                user.email || null,
            avatar:
                user.avatar || null
        },

        ip: getClientIP(req),

        timestamp:
            new Date().toISOString(),

        userAgent:
            req.headers["user-agent"] ||
            "unknown",

        language:
            req.headers["accept-language"] ||
            "unknown"
    };

    logs.push(entry);

    // Keep latest 10,000 logins
    if (logs.length > 10000) {
        logs = logs.slice(-10000);
    }

    fs.writeFileSync(
        loginLogsFile,
        JSON.stringify(
            logs,
            null,
            2
        ),
        "utf8"
    );

    console.log(
        `[DISCORD LOGIN] ${user.username} | ${user.id} | ${entry.ip}`
    );
}

// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function requireDiscordLogin(
    req,
    res,
    next
) {
    if (!req.session.user) {
        return res.redirect(
            "/auth/discord"
        );
    }

    next();
}

// =====================================================
// FIRST VISIT
// =====================================================

app.get("/", (req, res, next) => {

    // Already logged in
    if (req.session.user) {
        return next();
    }

    // Record IP immediately
    saveVisitLog(req);

    // Send visitor to Discord
    return res.redirect(
        "/auth/discord"
    );
});

// =====================================================
// DISCORD OAUTH
// =====================================================

app.get(
    "/auth/discord",
    (req, res) => {

        const params =
            new URLSearchParams({
                client_id:
                    DISCORD_CLIENT_ID,

                response_type:
                    "code",

                redirect_uri:
                    DISCORD_REDIRECT_URI,

                scope:
                    "identify email"
            });

        const url =
            "https://discord.com/oauth2/authorize?" +
            params.toString();

        res.redirect(url);
    }
);

// =====================================================
// DISCORD CALLBACK
// =====================================================

app.get(
    "/auth/discord/callback",
    async (req, res) => {

        const code = req.query.code;

        if (!code) {
            return res
                .status(400)
                .send(
                    "Missing Discord OAuth code."
                );
        }

        try {

            // -----------------------------------------
            // Exchange code for token
            // -----------------------------------------

            const tokenResponse =
                await fetch(
                    "https://discord.com/api/oauth2/token",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/x-www-form-urlencoded"
                        },

                        body:
                            new URLSearchParams({
                                client_id:
                                    DISCORD_CLIENT_ID,

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

                const error =
                    await tokenResponse.text();

                console.error(
                    "Discord token error:",
                    error
                );

                return res
                    .status(500)
                    .send(
                        "Discord authentication failed."
                    );
            }

            const tokenData =
                await tokenResponse.json();

            // -----------------------------------------
            // Get Discord account
            // -----------------------------------------

            const userResponse =
                await fetch(
                    "https://discord.com/api/users/@me",
                    {
                        headers: {
                            Authorization:
                                `${tokenData.token_type} ${tokenData.access_token}`
                        }
                    }
                );

            if (!userResponse.ok) {

                const error =
                    await userResponse.text();

                console.error(
                    "Discord user error:",
                    error
                );

                return res
                    .status(500)
                    .send(
                        "Unable to retrieve Discord account."
                    );
            }

            const discordUser =
                await userResponse.json();

            // -----------------------------------------
            // User information
            // -----------------------------------------

            const user = {
                id:
                    discordUser.id,

                username:
                    discordUser.username,

                global_name:
                    discordUser.global_name ||
                    null,

                email:
                    discordUser.email ||
                    null,

                avatar:
                    discordUser.avatar ||
                    null
            };

            // -----------------------------------------
            // Create session
            // -----------------------------------------

            req.session.user = user;

            // -----------------------------------------
            // Save login
            // -----------------------------------------

            saveLoginLog(
                user,
                req
            );

            // -----------------------------------------
            // Enter website
            // -----------------------------------------

            return res.redirect(
                "/"
            );

        } catch (error) {

            console.error(
                "OAuth error:",
                error
            );

            return res
                .status(500)
                .send(
                    "Authentication error."
                );
        }
    }
);

// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/me",
    requireDiscordLogin,
    (req, res) => {

        res.json({
            authenticated: true,

            user:
                req.session.user
        });
    }
);

// =====================================================
// LOGOUT
// =====================================================

app.get(
    "/logout",
    (req, res) => {

        req.session.destroy(
            () => {
                res.redirect(
                    "/auth/discord"
                );
            }
        );
    }
);

// =====================================================
// PROTECT ALL PUBLIC FILES
// =====================================================

app.use(
    requireDiscordLogin
);

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

// =====================================================
// 404
// =====================================================

app.use(
    (req, res) => {

        res
            .status(404)
            .send(
                "404 - Page Not Found"
            );
    }
);

// =====================================================
// ERROR HANDLER
// =====================================================

app.use(
    (err, req, res, next) => {

        console.error(err);

        res
            .status(500)
            .send(
                "Internal Server Error"
            );
    }
);

// =====================================================
// START
// =====================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `CIA RP server running on port ${PORT}`
        );
    }
);
