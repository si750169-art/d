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

// Render runs behind a proxy
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
// LOG FILES
// =====================================================

const logsDir = path.join(__dirname, "logs");

const visitLogsFile = path.join(
    logsDir,
    "visit-logs.json"
);

const discordLogsFile = path.join(
    logsDir,
    "discord-links.json"
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

if (!fs.existsSync(discordLogsFile)) {
    fs.writeFileSync(
        discordLogsFile,
        "[]",
        "utf8"
    );
}

// =====================================================
// GET CLIENT IP
// =====================================================

function getClientIP(req) {
    const forwarded = req.headers["x-forwarded-for"];

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
// READ JSON LOG
// =====================================================

function readLogs(file) {
    try {
        const data = fs.readFileSync(
            file,
            "utf8"
        );

        const parsed = JSON.parse(data);

        return Array.isArray(parsed)
            ? parsed
            : [];
    } catch {
        return [];
    }
}

// =====================================================
// WRITE JSON LOG
// =====================================================

function writeLogs(file, logs) {
    fs.writeFileSync(
        file,
        JSON.stringify(
            logs,
            null,
            2
        ),
        "utf8"
    );
}

// =====================================================
// SAVE SITE VISIT
// =====================================================

function saveVisitLog(req) {
    const logs = readLogs(
        visitLogsFile
    );

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

    // Keep the last 10,000 visits
    const limitedLogs =
        logs.length > 10000
            ? logs.slice(-10000)
            : logs;

    writeLogs(
        visitLogsFile,
        limitedLogs
    );

    console.log(
        `[VISIT] ${entry.ip} | ${entry.timestamp}`
    );
}

// =====================================================
// SAVE DISCORD LINK
// =====================================================

function saveDiscordLink(user, req) {
    const logs = readLogs(
        discordLogsFile
    );

    const entry = {
        type: "discord_link",

        discordId: user.id,

        username: user.username,

        globalName:
            user.global_name || null,

        email:
            user.email || null,

        avatar:
            user.avatar || null,

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

    // Keep the last 10,000 links
    const limitedLogs =
        logs.length > 10000
            ? logs.slice(-10000)
            : logs;

    writeLogs(
        discordLogsFile,
        limitedLogs
    );

    console.log(
        `[DISCORD LINK] ${user.username} | ${user.id} | ${entry.ip}`
    );
}

// =====================================================
// MAIN PAGE
// =====================================================

app.get("/", (req, res) => {
    // Already connected
    if (req.session.user) {
        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }

    // First visit
    saveVisitLog(req);

    // Show Discord connection page
    return res.sendFile(
        path.join(
            __dirname,
            "public",
            "link-discord.html"
        )
    );
});

// =====================================================
// DISCORD OAUTH START
// =====================================================

app.get(
    "/auth/discord",
    (req, res) => {
        const params = new URLSearchParams({
            client_id:
                DISCORD_CLIENT_ID,

            response_type:
                "code",

            redirect_uri:
                DISCORD_REDIRECT_URI,

            scope:
                "identify email"
        });

        const discordURL =
            "https://discord.com/oauth2/authorize?" +
            params.toString();

        return res.redirect(
            discordURL
        );
    }
);

// =====================================================
// DISCORD OAUTH CALLBACK
// =====================================================

app.get(
    "/auth/discord/callback",
    async (req, res) => {
        const code = req.query.code;

        if (!code) {
            return res
                .status(400)
                .send(
                    "Discord authorization was cancelled or failed."
                );
        }

        try {
            // -------------------------------------------------
            // Exchange OAuth code for access token
            // -------------------------------------------------

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
                const errorText =
                    await tokenResponse.text();

                console.error(
                    "Discord token error:",
                    errorText
                );

                return res
                    .status(500)
                    .send(
                        "Discord authentication failed."
                    );
            }

            const tokenData =
                await tokenResponse.json();

            // -------------------------------------------------
            // Get Discord account
            // -------------------------------------------------

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
                const errorText =
                    await userResponse.text();

                console.error(
                    "Discord user error:",
                    errorText
                );

                return res
                    .status(500)
                    .send(
                        "Unable to retrieve Discord account."
                    );
            }

            const discordUser =
                await userResponse.json();

            // -------------------------------------------------
            // Store Discord information
            // -------------------------------------------------

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

            // -------------------------------------------------
            // Create authenticated session
            // -------------------------------------------------

            req.session.user = user;

            // -------------------------------------------------
            // Save Discord link log
            // -------------------------------------------------

            saveDiscordLink(
                user,
                req
            );

            // -------------------------------------------------
            // Go to website
            // -------------------------------------------------

            return res.redirect(
                "/"
            );

        } catch (error) {
            console.error(
                "Discord OAuth error:",
                error
            );

            return res
                .status(500)
                .send(
                    "Discord connection failed."
                );
        }
    }
);

// =====================================================
// CURRENT USER API
// =====================================================

app.get(
    "/api/me",
    (req, res) => {
        if (!req.session.user) {
            return res.json({
                linked: false
            });
        }

        return res.json({
            linked: true,

            user:
                req.session.user
        });
    }
);

// =====================================================
// LOGOUT / UNLINK
// =====================================================

app.get(
    "/logout",
    (req, res) => {
        req.session.destroy(
            (error) => {
                if (error) {
                    console.error(
                        "Logout error:",
                        error
                    );
                }

                return res.redirect(
                    "/"
                );
            }
        );
    }
);

// =====================================================
// PROTECT ALL WEBSITE FILES
// =====================================================

app.use(
    (req, res, next) => {
        if (!req.session.user) {
            return res.redirect(
                "/"
            );
        }

        next();
    }
);

// =====================================================
// SERVE WEBSITE
// =====================================================

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
        return res
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
        console.error(
            "Server error:",
            err
        );

        return res
            .status(500)
            .send(
                "Internal Server Error"
            );
    }
);

// =====================================================
// START SERVER
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
