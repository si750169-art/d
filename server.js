const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !SESSION_SECRET) {
    console.error("=================================");
    console.error("Missing environment variables:");
    console.error("DISCORD_CLIENT_ID");
    console.error("DISCORD_CLIENT_SECRET");
    console.error("DISCORD_REDIRECT_URI");
    console.error("SESSION_SECRET");
    console.error("=================================");
    process.exit(1);
}

app.set("trust proxy", 1);

app.use(express.json({ limit: "10mb" }));
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
            secure: true,
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000
        }
    })
);

// =====================================================
// SIMPLE DATABASE
// =====================================================

const users = [];
const applications = [];
const messages = [];
const reports = [];
const audit = [];

let nextUserId = 1;
let nextApplicationId = 1;
let nextMessageId = 1;
let nextReportId = 1;

// =====================================================
// HELPERS
// =====================================================

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

function currentTime() {
    return new Date().toISOString();
}

function requireDiscord(req, res, next) {
    if (!req.session.discord) {
        return res.status(401).json({
            error: "DISCORD_REQUIRED"
        });
    }

    next();
}

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "LOGIN_REQUIRED"
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "LOGIN_REQUIRED"
        });
    }

    if (
        req.session.user.rank !== "AGENT OFFICER" &&
        req.session.user.rank !== "COMMAND OF CIA"
    ) {
        return res.status(403).json({
            error: "NOT_AUTHORIZED"
        });
    }

    next();
}

function requireCommand(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "LOGIN_REQUIRED"
        });
    }

    if (req.session.user.rank !== "COMMAND OF CIA") {
        return res.status(403).json({
            error: "NOT_AUTHORIZED"
        });
    }

    next();
}

// =====================================================
// DISCORD OAUTH
// =====================================================

app.get("/auth/discord", (req, res) => {

    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: "code",
        scope: "identify"
    });

    res.redirect(
        "https://discord.com/oauth2/authorize?" +
        params.toString()
    );
});

// =====================================================
// DISCORD CALLBACK
// =====================================================

app.get("/auth/discord/callback", async (req, res) => {

    const code = req.query.code;

    if (!code) {
        return res.status(400).send(
            "Discord authorization was cancelled."
        );
    }

    try {

        const tokenResponse = await fetch(
            "https://discord.com/api/oauth2/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    client_id: CLIENT_ID,
                    client_secret: CLIENT_SECRET,
                    grant_type: "authorization_code",
                    code,
                    redirect_uri: REDIRECT_URI
                })
            }
        );

        const tokenText = await tokenResponse.text();

        if (!tokenResponse.ok) {
            console.error(
                "DISCORD TOKEN ERROR:",
                tokenText
            );

            return res.status(500).send(
                "Discord authentication failed."
            );
        }

        const token = JSON.parse(tokenText);

        const userResponse = await fetch(
            "https://discord.com/api/users/@me",
            {
                headers: {
                    Authorization:
                        `Bearer ${token.access_token}`
                }
            }
        );

        const userText = await userResponse.text();

        if (!userResponse.ok) {
            console.error(
                "DISCORD USER ERROR:",
                userText
            );

            return res.status(500).send(
                "Unable to retrieve Discord account."
            );
        }

        const discordUser = JSON.parse(userText);

        console.log(
            "Discord connected:",
            discordUser.username,
            discordUser.id
        );

        // =================================================
        // IMPORTANT
        // Discord is ONLY linked.
        // NO CIA account is created here.
        // =================================================

        req.session.discord = {
            id: discordUser.id,
            username: discordUser.username,
            globalName: discordUser.global_name || null,
            avatar: discordUser.avatar || null
        };

        // Remove previous CIA login when changing Discord
        req.session.user = null;

        req.session.save(error => {

            if (error) {
                console.error(
                    "SESSION SAVE ERROR:",
                    error
                );

                return res.status(500).send(
                    "Could not save Discord session."
                );
            }

            res.redirect("/");
        });

    } catch (error) {

        console.error(
            "DISCORD OAUTH ERROR:",
            error
        );

        res.status(500).send(
            "Discord OAuth error."
        );
    }
});

// =====================================================
// DISCORD STATUS
// =====================================================

app.get("/api/discord", (req, res) => {

    if (!req.session.discord) {
        return res.json({
            connected: false
        });
    }

    res.json({
        connected: true,
        discord: req.session.discord
    });
});

// =====================================================
// CURRENT CIA USER
// =====================================================

app.get("/api/me", requireDiscord, (req, res) => {

    if (!req.session.user) {
        return res.json({
            user: null
        });
    }

    const user = users.find(
        x => x.id === req.session.user.id
    );

    if (!user) {
        req.session.user = null;

        return res.json({
            user: null
        });
    }

    res.json({
        user: {
            id: user.id,
            username: user.username,
            rank: user.rank,
            unit: user.unit,
            clearance: user.clearance,
            in_game_name: user.in_game_name
        }
    });
});

// =====================================================
// CIA LOGIN
// =====================================================

app.post("/api/login", requireDiscord, (req, res) => {

    const username = String(
        req.body.username || ""
    ).trim();

    const password = String(
        req.body.password || ""
    );

    if (!username || !password) {
        return res.status(400).json({
            error: "MISSING_CREDENTIALS"
        });
    }

    const user = users.find(
        x =>
            x.username.toLowerCase() ===
            username.toLowerCase()
    );

    if (!user) {
        return res.status(401).json({
            error: "INVALID_CREDENTIALS"
        });
    }

    const passwordHash = hashPassword(password);

    if (passwordHash !== user.password) {
        return res.status(401).json({
            error: "INVALID_CREDENTIALS"
        });
    }

    req.session.user = {
        id: user.id
    };

    audit.push({
        created_at: currentTime(),
        actor_label: user.username,
        action: "LOGIN",
        ip: req.ip,
        details: "CIA personnel login"
    });

    req.session.save(error => {

        if (error) {
            console.error(error);

            return res.status(500).json({
                error: "SESSION_ERROR"
            });
        }

        res.json({
            success: true,

            user: {
                id: user.id,
                username: user.username,
                rank: user.rank,
                unit: user.unit,
                clearance: user.clearance,
                in_game_name: user.in_game_name
            }
        });
    });
});

// =====================================================
// LOGOUT
// =====================================================

app.post("/api/logout", (req, res) => {

    req.session.destroy(() => {
        res.json({
            success: true
        });
    });
});

// =====================================================
// APPLICATION SUBMIT
// =====================================================

app.post("/api/applications", requireDiscord, (req, res) => {

    const name = String(
        req.body.name || ""
    ).trim();

    const age = String(
        req.body.age || ""
    ).trim();

    const unit = String(
        req.body.unit || ""
    ).trim();

    const experience = String(
        req.body.experience || ""
    ).trim();

    const why = String(
        req.body.why || ""
    ).trim();

    if (
        !name ||
        !age ||
        !unit ||
        !experience ||
        !why
    ) {
        return res.status(400).json({
            error: "MISSING_FIELDS"
        });
    }

    // Prevent duplicate pending application
    const existing = applications.find(
        x =>
            x.discord_id === req.session.discord.id &&
            x.status === "PENDING"
    );

    if (existing) {

        req.session.applicationToken =
            existing.token;

        return res.json({
            success: true,
            token: existing.token
        });
    }

    const token = generateToken();

    const application = {
        id: nextApplicationId++,
        token,

        discord_id:
            req.session.discord.id,

        discord_username:
            req.session.discord.username,

        name,
        age,
        unit,
        experience,
        why,

        status: "PENDING",

        created_at: currentTime()
    };

    applications.push(application);

    req.session.applicationToken = token;

    res.json({
        success: true,
        token
    });
});

// =====================================================
// APPLICATION ME
// =====================================================

app.get(
    "/api/application/me",
    requireDiscord,
    (req, res) => {

        const token =
            req.session.applicationToken;

        let application = null;

        if (token) {
            application =
                applications.find(
                    x => x.token === token
                );
        }

        if (!application) {

            application =
                applications.find(
                    x =>
                        x.discord_id ===
                        req.session.discord.id
                );
        }

        if (!application) {
            return res.json({
                application: null,
                messages: []
            });
        }

        const appMessages =
            messages.filter(
                x =>
                    x.application_id ===
                    application.id
            );

        const credentials =
            application.status === "APPROVED"
                ? users.find(
                    x =>
                        x.application_id ===
                        application.id
                )
                : null;

        res.json({
            application: {
                id: application.id,
                name: application.name,
                age: application.age,
                unit: application.unit,
                experience: application.experience,
                why: application.why,
                status: application.status,
                created_at: application.created_at
            },

            messages: appMessages,

            credentials: credentials
                ? {
                    username:
                        credentials.username,

                    rank:
                        credentials.rank,

                    unit:
                        credentials.unit
                }
                : null
        });
    }
);

// =====================================================
// DASHBOARD
// =====================================================

app.get(
    "/api/dashboard",
    requireDiscord,
    requireLogin,
    (req, res) => {

        const user =
            users.find(
                x =>
                    x.id ===
                    req.session.user.id
            );

        if (!user) {
            return res.status(401).json({
                error: "LOGIN_REQUIRED"
            });
        }

        const userMessages =
            messages.filter(
                x =>
                    x.user_id === user.id
            );

        res.json({
            user: {
                username: user.username,
                rank: user.rank,
                unit: user.unit,
                clearance: user.clearance
            },

            messages: userMessages,

            reports: reports
        });
    }
);

// =====================================================
// SECTOR DIRECTORY
// =====================================================

app.get(
    "/api/sector",
    requireDiscord,
    requireLogin,
    (req, res) => {

        res.json(
            users.map(x => ({
                username: x.username,
                in_game_name:
                    x.in_game_name,
                rank: x.rank,
                unit: x.unit,
                clearance:
                    x.clearance
            }))
        );
    }
);

// =====================================================
// ADMIN APPLICATIONS
// =====================================================

app.get(
    "/api/admin/applications",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        res.json(
            applications.map(x => ({
                id: x.id,
                name: x.name,
                age: x.age,
                unit: x.unit,
                experience: x.experience,
                why: x.why,
                status: x.status,
                created_at:
                    x.created_at
            }))
        );
    }
);

// =====================================================
// ADMIN USERS
// =====================================================

app.get(
    "/api/admin/users",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        res.json(
            users.map(x => ({
                username:
                    x.username,

                in_game_name:
                    x.in_game_name,

                rank:
                    x.rank,

                unit:
                    x.unit,

                clearance:
                    x.clearance,

                created_at:
                    x.created_at
            }))
        );
    }
);

// =====================================================
// APPROVE APPLICATION
// =====================================================

app.post(
    "/api/admin/application/:id/approve",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        const id =
            Number(req.params.id);

        const application =
            applications.find(
                x => x.id === id
            );

        if (!application) {
            return res.status(404).json({
                error: "APPLICATION_NOT_FOUND"
            });
        }

        if (
            application.status !==
            "PENDING"
        ) {
            return res.status(400).json({
                error: "ALREADY_PROCESSED"
            });
        }

        const username =
            "agent_" +
            String(application.id)
                .padStart(3, "0");

        let password =
            crypto.randomBytes(5)
                .toString("hex");

        const user = {
            id: nextUserId++,

            username,

            password:
                hashPassword(password),

            rank: "AGENT",

            unit:
                application.unit,

            clearance:
                "RESTRICTED",

            in_game_name:
                application.name,

            discord_id:
                application.discord_id,

            application_id:
                application.id,

            created_at:
                currentTime()
        };

        users.push(user);

        application.status =
            "APPROVED";

        messages.push({
            id: nextMessageId++,

            application_id:
                application.id,

            user_id:
                user.id,

            subject:
                "CIA APPLICATION APPROVED",

            sender_label:
                "COMMAND OF CIA",

            body:
                "Your CIA application has been approved.\n\nUsername: " +
                username +
                "\nTemporary Password: " +
                password,

            type: "MESSAGE",

            read: false,

            created_at:
                currentTime()
        });

        audit.push({
            created_at:
                currentTime(),

            actor_label:
                req.session.user.id,

            action:
                "APPLICATION_APPROVED",

            ip:
                req.ip,

            details:
                "Application #" +
                application.id
        });

        res.json({
            success: true,
            username,
            password
        });
    }
);

// =====================================================
// REJECT APPLICATION
// =====================================================

app.post(
    "/api/admin/application/:id/reject",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        const id =
            Number(req.params.id);

        const application =
            applications.find(
                x => x.id === id
            );

        if (!application) {
            return res.status(404).json({
                error: "APPLICATION_NOT_FOUND"
            });
        }

        application.status =
            "REJECTED";

        messages.push({
            id: nextMessageId++,

            application_id:
                application.id,

            subject:
                "CIA APPLICATION UPDATE",

            sender_label:
                "COMMAND OF CIA",

            body:
                "Your CIA application has been rejected.",

            type:
                "MESSAGE",

            read: false,

            created_at:
                currentTime()
        });

        res.json({
            success: true
        });
    }
);

// =====================================================
// SEND MESSAGE
// =====================================================

app.post(
    "/api/admin/message",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        const target =
            String(
                req.body.target || ""
            ).trim();

        const subject =
            String(
                req.body.subject || ""
            ).trim();

        const body =
            String(
                req.body.body || ""
            ).trim();

        const type =
            String(
                req.body.type || "MESSAGE"
            );

        if (
            !target ||
            !subject ||
            !body
        ) {
            return res.status(400).json({
                error: "MISSING_FIELDS"
            });
        }

        // Application target
        if (target.startsWith("app:")) {

            const id =
                Number(
                    target.replace(
                        "app:",
                        ""
                    )
                );

            const application =
                applications.find(
                    x => x.id === id
                );

            if (!application) {
                return res.status(404).json({
                    error:
                        "APPLICATION_NOT_FOUND"
                });
            }

            messages.push({
                id: nextMessageId++,

                application_id:
                    application.id,

                subject,

                sender_label:
                    "COMMAND OF CIA",

                body,

                type,

                read: false,

                created_at:
                    currentTime()
            });

            return res.json({
                success: true
            });
        }

        const user =
            users.find(
                x =>
                    x.username.toLowerCase() ===
                    target.toLowerCase()
            );

        if (!user) {
            return res.status(404).json({
                error: "USER_NOT_FOUND"
            });
        }

        messages.push({
            id: nextMessageId++,

            user_id:
                user.id,

            subject,

            sender_label:
                "COMMAND OF CIA",

            body,

            type,

            read: false,

            created_at:
                currentTime()
        });

        res.json({
            success: true
        });
    }
);

// =====================================================
// CREATE USER
// =====================================================

app.post(
    "/api/admin/users",
    requireDiscord,
    requireCommand,
    (req, res) => {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        const rank =
            String(
                req.body.rank || "AGENT"
            );

        const unit =
            String(
                req.body.unit ||
                "Intelligence Operations"
            ).trim();

        const clearance =
            String(
                req.body.clearance ||
                "RESTRICTED"
            );

        const inGameName =
            String(
                req.body.in_game_name || ""
            ).trim();

        if (
            !username ||
            !password ||
            !inGameName
        ) {
            return res.status(400).json({
                error: "MISSING_FIELDS"
            });
        }

        const exists =
            users.some(
                x =>
                    x.username.toLowerCase() ===
                    username.toLowerCase()
            );

        if (exists) {
            return res.status(409).json({
                error: "USERNAME_EXISTS"
            });
        }

        const user = {
            id: nextUserId++,

            username,

            password:
                hashPassword(password),

            rank,

            unit,

            clearance,

            in_game_name:
                inGameName,

            discord_id:
                null,

            application_id:
                null,

            created_at:
                currentTime()
        };

        users.push(user);

        audit.push({
            created_at:
                currentTime(),

            actor_label:
                "COMMAND OF CIA",

            action:
                "CREATE_USER",

            ip:
                req.ip,

            details:
                username
        });

        res.json({
            success: true
        });
    }
);

// =====================================================
// REPORTS
// =====================================================

app.get(
    "/api/reports/:id",
    requireDiscord,
    requireLogin,
    (req, res) => {

        const report =
            reports.find(
                x =>
                    x.id ===
                    Number(req.params.id)
            );

        if (!report) {
            return res.status(404).send(
                "Report not found."
            );
        }

        res.status(501).send(
            "PDF storage is not configured in this server build."
        );
    }
);

// =====================================================
// REGISTER REPORT
// =====================================================

app.post(
    "/api/admin/reports",
    requireDiscord,
    requireAdmin,
    (req, res) => {

        const title =
            String(
                req.body.title || ""
            ).trim();

        const classification =
            String(
                req.body.classification ||
                "CONFIDENTIAL"
            );

        if (!title) {
            return res.status(400).json({
                error: "MISSING_TITLE"
            });
        }

        const report = {
            id: nextReportId++,

            title,

            classification,

            created_at:
                currentTime()
        };

        reports.push(report);

        res.json({
            success: true,
            report
        });
    }
);

// =====================================================
// COMMAND AUDIT
// =====================================================

app.get(
    "/api/command/audit",
    requireDiscord,
    requireCommand,
    (req, res) => {

        res.json(
            audit.slice(-200).reverse()
        );
    }
);

// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

    if (!req.session.discord) {
        return res.redirect(
            "/auth/discord"
        );
    }

    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

// =====================================================
// STATIC FILES
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
// DISCORD LOGOUT
// =====================================================

app.get(
    "/discord/logout",
    (req, res) => {

        req.session.destroy(() => {
            res.redirect(
                "/auth/discord"
            );
        });
    }
);

// =====================================================
// 404
// =====================================================

app.use(
    (req, res) => {

        res.status(404).json({
            error: "NOT_FOUND",
            path: req.path
        });
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
            "================================="
        );

        console.log(
            `CIA RP running on port ${PORT}`
        );

        console.log(
            `Discord Redirect: ${REDIRECT_URI}`
        );

        console.log(
            "Discord authentication: ENABLED"
        );

        console.log(
            "CIA auto-account creation: DISABLED"
        );

        console.log(
            "================================="
        );
    }
);
