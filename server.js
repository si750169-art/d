const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

// =====================================================
// ENVIRONMENT
// =====================================================

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const DB_DIR =
    process.env.DB_DIR || "/var/data";

const DB_PATH =
    process.env.DB_PATH ||
    path.join(DB_DIR, "cia.db");

const REPORTS_DIR =
    process.env.REPORTS_DIR ||
    path.join(DB_DIR, "reports");

// =====================================================
// VALIDATE ENV
// =====================================================

if (
    !CLIENT_ID ||
    !CLIENT_SECRET ||
    !REDIRECT_URI ||
    !SESSION_SECRET
) {
    console.error("");
    console.error("==========================================");
    console.error("MISSING REQUIRED ENVIRONMENT VARIABLES");
    console.error("==========================================");
    console.error("DISCORD_CLIENT_ID");
    console.error("DISCORD_CLIENT_SECRET");
    console.error("DISCORD_REDIRECT_URI");
    console.error("SESSION_SECRET");
    console.error("==========================================");
    console.error("");

    process.exit(1);
}

// =====================================================
// DIRECTORIES
// =====================================================

fs.mkdirSync(DB_DIR, {
    recursive: true
});

fs.mkdirSync(REPORTS_DIR, {
    recursive: true
});

// =====================================================
// EXPRESS
// =====================================================

app.set("trust proxy", 1);

app.use(
    express.json({
        limit: "10mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "10mb"
    })
);

// =====================================================
// SQLITE
// =====================================================

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// =====================================================
// DATABASE TABLES
// =====================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,

        rank TEXT NOT NULL DEFAULT 'AGENT',
        unit TEXT NOT NULL DEFAULT 'Intelligence Operations',
        clearance TEXT NOT NULL DEFAULT 'RESTRICTED',

        in_game_name TEXT NOT NULL,

        discord_id TEXT,
        application_id INTEGER,

        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        token TEXT NOT NULL UNIQUE,

        discord_id TEXT NOT NULL,
        discord_username TEXT,

        name TEXT NOT NULL,
        age TEXT NOT NULL,
        unit TEXT NOT NULL,

        experience TEXT NOT NULL,
        why TEXT NOT NULL,

        status TEXT NOT NULL DEFAULT 'PENDING',

        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER,
        application_id INTEGER,

        subject TEXT NOT NULL,
        sender_label TEXT NOT NULL,

        body TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'MESSAGE',

        read INTEGER NOT NULL DEFAULT 0,

        created_at TEXT NOT NULL,

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY(application_id)
            REFERENCES applications(id)
            ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        title TEXT NOT NULL,
        classification TEXT NOT NULL,

        filename TEXT,
        original_name TEXT,

        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        actor_label TEXT NOT NULL,
        action TEXT NOT NULL,

        ip TEXT,
        details TEXT,

        created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_app_discord
        ON applications(discord_id);

    CREATE INDEX IF NOT EXISTS idx_messages_user
        ON messages(user_id);

    CREATE INDEX IF NOT EXISTS idx_messages_application
        ON messages(application_id);

    CREATE INDEX IF NOT EXISTS idx_users_discord
        ON users(discord_id);
`);

// =====================================================
// SESSION
// =====================================================

app.use(
    session({
        store: new SQLiteStore({
            db: "sessions.sqlite",
            dir: DB_DIR
        }),

        secret: SESSION_SECRET,

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
            maxAge:
                7 * 24 * 60 * 60 * 1000
        }
    })
);

// =====================================================
// HELPERS
// =====================================================

function now() {
    return new Date().toISOString();
}

function token() {
    return crypto
        .randomBytes(32)
        .toString("hex");
}

function hashPassword(password) {
    const salt =
        crypto.randomBytes(16).toString("hex");

    const hash =
        crypto
            .scryptSync(
                String(password),
                salt,
                64
            )
            .toString("hex");

    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    try {
        const parts =
            String(stored).split(":");

        if (parts.length !== 2) {
            return false;
        }

        const salt = parts[0];
        const originalHash =
            Buffer.from(parts[1], "hex");

        const testHash =
            crypto.scryptSync(
                String(password),
                salt,
                64
            );

        return (
            originalHash.length ===
                testHash.length &&
            crypto.timingSafeEqual(
                originalHash,
                testHash
            )
        );
    } catch {
        return false;
    }
}

function safeUser(user) {
    if (!user) return null;

    return {
        id: user.id,
        username: user.username,
        rank: user.rank,
        unit: user.unit,
        clearance: user.clearance,
        in_game_name: user.in_game_name
    };
}

function audit(
    actor,
    action,
    ip,
    details
) {
    db.prepare(`
        INSERT INTO audit (
            actor_label,
            action,
            ip,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
    `).run(
        actor || "SYSTEM",
        action,
        ip || null,
        details || "",
        now()
    );
}

// =====================================================
// MIDDLEWARE
// =====================================================

function requireDiscord(req, res, next) {

    if (!req.session.discord) {
        return res.status(401).json({
            error: "DISCORD_REQUIRED"
        });
    }

    next();
}

function requireLogin(req, res, next) {

    if (!req.session.userId) {
        return res.status(401).json({
            error: "LOGIN_REQUIRED"
        });
    }

    const user =
        db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(req.session.userId);

    if (!user) {

        req.session.userId = null;

        return res.status(401).json({
            error: "LOGIN_REQUIRED"
        });
    }

    req.user = user;

    next();
}

function requireAdmin(req, res, next) {

    requireLogin(req, res, () => {

        if (
            req.user.rank !== "AGENT OFFICER" &&
            req.user.rank !== "COMMAND OF CIA"
        ) {
            return res.status(403).json({
                error: "NOT_AUTHORIZED"
            });
        }

        next();
    });
}

function requireCommand(req, res, next) {

    requireLogin(req, res, () => {

        if (
            req.user.rank !==
            "COMMAND OF CIA"
        ) {
            return res.status(403).json({
                error: "NOT_AUTHORIZED"
            });
        }

        next();
    });
}

// =====================================================
// DISCORD OAUTH
// =====================================================

app.get(
    "/auth/discord",
    (req, res) => {

        const params =
            new URLSearchParams({
                client_id: CLIENT_ID,
                redirect_uri: REDIRECT_URI,
                response_type: "code",
                scope: "identify"
            });

        res.redirect(
            "https://discord.com/oauth2/authorize?" +
            params.toString()
        );
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
            return res.status(400).send(
                "Discord authorization was cancelled."
            );
        }

        try {

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
                                    CLIENT_ID,

                                client_secret:
                                    CLIENT_SECRET,

                                grant_type:
                                    "authorization_code",

                                code,

                                redirect_uri:
                                    REDIRECT_URI
                            })
                    }
                );

            const tokenText =
                await tokenResponse.text();

            if (!tokenResponse.ok) {

                console.error(
                    "DISCORD TOKEN ERROR:",
                    tokenText
                );

                return res.status(500).send(
                    "Discord authentication failed."
                );
            }

            const oauthToken =
                JSON.parse(tokenText);

            const userResponse =
                await fetch(
                    "https://discord.com/api/users/@me",
                    {
                        headers: {
                            Authorization:
                                `Bearer ${oauthToken.access_token}`
                        }
                    }
                );

            const userText =
                await userResponse.text();

            if (!userResponse.ok) {

                console.error(
                    "DISCORD USER ERROR:",
                    userText
                );

                return res.status(500).send(
                    "Unable to retrieve Discord account."
                );
            }

            const discordUser =
                JSON.parse(userText);

            // =================================================
            // IMPORTANT:
            // Discord linking DOES NOT create a CIA account.
            // =================================================

            req.session.discord = {
                id: discordUser.id,

                username:
                    discordUser.username,

                globalName:
                    discordUser.global_name || null,

                avatar:
                    discordUser.avatar || null
            };

            // Don't automatically log into CIA.
            req.session.userId = null;

            // Find existing approved CIA account
            // ONLY for information.
            const existingUser =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE discord_id = ?
                    LIMIT 1
                `).get(discordUser.id);

            if (existingUser) {

                console.log(
                    "Discord linked to existing CIA account:",
                    existingUser.username
                );

            } else {

                console.log(
                    "Discord connected:",
                    discordUser.username,
                    discordUser.id
                );
            }

            audit(
                discordUser.username,
                "DISCORD_CONNECT",
                req.ip,
                `Discord ID: ${discordUser.id}`
            );

            req.session.save(
                error => {

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
                }
            );

        } catch (error) {

            console.error(
                "DISCORD OAUTH ERROR:",
                error
            );

            res.status(500).send(
                "Discord OAuth error."
            );
        }
    }
);

// =====================================================
// DISCORD STATUS
// =====================================================

app.get(
    "/api/discord",
    (req, res) => {

        if (!req.session.discord) {
            return res.json({
                connected: false
            });
        }

        res.json({
            connected: true,
            discord:
                req.session.discord
        });
    }
);

// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/me",
    requireDiscord,
    (req, res) => {

        if (!req.session.userId) {
            return res.json({
                user: null
            });
        }

        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `).get(req.session.userId);

        if (!user) {

            req.session.userId = null;

            return res.json({
                user: null
            });
        }

        res.json({
            user: safeUser(user)
        });
    }
);

// =====================================================
// CIA LOGIN
// =====================================================

app.post(
    "/api/login",
    requireDiscord,
    (req, res) => {

        const username =
            String(
                req.body.username || ""
            ).trim();

        const password =
            String(
                req.body.password || ""
            );

        if (
            !username ||
            !password
        ) {
            return res.status(400).json({
                error:
                    "MISSING_CREDENTIALS"
            });
        }

        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE LOWER(username)
                    = LOWER(?)
                LIMIT 1
            `).get(username);

        if (!user) {

            return res.status(401).json({
                error:
                    "INVALID_CREDENTIALS"
            });
        }

        if (
            !verifyPassword(
                password,
                user.password
            )
        ) {

            return res.status(401).json({
                error:
                    "INVALID_CREDENTIALS"
            });
        }

        // Optional Discord association
        // when a CIA account logs in.
        if (
            !user.discord_id &&
            req.session.discord
        ) {

            db.prepare(`
                UPDATE users
                SET discord_id = ?
                WHERE id = ?
            `).run(
                req.session.discord.id,
                user.id
            );
        }

        req.session.userId =
            user.id;

        audit(
            user.username,
            "CIA_LOGIN",
            req.ip,
            "Personnel login"
        );

        req.session.save(
            error => {

                if (error) {

                    console.error(error);

                    return res.status(500).json({
                        error:
                            "SESSION_ERROR"
                    });
                }

                res.json({
                    success: true,
                    user: safeUser(user)
                });
            }
        );
    }
);

// =====================================================
// LOGOUT
// =====================================================

app.post(
    "/api/logout",
    (req, res) => {

        req.session.userId = null;

        req.session.save(() => {

            res.json({
                success: true
            });
        });
    }
);

// =====================================================
// APPLICATION SUBMIT
// =====================================================

app.post(
    "/api/applications",
    requireDiscord,
    (req, res) => {

        const name =
            String(
                req.body.name || ""
            ).trim();

        const age =
            String(
                req.body.age || ""
            ).trim();

        const unit =
            String(
                req.body.unit || ""
            ).trim();

        const experience =
            String(
                req.body.experience || ""
            ).trim();

        const why =
            String(
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
                error:
                    "MISSING_FIELDS"
            });
        }

        // Don't allow multiple pending
        // applications for same Discord.
        const existing =
            db.prepare(`
                SELECT *
                FROM applications
                WHERE discord_id = ?
                AND status = 'PENDING'
                ORDER BY id DESC
                LIMIT 1
            `).get(
                req.session.discord.id
            );

        if (existing) {

            req.session.applicationToken =
                existing.token;

            return res.json({
                success: true,
                token:
                    existing.token
            });
        }

        const applicationToken =
            token();

        const result =
            db.prepare(`
                INSERT INTO applications (
                    token,
                    discord_id,
                    discord_username,
                    name,
                    age,
                    unit,
                    experience,
                    why,
                    status,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
            `).run(

                applicationToken,

                req.session.discord.id,

                req.session.discord.username,

                name,

                age,

                unit,

                experience,

                why,

                now()
            );

        req.session.applicationToken =
            applicationToken;

        audit(
            req.session.discord.username,
            "APPLICATION_SUBMITTED",
            req.ip,
            `Application #${result.lastInsertRowid}`
        );

        res.json({
            success: true,
            token:
                applicationToken
        });
    }
);

// =====================================================
// APPLICATION ME
// =====================================================

app.get(
    "/api/application/me",
    requireDiscord,
    (req, res) => {

        let application = null;

        if (
            req.session.applicationToken
        ) {

            application =
                db.prepare(`
                    SELECT *
                    FROM applications
                    WHERE token = ?
                    LIMIT 1
                `).get(
                    req.session.applicationToken
                );
        }

        // Fallback by Discord
        if (!application) {

            application =
                db.prepare(`
                    SELECT *
                    FROM applications
                    WHERE discord_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                `).get(
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
            db.prepare(`
                SELECT
                    id,
                    subject,
                    sender_label,
                    body,
                    type,
                    read,
                    created_at
                FROM messages
                WHERE application_id = ?
                ORDER BY id DESC
            `).all(
                application.id
            );

        const credentials =
            db.prepare(`
                SELECT
                    username,
                    rank,
                    unit
                FROM users
                WHERE application_id = ?
                LIMIT 1
            `).get(
                application.id
            );

        res.json({

            application: {
                id:
                    application.id,

                name:
                    application.name,

                age:
                    application.age,

                unit:
                    application.unit,

                experience:
                    application.experience,

                why:
                    application.why,

                status:
                    application.status,

                created_at:
                    application.created_at
            },

            messages:
                appMessages,

            credentials:
                credentials || null
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

        const messages =
            db.prepare(`
                SELECT
                    id,
                    subject,
                    sender_label,
                    body,
                    type,
                    read,
                    created_at
                FROM messages
                WHERE user_id = ?
                ORDER BY id DESC
            `).all(
                req.user.id
            );

        const reports =
            db.prepare(`
                SELECT
                    id,
                    title,
                    classification,
                    created_at
                FROM reports
                ORDER BY id DESC
            `).all();

        res.json({

            user:
                safeUser(req.user),

            messages,

            reports
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

        const users =
            db.prepare(`
                SELECT
                    username,
                    in_game_name,
                    rank,
                    unit,
                    clearance
                FROM users
                ORDER BY id ASC
            `).all();

        res.json(users);
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

        const applications =
            db.prepare(`
                SELECT
                    id,
                    name,
                    age,
                    unit,
                    experience,
                    why,
                    status,
                    created_at
                FROM applications
                ORDER BY id DESC
            `).all();

        res.json(applications);
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

        const users =
            db.prepare(`
                SELECT
                    username,
                    in_game_name,
                    rank,
                    unit,
                    clearance,
                    created_at
                FROM users
                ORDER BY id ASC
            `).all();

        res.json(users);
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
            db.prepare(`
                SELECT *
                FROM applications
                WHERE id = ?
                LIMIT 1
            `).get(id);

        if (!application) {
            return res.status(404).json({
                error:
                    "APPLICATION_NOT_FOUND"
            });
        }

        if (
            application.status !==
            "PENDING"
        ) {
            return res.status(400).json({
                error:
                    "ALREADY_PROCESSED"
            });
        }

        // Generate permanent CIA username
        const username =
            "agent_" +
            String(application.id)
                .padStart(3, "0");

        // Generate temporary password
        const password =
            crypto
                .randomBytes(6)
                .toString("hex");

        const createUser =
            db.prepare(`
                INSERT INTO users (
                    username,
                    password,
                    rank,
                    unit,
                    clearance,
                    in_game_name,
                    discord_id,
                    application_id,
                    created_at
                )
                VALUES (?, ?, 'AGENT', ?, 'RESTRICTED', ?, ?, ?, ?)
            `);

        const updateApplication =
            db.prepare(`
                UPDATE applications
                SET status = 'APPROVED'
                WHERE id = ?
            `);

        const addMessage =
            db.prepare(`
                INSERT INTO messages (
                    user_id,
                    application_id,
                    subject,
                    sender_label,
                    body,
                    type,
                    read,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, 'MESSAGE', 0, ?)
            `);

        const transaction =
            db.transaction(() => {

                const userResult =
                    createUser.run(

                        username,

                        hashPassword(
                            password
                        ),

                        application.unit,

                        application.name,

                        application.discord_id,

                        application.id,

                        now()
                    );

                updateApplication.run(
                    application.id
                );

                addMessage.run(

                    userResult.lastInsertRowid,

                    application.id,

                    "CIA APPLICATION APPROVED",

                    "COMMAND OF CIA",

                    "Your CIA application has been approved.\n\nUsername: " +
                        username +
                        "\nTemporary Password: " +
                        password,

                    now()
                );

                return userResult.lastInsertRowid;
            });

        try {

            transaction();

        } catch (error) {

            console.error(
                "APPROVAL ERROR:",
                error
            );

            return res.status(500).json({
                error:
                    "COULD_NOT_APPROVE"
            });
        }

        audit(
            req.user.username,
            "APPLICATION_APPROVED",
            req.ip,
            `Application #${id}`
        );

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
            db.prepare(`
                SELECT *
                FROM applications
                WHERE id = ?
            `).get(id);

        if (!application) {

            return res.status(404).json({
                error:
                    "APPLICATION_NOT_FOUND"
            });
        }

        db.prepare(`
            UPDATE applications
            SET status = 'REJECTED'
            WHERE id = ?
        `).run(id);

        db.prepare(`
            INSERT INTO messages (
                application_id,
                subject,
                sender_label,
                body,
                type,
                read,
                created_at
            )
            VALUES (?, ?, ?, ?, 'MESSAGE', 0, ?)
        `).run(

            id,

            "CIA APPLICATION UPDATE",

            "COMMAND OF CIA",

            "Your CIA application has been rejected.",

            now()
        );

        audit(
            req.user.username,
            "APPLICATION_REJECTED",
            req.ip,
            `Application #${id}`
        );

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
                req.body.type ||
                "MESSAGE"
            );

        if (
            !target ||
            !subject ||
            !body
        ) {
            return res.status(400).json({
                error:
                    "MISSING_FIELDS"
            });
        }

        // Application target
        if (
            target.toLowerCase()
                .startsWith("app:")
        ) {

            const id =
                Number(
                    target.substring(4)
                );

            const application =
                db.prepare(`
                    SELECT *
                    FROM applications
                    WHERE id = ?
                `).get(id);

            if (!application) {

                return res.status(404).json({
                    error:
                        "APPLICATION_NOT_FOUND"
                });
            }

            db.prepare(`
                INSERT INTO messages (
                    application_id,
                    subject,
                    sender_label,
                    body,
                    type,
                    read,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, 0, ?)
            `).run(

                id,

                subject,

                req.user.username,

                body,

                type,

                now()
            );

            audit(
                req.user.username,
                "SEND_APPLICATION_MESSAGE",
                req.ip,
                `Application #${id}`
            );

            return res.json({
                success: true
            });
        }

        // User target
        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE LOWER(username)
                    = LOWER(?)
                LIMIT 1
            `).get(target);

        if (!user) {

            return res.status(404).json({
                error:
                    "USER_NOT_FOUND"
            });
        }

        db.prepare(`
            INSERT INTO messages (
                user_id,
                subject,
                sender_label,
                body,
                type,
                read,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?)
        `).run(

            user.id,

            subject,

            req.user.username,

            body,

            type,

            now()
        );

        audit(
            req.user.username,
            "SEND_MESSAGE",
            req.ip,
            `Target: ${user.username}`
        );

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
                req.body.rank ||
                "AGENT"
            ).trim();

        const unit =
            String(
                req.body.unit ||
                "Intelligence Operations"
            ).trim();

        const clearance =
            String(
                req.body.clearance ||
                "RESTRICTED"
            ).trim();

        const inGameName =
            String(
                req.body.in_game_name ||
                ""
            ).trim();

        if (
            !username ||
            !password ||
            !inGameName
        ) {
            return res.status(400).json({
                error:
                    "MISSING_FIELDS"
            });
        }

        const existing =
            db.prepare(`
                SELECT id
                FROM users
                WHERE LOWER(username)
                    = LOWER(?)
            `).get(username);

        if (existing) {

            return res.status(409).json({
                error:
                    "USERNAME_EXISTS"
            });
        }

        db.prepare(`
            INSERT INTO users (
                username,
                password,
                rank,
                unit,
                clearance,
                in_game_name,
                discord_id,
                application_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)
        `).run(

            username,

            hashPassword(password),

            rank,

            unit,

            clearance,

            inGameName,

            now()
        );

        audit(
            req.user.username,
            "CREATE_USER",
            req.ip,
            `Created: ${username}`
        );

        res.json({
            success: true
        });
    }
);

// =====================================================
// MULTER / PDF STORAGE
// =====================================================

const storage =
    multer.diskStorage({

        destination:
            function (
                req,
                file,
                cb
            ) {
                cb(
                    null,
                    REPORTS_DIR
                );
            },

        filename:
            function (
                req,
                file,
                cb
            ) {

                const filename =
                    Date.now() +
                    "-" +
                    crypto
                        .randomBytes(8)
                        .toString("hex") +
                    ".pdf";

                cb(
                    null,
                    filename
                );
            }
    });

const upload =
    multer({

        storage,

        limits: {
            fileSize:
                20 * 1024 * 1024
        },

        fileFilter:
            function (
                req,
                file,
                cb
            ) {

                if (
                    file.mimetype !==
                    "application/pdf"
                ) {
                    return cb(
                        new Error(
                            "PDF_ONLY"
                        )
                    );
                }

                cb(null, true);
            }
    });

// =====================================================
// REGISTER PDF REPORT
// =====================================================

app.post(
    "/api/admin/reports",
    requireDiscord,
    requireAdmin,
    upload.single("pdf"),
    (req, res) => {

        const title =
            String(
                req.body.title || ""
            ).trim();

        const classification =
            String(
                req.body.classification ||
                "CONFIDENTIAL"
            ).trim();

        if (
            !title ||
            !req.file
        ) {

            if (req.file) {
                fs.unlink(
                    req.file.path,
                    () => {}
                );
            }

            return res.status(400).json({
                error:
                    "MISSING_REPORT"
            });
        }

        const result =
            db.prepare(`
                INSERT INTO reports (
                    title,
                    classification,
                    filename,
                    original_name,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
            `).run(

                title,

                classification,

                req.file.filename,

                req.file.originalname,

                now()
            );

        audit(
            req.user.username,
            "REGISTER_REPORT",
            req.ip,
            `Report #${result.lastInsertRowid}`
        );

        res.json({
            success: true,
            id:
                result.lastInsertRowid
        });
    }
);

// =====================================================
// VIEW PDF
// =====================================================

app.get(
    "/api/reports/:id",
    requireDiscord,
    requireLogin,
    (req, res) => {

        const report =
            db.prepare(`
                SELECT *
                FROM reports
                WHERE id = ?
            `).get(
                Number(req.params.id)
            );

        if (!report) {
            return res.status(404).send(
                "Report not found."
            );
        }

        if (!report.filename) {
            return res.status(404).send(
                "PDF file not found."
            );
        }

        const filePath =
            path.join(
                REPORTS_DIR,
                report.filename
            );

        if (
            !fs.existsSync(filePath)
        ) {
            return res.status(404).send(
                "PDF file is missing from storage."
            );
        }

        res.setHeader(
            "Content-Type",
            "application/pdf"
        );

        res.setHeader(
            "Content-Disposition",
            "inline; filename=\"report.pdf\""
        );

        res.sendFile(
            path.resolve(filePath)
        );
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

        const records =
            db.prepare(`
                SELECT
                    created_at,
                    actor_label,
                    action,
                    ip,
                    details
                FROM audit
                ORDER BY id DESC
                LIMIT 500
            `).all();

        res.json(records);
    }
);

// =====================================================
// HOME
// =====================================================

app.get(
    "/",
    (req, res) => {

        // Discord must be connected first.
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
    }
);

// =====================================================
// STATIC
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
// ERROR HANDLER
// =====================================================

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if (
            error.message ===
            "PDF_ONLY"
        ) {
            return res.status(400).json({
                error:
                    "PDF_ONLY"
            });
        }

        if (
            error.code ===
            "LIMIT_FILE_SIZE"
        ) {
            return res.status(400).json({
                error:
                    "PDF_TOO_LARGE"
            });
        }

        res.status(500).json({
            error:
                "INTERNAL_SERVER_ERROR"
        });
    }
);

// =====================================================
// 404
// =====================================================

app.use(
    (req, res) => {

        res.status(404).json({
            error:
                "NOT_FOUND"
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

        console.log("");
        console.log(
            "=========================================="
        );

        console.log(
            `CIA RP running on port ${PORT}`
        );

        console.log(
            `SQLite database: ${DB_PATH}`
        );

        console.log(
            `PDF storage: ${REPORTS_DIR}`
        );

        console.log(
            "Discord OAuth: ENABLED"
        );

        console.log(
            "Automatic CIA account creation: DISABLED"
        );

        console.log(
            "Persistent storage: ENABLED"
        );

        console.log(
            "=========================================="
        );
        console.log("");
    }
);
