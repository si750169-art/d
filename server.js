const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

// =====================================================
// CONFIG
// =====================================================

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

app.set("trust proxy", true);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// =====================================================
// DATABASE
// =====================================================

const dbPath = path.join(__dirname, "cia.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    rank TEXT NOT NULL,
    unit TEXT NOT NULL,
    clearance TEXT NOT NULL,
    in_game_name TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    age INTEGER NOT NULL,
    unit TEXT NOT NULL,
    experience TEXT NOT NULL,
    why TEXT NOT NULL,
    discord_id TEXT,
    status TEXT DEFAULT 'PENDING',
    dashboard_token TEXT UNIQUE NOT NULL,
    linked_user INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(linked_user) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    sender_label TEXT NOT NULL,
    recipient_user INTEGER,
    recipient_application INTEGER,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    type TEXT DEFAULT 'MESSAGE',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    read INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author INTEGER NOT NULL,
    classification TEXT NOT NULL,
    file TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor INTEGER,
    actor_label TEXT,
    action TEXT NOT NULL,
    ip TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

// =====================================================
// DATABASE MIGRATION
// =====================================================

function columnExists(table, column) {
    const columns = db
        .prepare(`PRAGMA table_info(${table})`)
        .all();

    return columns.some(
        (item) => item.name === column
    );
}

if (!columnExists("applications", "discord_id")) {
    db.exec(`
        ALTER TABLE applications
        ADD COLUMN discord_id TEXT
    `);

    console.log("Database migration: discord_id added.");
}

// =====================================================
// UPLOADS
// =====================================================

const uploads = path.join(__dirname, "uploads");

if (!fs.existsSync(uploads)) {
    fs.mkdirSync(uploads, {
        recursive: true
    });
}

// =====================================================
// SESSION
// =====================================================

const sessionSecret =
    process.env.SESSION_SECRET ||
    "CHANGE_THIS_SESSION_SECRET_TO_A_LONG_RANDOM_VALUE_2026";

app.use(
    session({
        secret: sessionSecret,

        resave: false,

        saveUninitialized: false,

        rolling: true,

        cookie: {
            httpOnly: true,

            secure:
                process.env.NODE_ENV === "production",

            sameSite: "lax",

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30
        }
    })
);

// =====================================================
// IP
// =====================================================

function getClientIP(req) {
    const cloudflareIP =
        req.headers["cf-connecting-ip"];

    if (cloudflareIP) {
        return String(cloudflareIP)
            .trim()
            .replace("::ffff:", "");
    }

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {
        return String(forwarded)
            .split(",")[0]
            .trim()
            .replace("::ffff:", "");
    }

    return String(
        req.socket.remoteAddress || "unknown"
    )
        .trim()
        .replace("::ffff:", "");
}

app.use((req, res, next) => {
    req.visitorIP = getClientIP(req);
    next();
});

// =====================================================
// COOKIE PARSER
// =====================================================

app.use((req, res, next) => {
    const raw = req.headers.cookie || "";

    req.cookies = {};

    raw.split(";").forEach((item) => {
        const index = item.indexOf("=");

        if (index <= 0) {
            return;
        }

        const key =
            item.slice(0, index).trim();

        const value =
            item.slice(index + 1).trim();

        try {
            req.cookies[key] =
                decodeURIComponent(value);
        } catch {
            req.cookies[key] = value;
        }
    });

    next();
});

// =====================================================
// RANKS
// =====================================================

const RANKS = [
    "AGENT",
    "AGENT OFFICER",
    "COMMAND OF CIA"
];

// ALPHA IS INTENTIONALLY NOT HERE.
// It cannot be created from the normal admin panel.

const ADMIN = [
    "AGENT OFFICER",
    "COMMAND OF CIA"
];

const COMMAND = [
    "COMMAND OF CIA"
];

const ALPHA_USERNAME = "log";
const ALPHA_PASSWORD = "log_1";
const ALPHA_RANK = "ALPHA";

const clearanceRank = {
    RESTRICTED: 1,
    CONFIDENTIAL: 2,
    SECRET: 3,
    "TOP SECRET": 4,
    OMEGA: 5
};

// =====================================================
// MULTER
// =====================================================

const upload = multer({
    dest: uploads,

    limits: {
        fileSize: 20 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
        if (
            file.mimetype !==
            "application/pdf"
        ) {
            return cb(
                new Error("ONLY_PDF_ALLOWED")
            );
        }

        cb(null, true);
    }
});

// =====================================================
// HELPERS
// =====================================================

function ip(req) {
    return (
        req.visitorIP ||
        getClientIP(req)
    );
}

function safeUser(user) {
    if (!user) {
        return null;
    }

    const copy = {
        ...user
    };

    delete copy.password;

    return copy;
}

function cleanUsername(name, id) {
    const base = String(name)
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "")
        .slice(0, 18);

    return (
        (base || "agent") +
        "_" +
        String(id).padStart(3, "0")
    );
}

function randomPassword() {
    return (
        crypto
            .randomBytes(6)
            .toString("base64url") +
        "!9"
    );
}

function canView(user, classification) {
    return (
        (clearanceRank[user.clearance] || 0) >=
        (clearanceRank[classification] || 99)
    );
}

// =====================================================
// AUDIT
// =====================================================

function audit(
    req,
    action,
    details = ""
) {
    const user =
        req.session?.user;

    try {
        db.prepare(`
            INSERT INTO audit
            (
                actor,
                actor_label,
                action,
                ip,
                details
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            user?.id || null,
            user?.username ||
                user?.rank ||
                "PUBLIC",
            action,
            ip(req),
            details
        );
    } catch (error) {
        console.error(
            "AUDIT ERROR:",
            error
        );
    }
}

// =====================================================
// ALPHA ACCOUNT
// ONLY CREATED FROM CODE
// =====================================================

function ensureAlpha() {
    const existing = db
        .prepare(
            "SELECT * FROM users WHERE username = ?"
        )
        .get(ALPHA_USERNAME);

    if (!existing) {
        const passwordHash =
            bcrypt.hashSync(
                ALPHA_PASSWORD,
                12
            );

        db.prepare(`
            INSERT INTO users
            (
                username,
                password,
                rank,
                unit,
                clearance,
                in_game_name
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            ALPHA_USERNAME,
            passwordHash,
            ALPHA_RANK,
            "CIA LOGISTICS",
            "OMEGA",
            "ALPHA"
        );

        console.log(
            "ALPHA ACCOUNT CREATED"
        );
    } else {
        // Force the account to remain ALPHA.
        // This prevents an admin from accidentally
        // changing it through another route.

        db.prepare(`
            UPDATE users
            SET
                rank = ?,
                unit = ?,
                clearance = ?,
                in_game_name = ?
            WHERE username = ?
        `).run(
            ALPHA_RANK,
            "CIA LOGISTICS",
            "OMEGA",
            "ALPHA",
            ALPHA_USERNAME
        );
    }
}

// =====================================================
// COMMAND ACCOUNT
// =====================================================

function ensureCommand() {
    const existing = db
        .prepare(
            "SELECT * FROM users WHERE username = ?"
        )
        .get("code_alpha");

    if (!existing) {
        const passwordHash =
            bcrypt.hashSync(
                "cia command91",
                12
            );

        db.prepare(`
            INSERT INTO users
            (
                username,
                password,
                rank,
                unit,
                clearance,
                in_game_name
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            "code_alpha",
            passwordHash,
            "COMMAND OF CIA",
            "CIA COMMAND",
            "OMEGA",
            "code_alpha"
        );

        console.log(
            "COMMAND ACCOUNT CREATED: code_alpha"
        );
    }
}

ensureAlpha();
ensureCommand();

// =====================================================
// AUTH
// =====================================================

function auth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "AUTH_REQUIRED"
        });
    }

    next();
}

// =====================================================
// BLOCK ALPHA FROM NORMAL SYSTEM
// =====================================================

function notAlpha(req, res, next) {
    if (
        req.session.user?.username ===
        ALPHA_USERNAME
    ) {
        return res.status(403).json({
            error: "ALPHA_LOG_ONLY"
        });
    }

    next();
}

// =====================================================
// ADMIN
// =====================================================

function admin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "AUTH_REQUIRED"
        });
    }

    if (
        req.session.user.username ===
        ALPHA_USERNAME
    ) {
        return res.status(403).json({
            error: "ALPHA_LOG_ONLY"
        });
    }

    if (
        !ADMIN.includes(
            req.session.user.rank
        )
    ) {
        return res.status(403).json({
            error: "FORBIDDEN"
        });
    }

    next();
}

// =====================================================
// COMMAND
// =====================================================

function command(req, res, next) {
    if (
        !req.session.user ||
        req.session.user.username !==
            "code_alpha"
    ) {
        return res.status(403).json({
            error: "COMMAND_ONLY"
        });
    }

    next();
}

// =====================================================
// ALPHA ONLY
// =====================================================

function alpha(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "AUTH_REQUIRED"
        });
    }

    if (
        req.session.user.username !==
            ALPHA_USERNAME ||
        req.session.user.rank !==
            ALPHA_RANK
    ) {
        return res.status(403).json({
            error: "ALPHA_ONLY"
        });
    }

    next();
}

// =====================================================
// APPLICATIONS
// =====================================================

app.post(
    "/api/applications",
    (req, res) => {
        try {
            const {
                name,
                age,
                unit,
                experience,
                why,
                discord_id
            } = req.body;

            if (
                !name ||
                !age ||
                !unit ||
                !experience ||
                !why ||
                !discord_id
            ) {
                return res.status(400).json({
                    error: "MISSING_FIELDS"
                });
            }

            const discordId =
                String(
                    discord_id
                ).trim();

            if (
                !/^\d{17,20}$/.test(
                    discordId
                )
            ) {
                return res.status(400).json({
                    error: "INVALID_DISCORD_ID"
                });
            }

            const token =
                crypto
                    .randomBytes(32)
                    .toString("hex");

            const result =
                db.prepare(`
                    INSERT INTO applications
                    (
                        name,
                        age,
                        unit,
                        experience,
                        why,
                        discord_id,
                        dashboard_token
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `).run(
                    String(name).trim(),
                    Number(age),
                    String(unit),
                    String(
                        experience
                    ).trim(),
                    String(why).trim(),
                    discordId,
                    token
                );

            audit(
                req,
                "APPLICATION_SUBMITTED",
                `application=${result.lastInsertRowid};discord_id=${discordId}`
            );

            res.cookie(
                "cia_application",
                token,
                {
                    httpOnly: true,
                    sameSite: "lax",
                    maxAge:
                        1000 *
                        60 *
                        60 *
                        24 *
                        365
                }
            );

            res.json({
                ok: true,
                id:
                    result.lastInsertRowid,
                token
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                error: "SERVER_ERROR"
            });
        }
    }
);

// =====================================================
// APPLICATION ME
// =====================================================

app.get(
    "/api/application/me",
    (req, res) => {
        const token =
            req.cookies
                ?.cia_application ||
            req.headers[
                "x-application-token"
            ] ||
            req.query.token;

        if (!token) {
            return res.json({
                application: null
            });
        }

        const application =
            db.prepare(`
                SELECT
                    id,
                    name,
                    age,
                    unit,
                    experience,
                    why,
                    discord_id,
                    status,
                    linked_user,
                    created_at,
                    updated_at
                FROM applications
                WHERE dashboard_token = ?
            `).get(token);

        if (!application) {
            return res.json({
                application: null
            });
        }

        const messages =
            db.prepare(`
                SELECT
                    id,
                    sender_label,
                    subject,
                    body,
                    type,
                    created_at,
                    read
                FROM messages
                WHERE recipient_application = ?
                ORDER BY id DESC
            `).all(
                application.id
            );

        let credentials = null;

        if (application.linked_user) {
            credentials =
                db.prepare(`
                    SELECT
                        username,
                        rank,
                        unit,
                        clearance
                    FROM users
                    WHERE id = ?
                `).get(
                    application.linked_user
                );
        }

        res.json({
            application,
            messages,
            credentials
        });
    }
);

// =====================================================
// LOGIN
// =====================================================

app.post(
    "/api/login",
    (req, res, next) => {
        try {
            const username =
                String(
                    req.body.username ||
                        ""
                ).trim();

            const password =
                String(
                    req.body.password ||
                        ""
                );

            const user =
                db.prepare(
                    "SELECT * FROM users WHERE username = ?"
                ).get(username);

            if (
                !user ||
                !bcrypt.compareSync(
                    password,
                    user.password
                )
            ) {
                audit(
                    req,
                    "LOGIN_FAILED",
                    `username=${username}`
                );

                return res.status(401).json({
                    error:
                        "INVALID_CREDENTIALS"
                });
            }

            req.session.regenerate(
                (error) => {
                    if (error) {
                        console.error(
                            "SESSION REGENERATE ERROR:",
                            error
                        );

                        return next(
                            error
                        );
                    }

                    req.session.user =
                        user;

                    req.session.save(
                        (saveError) => {
                            if (
                                saveError
                            ) {
                                console.error(
                                    "SESSION SAVE ERROR:",
                                    saveError
                                );

                                return next(
                                    saveError
                                );
                            }

                            audit(
                                req,
                                "LOGIN_SUCCESS",
                                `rank=${user.rank}`
                            );

                            res.json({
                                user:
                                    safeUser(
                                        user
                                    )
                            });
                        }
                    );
                }
            );
        } catch (error) {
            next(error);
        }
    }
);

// =====================================================
// LOGOUT
// =====================================================

app.post(
    "/api/logout",
    auth,
    (req, res) => {
        audit(
            req,
            "LOGOUT"
        );

        req.session.destroy(
            (error) => {
                if (error) {
                    console.error(
                        error
                    );

                    return res.status(
                        500
                    ).json({
                        error:
                            "LOGOUT_FAILED"
                    });
                }

                res.clearCookie(
                    "connect.sid"
                );

                res.json({
                    ok: true
                });
            }
        );
    }
);

// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/me",
    (req, res) => {
        res.json({
            user:
                safeUser(
                    req.session.user
                )
        });
    }
);

// =====================================================
// ALPHA DASHBOARD
// ONLY LOGS
// =====================================================

app.get(
    "/api/alpha/dashboard",
    alpha,
    (req, res) => {
        const logs =
            db.prepare(`
                SELECT
                    id,
                    actor,
                    actor_label,
                    action,
                    ip,
                    details,
                    created_at
                FROM audit
                ORDER BY id DESC
                LIMIT 500
            `).all();

        res.json({
            ok: true,
            mode: "ALPHA_LOG_ONLY",
            logs
        });
    }
);

// =====================================================
// ALPHA LOGOUT
// =====================================================

app.post(
    "/api/alpha/logout",
    alpha,
    (req, res) => {
        audit(
            req,
            "ALPHA_LOGOUT"
        );

        req.session.destroy(
            (error) => {
                if (error) {
                    return res.status(
                        500
                    ).json({
                        error:
                            "LOGOUT_FAILED"
                    });
                }

                res.clearCookie(
                    "connect.sid"
                );

                res.json({
                    ok: true
                });
            }
        );
    }
);

// =====================================================
// DASHBOARD
// =====================================================

app.get(
    "/api/dashboard",
    auth,
    notAlpha,
    (req, res) => {
        const user =
            req.session.user;

        const messages =
            db.prepare(`
                SELECT
                    id,
                    sender_label,
                    subject,
                    body,
                    type,
                    created_at,
                    read
                FROM messages
                WHERE recipient_user = ?
                ORDER BY id DESC
            `).all(user.id);

        const reports =
            db.prepare(`
                SELECT
                    id,
                    title,
                    author,
                    classification,
                    created_at
                FROM reports
                ORDER BY id DESC
            `)
                .all()
                .filter(
                    (report) =>
                        canView(
                            user,
                            report.classification
                        )
                );

        res.json({
            user:
                safeUser(user),
            messages,
            reports
        });
    }
);

// =====================================================
// MESSAGE READ
// =====================================================

app.post(
    "/api/messages/:id/read",
    auth,
    notAlpha,
    (req, res) => {
        db.prepare(`
            UPDATE messages
            SET read = 1
            WHERE id = ?
            AND recipient_user = ?
        `).run(
            req.params.id,
            req.session.user.id
        );

        res.json({
            ok: true
        });
    }
);

// =====================================================
// ADMIN APPLICATIONS
// =====================================================

app.get(
    "/api/admin/applications",
    admin,
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
                    discord_id,
                    status,
                    linked_user,
                    created_at,
                    updated_at
                FROM applications
                ORDER BY id DESC
            `).all();

        res.json(
            applications
        );
    }
);

// =====================================================
// APPROVE APPLICATION
// =====================================================

app.post(
    "/api/admin/application/:id/approve",
    admin,
    (req, res) => {
        const application =
            db.prepare(
                "SELECT * FROM applications WHERE id = ?"
            ).get(
                req.params.id
            );

        if (!application) {
            return res.sendStatus(
                404
            );
        }

        if (
            application.status ===
            "APPROVED"
        ) {
            return res.status(400).json({
                error:
                    "ALREADY_APPROVED"
            });
        }

        let username =
            cleanUsername(
                application.name,
                application.id
            );

        while (
            db.prepare(
                "SELECT id FROM users WHERE username = ?"
            ).get(username)
        ) {
            username =
                cleanUsername(
                    application.name,
                    application.id
                ) +
                "_" +
                crypto
                    .randomBytes(2)
                    .toString("hex");
        }

        const password =
            randomPassword();

        const rank = "AGENT";
        const clearance =
            "RESTRICTED";

        const userResult =
            db.prepare(`
                INSERT INTO users
                (
                    username,
                    password,
                    rank,
                    unit,
                    clearance,
                    in_game_name
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                username,
                bcrypt.hashSync(
                    password,
                    12
                ),
                rank,
                application.unit,
                clearance,
                application.name
            );

        db.prepare(`
            UPDATE applications
            SET
                status = ?,
                linked_user = ?,
                updated_at =
                    CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(
            "APPROVED",
            userResult.lastInsertRowid,
            application.id
        );

        const body =
`Your CIA application has been APPROVED.

USERNAME: ${username}
PASSWORD: ${password}
UNIT: ${application.unit}
RANK: ${rank}
CLEARANCE: ${clearance}

Keep these credentials private.`;

        db.prepare(`
            INSERT INTO messages
            (
                sender_id,
                sender_label,
                recipient_user,
                recipient_application,
                subject,
                body,
                type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            req.session.user.id,
            req.session.user.rank,
            userResult.lastInsertRowid,
            application.id,
            "ACCOUNT ISSUED",
            body,
            "CREDENTIALS"
        );

        audit(
            req,
            "APPLICATION_APPROVED",
            `application=${application.id};user=${username};newUser=${userResult.lastInsertRowid}`
        );

        res.json({
            ok: true,
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
    admin,
    (req, res) => {
        db.prepare(`
            UPDATE applications
            SET
                status = ?,
                updated_at =
                    CURRENT_TIMESTAMP
            WHERE id = ?
        `).run(
            "REJECTED",
            req.params.id
        );

        audit(
            req,
            "APPLICATION_REJECTED",
            `application=${req.params.id}`
        );

        res.json({
            ok: true
        });
    }
);

// =====================================================
// ADMIN USERS
// =====================================================

app.get(
    "/api/admin/users",
    admin,
    (req, res) => {
        const users =
            db.prepare(`
                SELECT
                    id,
                    username,
                    in_game_name,
                    rank,
                    unit,
                    clearance,
                    created_at
                FROM users
                ORDER BY id DESC
            `).all();

        res.json(users);
    }
);

// =====================================================
// CREATE USER
// =====================================================

app.post(
    "/api/admin/users",
    command,
    (req, res) => {
        const {
            username,
            password,
            rank,
            unit,
            clearance
        } = req.body;

        if (
            !username ||
            !password ||
            !RANKS.includes(rank) ||
            !unit ||
            !Object.prototype.hasOwnProperty.call(
                clearanceRank,
                clearance
            )
        ) {
            return res.status(400).json({
                error:
                    "INVALID_DATA"
            });
        }

        // Explicitly prevent creation of ALPHA.
        if (
            username.toLowerCase() ===
                ALPHA_USERNAME ||
            rank === ALPHA_RANK
        ) {
            return res.status(403).json({
                error:
                    "ALPHA_CANNOT_BE_CREATED_HERE"
            });
        }

        try {
            const result =
                db.prepare(`
                    INSERT INTO users
                    (
                        username,
                        password,
                        rank,
                        unit,
                        clearance,
                        in_game_name
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(
                    username,
                    bcrypt.hashSync(
                        password,
                        12
                    ),
                    rank,
                    unit,
                    clearance,
                    req.body
                        .in_game_name ||
                        username
                );

            audit(
                req,
                "USER_CREATED",
                `user=${username};rank=${rank}`
            );

            res.json({
                ok: true,
                id:
                    result.lastInsertRowid
            });
        } catch {
            res.status(400).json({
                error:
                    "USERNAME_EXISTS"
            });
        }
    }
);

// =====================================================
// SEND MESSAGE
// =====================================================

app.post(
    "/api/admin/message",
    admin,
    (req, res) => {
        const {
            target,
            subject,
            body,
            type = "MESSAGE"
        } = req.body;

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

        if (
            String(target).startsWith(
                "app:"
            )
        ) {
            const id =
                Number(
                    String(
                        target
                    ).slice(4)
                );

            const application =
                db.prepare(
                    "SELECT id FROM applications WHERE id = ?"
                ).get(id);

            if (!application) {
                return res.status(404).json({
                    error:
                        "APPLICATION_NOT_FOUND"
                });
            }

            db.prepare(`
                INSERT INTO messages
                (
                    sender_id,
                    sender_label,
                    recipient_application,
                    subject,
                    body,
                    type
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                req.session.user.id,
                req.session.user.rank,
                id,
                subject,
                body,
                type
            );

            audit(
                req,
                "APPLICATION_MESSAGE_SENT",
                `application=${id};type=${type};subject=${subject}`
            );

            return res.json({
                ok: true
            });
        }

        const user =
            db.prepare(
                "SELECT id FROM users WHERE username = ?"
            ).get(target);

        if (!user) {
            return res.status(404).json({
                error:
                    "USER_NOT_FOUND"
            });
        }

        db.prepare(`
            INSERT INTO messages
            (
                sender_id,
                sender_label,
                recipient_user,
                subject,
                body,
                type
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            req.session.user.id,
            req.session.user.rank,
            user.id,
            subject,
            body,
            type
        );

        audit(
            req,
            "MESSAGE_SENT",
            `to=${target};type=${type};subject=${subject}`
        );

        res.json({
            ok: true
        });
    }
);

// =====================================================
// REPORT UPLOAD
// =====================================================

app.post(
    "/api/admin/reports",
    admin,
    upload.single("pdf"),
    (req, res) => {
        if (
            !req.body.title ||
            !req.file
        ) {
            return res.status(400).json({
                error:
                    "TITLE_AND_PDF_REQUIRED"
            });
        }

        const finalPath =
            path.join(
                uploads,
                req.file.filename +
                    ".pdf"
            );

        fs.renameSync(
            req.file.path,
            finalPath
        );

        const classification =
            req.body.classification ||
            "CONFIDENTIAL";

        if (
            !Object.prototype.hasOwnProperty.call(
                clearanceRank,
                classification
            )
        ) {
            try {
                fs.unlinkSync(
                    finalPath
                );
            } catch {}

            return res.status(400).json({
                error:
                    "INVALID_CLASSIFICATION"
            });
        }

        const result =
            db.prepare(`
                INSERT INTO reports
                (
                    title,
                    author,
                    classification,
                    file
                )
                VALUES (?, ?, ?, ?)
            `).run(
                req.body.title,
                req.session.user.id,
                classification,
                finalPath
            );

        audit(
            req,
            "REPORT_REGISTERED",
            `report=${result.lastInsertRowid};title=${req.body.title}`
        );

        res.json({
            ok: true,
            id:
                result.lastInsertRowid
        });
    }
);

// =====================================================
// VIEW REPORT
// =====================================================

app.get(
    "/api/reports/:id",
    auth,
    notAlpha,
    (req, res) => {
        const report =
            db.prepare(
                "SELECT * FROM reports WHERE id = ?"
            ).get(
                req.params.id
            );

        if (
            !report ||
            !canView(
                req.session.user,
                report.classification
            ) ||
            !fs.existsSync(
                report.file
            )
        ) {
            return res.sendStatus(
                404
            );
        }

        audit(
            req,
            "REPORT_VIEWED",
            `report=${report.id}`
        );

        res.type(
            "application/pdf"
        );

        res.sendFile(
            path.resolve(
                report.file
            )
        );
    }
);

// =====================================================
// COMMAND AUDIT
// ONLY code_alpha
// =====================================================

app.get(
    "/api/command/audit",
    command,
    (req, res) => {
        const logs =
            db.prepare(`
                SELECT
                    id,
                    actor,
                    actor_label,
                    action,
                    ip,
                    details,
                    created_at
                FROM audit
                ORDER BY id DESC
                LIMIT 500
            `).all();

        res.json({
            ok: true,
            logs
        });
    }
);

// =====================================================
// OLD ADMIN LOG ROUTE
// DISABLED FOR NORMAL ADMIN
// =====================================================

app.get(
    "/api/admin/logs",
    (req, res) => {
        if (
            !req.session.user
        ) {
            return res.status(401).json({
                error:
                    "AUTH_REQUIRED"
            });
        }

        return res.status(403).json({
            error:
                "LOGS_MOVED_TO_ALPHA"
        });
    }
);

// =====================================================
// SECTOR
// =====================================================

app.get(
    "/api/sector",
    auth,
    notAlpha,
    (req, res) => {
        const users =
            db.prepare(`
                SELECT
                    id,
                    username,
                    in_game_name,
                    rank,
                    unit,
                    clearance,
                    created_at
                FROM users
                WHERE username != ?
                ORDER BY
                    CASE rank
                        WHEN "COMMAND OF CIA" THEN 1
                        WHEN "AGENT OFFICER" THEN 2
                        WHEN "ALPHA" THEN 3
                        ELSE 4
                    END,
                    id
            `).all(
                ALPHA_USERNAME
            );

        res.json(users);
    }
);

// =====================================================
// HEALTH CHECK
// =====================================================

app.get(
    "/api/health",
    (req, res) => {
        try {
            db.prepare(
                "SELECT 1"
            ).get();

            res.json({
                ok: true,
                server: "online",
                database: "online",
                time:
                    new Date().toISOString()
            });
        } catch (error) {
            console.error(
                "HEALTH ERROR:",
                error
            );

            res.status(500).json({
                ok: false,
                server: "online",
                database: "offline"
            });
        }
    }
);

// =====================================================
// STATIC WEBSITE
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
// INDEX
// =====================================================

app.get(
    "/",
    (req, res) => {
        const indexPath =
            path.join(
                __dirname,
                "public",
                "index.html"
            );

        if (
            !fs.existsSync(
                indexPath
            )
        ) {
            return res.status(
                404
            ).send(
                "index.html not found. Make sure public/index.html exists."
            );
        }

        res.sendFile(
            indexPath
        );
    }
);

// =====================================================
// 404 API
// =====================================================

app.use(
    "/api",
    (req, res) => {
        res.status(404).json({
            error:
                "API_ROUTE_NOT_FOUND",
            path: req.path
        });
    }
);

// =====================================================
// ERROR HANDLER
// =====================================================

app.use(
    (
        err,
        req,
        res,
        next
    ) => {
        console.error(
            "SERVER ERROR:",
            err
        );

        if (
            res.headersSent
        ) {
            return next(err);
        }

        if (
            err.message ===
            "ONLY_PDF_ALLOWED"
        ) {
            return res.status(
                400
            ).json({
                error:
                    "ONLY_PDF_ALLOWED"
            });
        }

        res.status(500).json({
            error:
                "SERVER_ERROR",

            message:
                process.env
                    .NODE_ENV ===
                "development"
                    ? err.message
                    : "Internal server error"
        });
    }
);

// =====================================================
// START
// =====================================================

const server =
    app.listen(
        PORT,
        HOST,
        () => {
            console.log(
                "========================================"
            );

            console.log(
                "CIA RP SERVER ONLINE"
            );

            console.log(
                `HTTP: http://${HOST}:${PORT}`
            );

            console.log(
                `PORT: ${PORT}`
            );

            console.log(
                `DATABASE: ${dbPath}`
            );

            console.log(
                `PUBLIC: ${path.join(
                    __dirname,
                    "public"
                )}`
            );

            console.log(
                "ALPHA ACCOUNT: log"
            );

            console.log(
                "ALPHA MODE: LOG ONLY"
            );

            console.log(
                "========================================"
            );
        }
    );

// =====================================================
// GRACEFUL SHUTDOWN
// =====================================================

function shutdown() {
    console.log(
        "Shutting down..."
    );

    server.close(() => {
        try {
            db.close();
        } catch {}

        process.exit(0);
    });
}

process.on(
    "SIGTERM",
    shutdown
);

process.on(
    "SIGINT",
    shutdown
);
