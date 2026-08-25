const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = Number(process.env.PORT || 3000);

/*
|--------------------------------------------------------------------------
| PATHS
|--------------------------------------------------------------------------
|
| Render:
| DATA_DIR can be configured to a persistent disk path.
|
| Local:
| ./data will be used automatically.
|
*/

const DATA_DIR =
    process.env.DATA_DIR ||
    path.join(__dirname, "data");

const PUBLIC_DIR =
    path.join(__dirname, "public");

const UPLOAD_DIR =
    path.join(DATA_DIR, "reports");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

const dbPath = path.join(DATA_DIR, "cia.sqlite");

const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,

    in_game_name TEXT NOT NULL DEFAULT '',
    rank TEXT NOT NULL DEFAULT 'AGENT',
    unit TEXT NOT NULL DEFAULT 'Intelligence Operations',
    clearance TEXT NOT NULL DEFAULT 'RESTRICTED',

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    name TEXT NOT NULL,
    age INTEGER NOT NULL,
    unit TEXT NOT NULL,

    experience TEXT NOT NULL,
    why TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'PENDING',

    applicant_token TEXT NOT NULL UNIQUE,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER,
    application_id INTEGER,

    sender_label TEXT NOT NULL,

    subject TEXT NOT NULL,
    body TEXT NOT NULL,

    type TEXT NOT NULL DEFAULT 'MESSAGE',

    read INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

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

    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    ip TEXT NOT NULL,

    user_agent TEXT,
    language TEXT,
    timezone TEXT,

    path TEXT,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    actor_label TEXT NOT NULL,
    action TEXT NOT NULL,

    ip TEXT,

    details TEXT,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

/*
|--------------------------------------------------------------------------
| DEFAULT COMMAND ACCOUNT
|--------------------------------------------------------------------------
|
| Create a command account automatically if it doesn't exist.
|
| Change these through Render Environment Variables.
|
*/

const DEFAULT_ADMIN_USERNAME =
    process.env.ADMIN_USERNAME || "command_cia";

const DEFAULT_ADMIN_PASSWORD =
    process.env.ADMIN_PASSWORD || "ChangeThisPassword123!";

const existingAdmin = db
    .prepare(
        "SELECT id FROM users WHERE username = ?"
    )
    .get(DEFAULT_ADMIN_USERNAME);

if (!existingAdmin) {

    const passwordHash =
        bcrypt.hashSync(
            DEFAULT_ADMIN_PASSWORD,
            12
        );

    db.prepare(`
        INSERT INTO users
        (
            username,
            password_hash,
            in_game_name,
            rank,
            unit,
            clearance
        )
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        DEFAULT_ADMIN_USERNAME,
        passwordHash,
        "CIA COMMAND",
        "COMMAND OF CIA",
        "Command",
        "OMEGA"
    );

    console.log(
        `Created command account: ${DEFAULT_ADMIN_USERNAME}`
    );
}

/*
|--------------------------------------------------------------------------
| EXPRESS
|--------------------------------------------------------------------------
*/

app.set("trust proxy", 1);

app.use(express.json({
    limit: "2mb"
}));

app.use(express.urlencoded({
    extended: true
}));

app.use(cookieParser());

/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

app.use(
    session({
        store: new SQLiteStore({
            db: "sessions.sqlite",
            dir: DATA_DIR
        }),

        secret:
            process.env.SESSION_SECRET ||
            "CHANGE_THIS_SESSION_SECRET_123456789",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,

            secure:
                process.env.NODE_ENV === "production",

            sameSite: "lax",

            maxAge:
                7 * 24 * 60 * 60 * 1000
        }
    })
);

/*
|--------------------------------------------------------------------------
| IP
|--------------------------------------------------------------------------
*/

function getClientIP(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {

        return forwarded
            .split(",")[0]
            .trim();
    }

    return (
        req.socket.remoteAddress ||
        req.ip ||
        "UNKNOWN"
    );
}

/*
|--------------------------------------------------------------------------
| VISITOR LOG
|--------------------------------------------------------------------------
|
| Logs the visitor's IP when they first enter the website
| during their current session.
|
*/

app.use((req, res, next) => {

    const ignored =
        req.path.startsWith("/api/") ||
        req.path.startsWith("/reports/") ||
        req.path.startsWith("/auth/") ||
        req.path.includes(".") ||
        req.path === "/favicon.ico";

    if (
        !ignored &&
        !req.session.visitLogged
    ) {

        const ip =
            getClientIP(req);

        const userAgent =
            req.headers["user-agent"] || null;

        const language =
            req.headers["accept-language"] || null;

        db.prepare(`
            INSERT INTO visits
            (
                ip,
                user_agent,
                language,
                path
            )
            VALUES (?, ?, ?, ?)
        `).run(
            ip,
            userAgent,
            language,
            req.path
        );

        req.session.visitLogged = true;
    }

    next();
});

/*
|--------------------------------------------------------------------------
| AUDIT
|--------------------------------------------------------------------------
*/

function audit(
    actor,
    action,
    req,
    details = ""
) {

    db.prepare(`
        INSERT INTO audit
        (
            actor_label,
            action,
            ip,
            details
        )
        VALUES (?, ?, ?, ?)
    `).run(
        actor,
        action,
        getClientIP(req),
        details
    );
}

/*
|--------------------------------------------------------------------------
| AUTH HELPERS
|--------------------------------------------------------------------------
*/

function requireLogin(req, res, next) {

    if (!req.session.user) {

        return res.status(401).json({
            error: "NOT_AUTHENTICATED"
        });
    }

    next();
}

function requireAdmin(req, res, next) {

    if (!req.session.user) {

        return res.status(401).json({
            error: "NOT_AUTHENTICATED"
        });
    }

    if (
        req.session.user.rank !==
            "AGENT OFFICER" &&
        req.session.user.rank !==
            "COMMAND OF CIA"
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
            error: "NOT_AUTHENTICATED"
        });
    }

    if (
        req.session.user.rank !==
        "COMMAND OF CIA"
    ) {

        return res.status(403).json({
            error: "COMMAND_ONLY"
        });
    }

    next();
}

/*
|--------------------------------------------------------------------------
| APPLICATION TOKEN
|--------------------------------------------------------------------------
*/

function generateToken() {

    return (
        require("crypto")
            .randomBytes(32)
            .toString("hex")
    );
}

/*
|--------------------------------------------------------------------------
| APPLICATION
|--------------------------------------------------------------------------
*/

app.post(
    "/api/applications",
    (req, res) => {

        try {

            const {
                name,
                age,
                unit,
                experience,
                why
            } = req.body;

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

            const token =
                generateToken();

            const result =
                db.prepare(`
                    INSERT INTO applications
                    (
                        name,
                        age,
                        unit,
                        experience,
                        why,
                        applicant_token
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                `).run(
                    String(name).trim(),
                    Number(age),
                    String(unit).trim(),
                    String(experience).trim(),
                    String(why).trim(),
                    token
                );

            audit(
                "PUBLIC APPLICANT",
                "APPLICATION_SUBMITTED",
                req,
                `Application #${result.lastInsertRowid}`
            );

            res.json({
                success: true,
                token
            });

        } catch (error) {

            console.error(
                "APPLICATION ERROR:",
                error
            );

            res.status(500).json({
                error: "APPLICATION_FAILED"
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| APPLICATION COOKIE
|--------------------------------------------------------------------------
*/

function getApplicationToken(req) {

    const cookie =
        req.headers.cookie || "";

    const match =
        cookie.match(
            /(?:^|;\s*)cia_application=([^;]+)/
        );

    if (!match) {
        return null;
    }

    try {

        return decodeURIComponent(
            match[1]
        );

    } catch {

        return null;
    }
}

/*
|--------------------------------------------------------------------------
| APPLICATION ME
|--------------------------------------------------------------------------
*/

app.get(
    "/api/application/me",
    (req, res) => {

        const token =
            getApplicationToken(req);

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
                    status,
                    created_at
                FROM applications
                WHERE applicant_token = ?
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
                    subject,
                    body,
                    type,
                    sender_label,
                    read,
                    created_at
                FROM messages
                WHERE application_id = ?
                ORDER BY id DESC
            `).all(application.id);

        let credentials = null;

        if (
            application.status ===
            "APPROVED"
        ) {

            credentials =
                db.prepare(`
                    SELECT
                        username,
                        rank,
                        unit
                    FROM users
                    WHERE in_game_name = ?
                    ORDER BY id DESC
                    LIMIT 1
                `).get(application.name);
        }

        res.json({
            application,
            messages,
            credentials:
                credentials || null
        });
    }
);

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

app.post(
    "/api/login",
    (req, res) => {

        const {
            username,
            password
        } = req.body;

        if (!username || !password) {

            return res.status(400).json({
                error: "MISSING_CREDENTIALS"
            });
        }

        const user =
            db.prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `).get(
                String(username).trim()
            );

        if (
            !user ||
            !bcrypt.compareSync(
                password,
                user.password_hash
            )
        ) {

            audit(
                "UNKNOWN",
                "LOGIN_FAILED",
                req,
                `Username: ${String(username).slice(0, 80)}`
            );

            return res.status(401).json({
                error: "INVALID_CREDENTIALS"
            });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            in_game_name:
                user.in_game_name,
            rank: user.rank,
            unit: user.unit,
            clearance:
                user.clearance
        };

        audit(
            user.username,
            "LOGIN",
            req
        );

        req.session.save(
            () => {

                res.json({
                    success: true,

                    user:
                        req.session.user
                });
            }
        );
    }
);

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

app.get(
    "/api/me",
    (req, res) => {

        if (!req.session.user) {

            return res.json({
                user: null
            });
        }

        res.json({
            user:
                req.session.user
        });
    }
);

/*
|--------------------------------------------------------------------------
| DASHBOARD
|--------------------------------------------------------------------------
*/

app.get(
    "/api/dashboard",
    requireLogin,
    (req, res) => {

        const userId =
            req.session.user.id;

        const messages =
            db.prepare(`
                SELECT
                    id,
                    subject,
                    body,
                    type,
                    sender_label,
                    read,
                    created_at
                FROM messages
                WHERE user_id = ?
                ORDER BY id DESC
            `).all(userId);

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
            messages,
            reports
        });
    }
);

/*
|--------------------------------------------------------------------------
| SECTOR
|--------------------------------------------------------------------------
*/

app.get(
    "/api/sector",
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

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

app.post(
    "/api/logout",
    requireLogin,
    (req, res) => {

        const username =
            req.session.user.username;

        audit(
            username,
            "LOGOUT",
            req
        );

        req.session.destroy(
            () => {

                res.clearCookie(
                    "connect.sid"
                );

                res.json({
                    success: true
                });
            }
        );
    }
);

/*
|--------------------------------------------------------------------------
| ADMIN APPLICATIONS
|--------------------------------------------------------------------------
*/

app.get(
    "/api/admin/applications",
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

/*
|--------------------------------------------------------------------------
| ADMIN USERS
|--------------------------------------------------------------------------
*/

app.get(
    "/api/admin/users",
    requireAdmin,
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
                ORDER BY id ASC
            `).all();

        res.json(users);
    }
);

/*
|--------------------------------------------------------------------------
| APPROVE APPLICATION
|--------------------------------------------------------------------------
*/

app.post(
    "/api/admin/application/:id/approve",
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
                error: "APPLICATION_NOT_FOUND"
            });
        }

        if (
            application.status ===
            "APPROVED"
        ) {

            return res.status(400).json({
                error: "ALREADY_APPROVED"
            });
        }

        const username =
            "agent_" +
            String(id).padStart(3, "0");

        let finalUsername =
            username;

        let counter = 1;

        while (
            db.prepare(
                "SELECT id FROM users WHERE username = ?"
            ).get(finalUsername)
        ) {

            finalUsername =
                `${username}_${counter}`;

            counter++;
        }

        const password =
            require("crypto")
                .randomBytes(6)
                .toString("base64")
                .replace(/[^a-zA-Z0-9]/g, "")
                .slice(0, 10);

        const passwordHash =
            bcrypt.hashSync(
                password,
                12
            );

        const result =
            db.prepare(`
                INSERT INTO users
                (
                    username,
                    password_hash,
                    in_game_name,
                    rank,
                    unit,
                    clearance
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                finalUsername,
                passwordHash,
                application.name,
                "AGENT",
                application.unit,
                "RESTRICTED"
            );

        db.prepare(`
            UPDATE applications
            SET status = 'APPROVED'
            WHERE id = ?
        `).run(id);

        db.prepare(`
            INSERT INTO messages
            (
                user_id,
                sender_label,
                subject,
                body,
                type
            )
            VALUES (?, ?, ?, ?, ?)
        `).run(
            result.lastInsertRowid,
            "CIA COMMAND",
            "ACCOUNT ISSUED",
            `Your CIA personnel account has been issued.

USERNAME: ${finalUsername}
PASSWORD: ${password}

Keep these credentials secure.`,
            "MESSAGE"
        );

        audit(
            req.session.user.username,
            "APPLICATION_APPROVED",
            req,
            `Application #${id}; Account ${finalUsername}`
        );

        res.json({
            success: true,
            username: finalUsername,
            password
        });
    }
);

/*
|--------------------------------------------------------------------------
| REJECT APPLICATION
|--------------------------------------------------------------------------
*/

app.post(
    "/api/admin/application/:id/reject",
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
                error: "APPLICATION_NOT_FOUND"
            });
        }

        db.prepare(`
            UPDATE applications
            SET status = 'REJECTED'
            WHERE id = ?
        `).run(id);

        audit(
            req.session.user.username,
            "APPLICATION_REJECTED",
            req,
            `Application #${id}`
        );

        res.json({
            success: true
        });
    }
);

/*
|--------------------------------------------------------------------------
| SEND MESSAGE
|--------------------------------------------------------------------------
*/

app.post(
    "/api/admin/message",
    requireAdmin,
    (req, res) => {

        const {
            target,
            subject,
            body,
            type
        } = req.body;

        if (
            !target ||
            !subject ||
            !body
        ) {

            return res.status(400).json({
                error: "MISSING_FIELDS"
            });
        }

        let userId = null;
        let applicationId = null;

        if (
            String(target).startsWith(
                "app:"
            )
        ) {

            applicationId =
                Number(
                    String(target)
                        .replace("app:", "")
                );

            const appExists =
                db.prepare(`
                    SELECT id
                    FROM applications
                    WHERE id = ?
                `).get(applicationId);

            if (!appExists) {

                return res.status(404).json({
                    error: "APPLICATION_NOT_FOUND"
                });
            }

        } else {

            const user =
                db.prepare(`
                    SELECT id
                    FROM users
                    WHERE username = ?
                `).get(
                    String(target).trim()
                );

            if (!user) {

                return res.status(404).json({
                    error: "USER_NOT_FOUND"
                });
            }

            userId = user.id;
        }

        db.prepare(`
            INSERT INTO messages
            (
                user_id,
                application_id,
                sender_label,
                subject,
                body,
                type
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            userId,
            applicationId,
            req.session.user.username,
            String(subject).trim(),
            String(body).trim(),
            type || "MESSAGE"
        );

        audit(
            req.session.user.username,
            "MESSAGE_SENT",
            req,
            `Target: ${target}`
        );

        res.json({
            success: true
        });
    }
);

/*
|--------------------------------------------------------------------------
| CREATE USER
|--------------------------------------------------------------------------
*/

app.post(
    "/api/admin/users",
    requireCommand,
    (req, res) => {

        const {
            username,
            password,
            rank,
            unit,
            clearance,
            in_game_name
        } = req.body;

        if (
            !username ||
            !password ||
            !rank ||
            !unit ||
            !clearance ||
            !in_game_name
        ) {

            return res.status(400).json({
                error: "MISSING_FIELDS"
            });
        }

        const exists =
            db.prepare(`
                SELECT id
                FROM users
                WHERE username = ?
            `).get(
                String(username).trim()
            );

        if (exists) {

            return res.status(409).json({
                error: "USERNAME_EXISTS"
            });
        }

        const passwordHash =
            bcrypt.hashSync(
                password,
                12
            );

        const result =
            db.prepare(`
                INSERT INTO users
                (
                    username,
                    password_hash,
                    in_game_name,
                    rank,
                    unit,
                    clearance
                )
                VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                String(username).trim(),
                passwordHash,
                String(in_game_name).trim(),
                String(rank).trim(),
                String(unit).trim(),
                String(clearance).trim()
            );

        audit(
            req.session.user.username,
            "USER_CREATED",
            req,
            `User ID ${result.lastInsertRowid}`
        );

        res.json({
            success: true
        });
    }
);

/*
|--------------------------------------------------------------------------
| PDF UPLOAD
|--------------------------------------------------------------------------
*/

const upload =
    multer({
        storage:
            multer.diskStorage({

                destination:
                    function (
                        req,
                        file,
                        cb
                    ) {

                        cb(
                            null,
                            UPLOAD_DIR
                        );
                    },

                filename:
                    function (
                        req,
                        file,
                        cb
                    ) {

                        const safe =
                            Date.now() +
                            "-" +
                            file.originalname
                                .replace(
                                    /[^a-zA-Z0-9._-]/g,
                                    "_"
                                );

                        cb(
                            null,
                            safe
                        );
                    }
            }),

        limits: {
            fileSize:
                15 * 1024 * 1024
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

                cb(
                    null,
                    true
                );
            }
    });

/*
|--------------------------------------------------------------------------
| REGISTER REPORT
|--------------------------------------------------------------------------
*/

app.post(
    "/api/admin/reports",
    requireAdmin,
    upload.single("pdf"),
    (req, res) => {

        if (!req.file) {

            return res.status(400).json({
                error: "PDF_REQUIRED"
            });
        }

        const title =
            String(
                req.body.title || ""
            ).trim();

        const classification =
            String(
                req.body.classification ||
                "CONFIDENTIAL"
            ).trim();

        if (!title) {

            fs.unlinkSync(
                req.file.path
            );

            return res.status(400).json({
                error: "TITLE_REQUIRED"
            });
        }

        const result =
            db.prepare(`
                INSERT INTO reports
                (
                    title,
                    classification,
                    filename,
                    filepath
                )
                VALUES (?, ?, ?, ?)
            `).run(
                title,
                classification,
                req.file.filename,
                req.file.path
            );

        audit(
            req.session.user.username,
            "REPORT_REGISTERED",
            req,
            `Report #${result.lastInsertRowid}`
        );

        res.json({
            success: true,
            id:
                result.lastInsertRowid
        });
    }
);

/*
|--------------------------------------------------------------------------
| VIEW PDF
|--------------------------------------------------------------------------
*/

app.get(
    "/api/reports/:id",
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

        if (
            !fs.existsSync(
                report.filepath
            )
        ) {

            return res.status(404).send(
                "PDF file not found."
            );
        }

        res.setHeader(
            "Content-Type",
            "application/pdf"
        );

        res.setHeader(
            "Content-Disposition",
            "inline"
        );

        res.sendFile(
            path.resolve(
                report.filepath
            )
        );
    }
);

/*
|--------------------------------------------------------------------------
| COMMAND AUDIT
|--------------------------------------------------------------------------
*/

app.get(
    "/api/command/audit",
    requireCommand,
    (req, res) => {

        const rows =
            db.prepare(`
                SELECT
                    actor_label,
                    action,
                    ip,
                    details,
                    created_at
                FROM audit
                ORDER BY id DESC
                LIMIT 500
            `).all();

        res.json(rows);
    }
);

/*
|--------------------------------------------------------------------------
| VISITS / IP
|--------------------------------------------------------------------------
|
| Only COMMAND OF CIA can view IP records.
|
*/

app.get(
    "/api/command/visits",
    requireCommand,
    (req, res) => {

        const visits =
            db.prepare(`
                SELECT
                    id,
                    ip,
                    user_agent,
                    language,
                    timezone,
                    path,
                    created_at
                FROM visits
                ORDER BY id DESC
                LIMIT 1000
            `).all();

        res.json(visits);
    }
);

/*
|--------------------------------------------------------------------------
| PUBLIC WEBSITE
|--------------------------------------------------------------------------
*/

app.use(
    express.static(
        PUBLIC_DIR
    )
);

/*
|--------------------------------------------------------------------------
| HEALTH CHECK
|--------------------------------------------------------------------------
*/

app.get(
    "/health",
    (req, res) => {

        res.json({
            status: "ok",
            database: dbPath
        });
    }
);

/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use(
    (req, res) => {

        res.status(404).send(
            "404 - Page Not Found"
        );
    }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use(
    (error, req, res, next) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if (
            error.message ===
            "PDF_ONLY"
        ) {

            return res.status(400).json({
                error: "PDF_ONLY"
            });
        }

        res.status(500).json({
            error: "INTERNAL_SERVER_ERROR"
        });
    }
);

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "======================================"
        );

        console.log(
            "CIA RP SERVER ONLINE"
        );

        console.log(
            `PORT: ${PORT}`
        );

        console.log(
            `DATABASE: ${dbPath}`
        );

        console.log(
            `REPORTS: ${UPLOAD_DIR}`
        );

        console.log(
            "======================================"
        );
    }
);
