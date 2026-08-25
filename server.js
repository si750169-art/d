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

// Render proxy
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
// LOGS
// =====================================================

const logsDir = path.join(__dirname, "logs");

const visitsFile = path.join(
    logsDir,
    "visits.json"
);

const discordLinksFile = path.join(
    logsDir,
    "discord-links.json"
);

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, {
        recursive: true
    });
}

if (!fs.existsSync(visitsFile)) {
    fs.writeFileSync(
        visitsFile,
        "[]",
        "utf8"
    );
}

if (!fs.existsSync(discordLinksFile)) {
    fs.writeFileSync(
        discordLinksFile,
        "[]",
        "utf8"
    );
}

// =====================================================
// IP
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
// JSON LOG HELPERS
// =====================================================

function readLog(file) {
    try {
        const data =
            fs.readFileSync(
                file,
                "utf8"
            );

        const parsed =
            JSON.parse(data);

        return Array.isArray(parsed)
            ? parsed
            : [];
    } catch {
        return [];
    }
}

function writeLog(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(
            data,
            null,
            2
        ),
        "utf8"
    );
}

// =====================================================
// FIRST SITE VISIT
// =====================================================

function saveVisit(req) {
    const logs =
        readLog(visitsFile);

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
            "unknown"
    };

    logs.push(entry);

    writeLog(
        visitsFile,
        logs.slice(-10000)
    );

    console.log(
        `[SITE VISIT] ${entry.ip} | ${entry.timestamp}`
    );
}

// =====================================================
// DISCORD LINK LOG
// =====================================================

function saveDiscordLink(user, req) {
    const logs =
        readLog(discordLinksFile);

    const entry = {
        type: "discord_link",

        discordId:
            user.id,

        username:
            user.username,

        globalName:
            user.global_name || null,

        email:
            user.email || null,

        avatar:
            user.avatar || null,

        ip:
            getClientIP(req),

        timestamp:
            new Date().toISOString(),

        userAgent:
            req.headers["user-agent"] ||
            "unknown"
    };

    logs.push(entry);

    writeLog(
        discordLinksFile,
        logs.slice(-10000)
    );

    console.log(
        `[DISCORD LINK] ${user.username} | ${user.id} | ${entry.ip}`
    );
}

// =====================================================
// MAIN ENTRY
// =====================================================

app.get("/", (req, res) => {

    /*
     * إذا Discord غير مربوط:
     * اعرض صفحة الربط فقط.
     */

    if (!req.session.discordLinked) {

        // تسجيل أول زيارة
        if (!req.session.visitLogged) {

            saveVisit(req);

            req.session.visitLogged = true;
        }

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "link-discord.html"
            )
        );
    }

    /*
     * Discord مربوط.
     *
     * هنا يدخل الموقع الطبيعي.
     * لا يتم إنشاء حساب جديد.
     */

    return res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
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

                /*
                 * هذه الصلاحيات فقط:
                 * identify = معلومات الحساب الأساسية
                 * email    = البريد إذا وافق المستخدم
                 */

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
// DISCORD CALLBACK
// =====================================================

app.get(
    "/auth/discord/callback",
    async (req, res) => {

        const code =
            req.query.code;

        if (!code) {

            return res
                .status(400)
                .send(
                    "لم يتم إكمال ربط حساب Discord."
                );
        }

        try {

            // =================================================
            // TOKEN
            // =================================================

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
                        "فشل الاتصال بـ Discord."
                    );
            }

            const token =
                await tokenResponse.json();

            // =================================================
            // GET DISCORD USER
            // =================================================

            const userResponse =
                await fetch(
                    "https://discord.com/api/users/@me",
                    {
                        headers: {
                            Authorization:
                                `${token.token_type} ${token.access_token}`
                        }
                    }
                );

            if (!userResponse.ok) {

                return res
                    .status(500)
                    .send(
                        "تعذر التحقق من حساب Discord."
                    );
            }

            const discordUser =
                await userResponse.json();

            // =================================================
            // DISCORD LINK DATA
            // =================================================

            const linkedAccount = {

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

            // =================================================
            // LINK ONLY
            // =================================================

            /*
             * مهم:
             *
             * لا ننشئ مستخدمًا في قاعدة بيانات الموقع.
             * لا ننشئ username للموقع.
             * لا ننشئ password.
             *
             * فقط نحفظ Discord في Session
             * حتى يعرف الموقع أن الحساب تم التحقق منه.
             */

            req.session.discordLinked = true;

            req.session.discordUser =
                linkedAccount;

            // =================================================
            // LOG
            // =================================================

            saveDiscordLink(
                linkedAccount,
                req
            );

            // =================================================
            // RETURN TO WEBSITE
            // =================================================

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
                    "حدث خطأ أثناء ربط Discord."
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

        if (
            !req.session.discordLinked
        ) {

            return res.json({
                linked: false
            });
        }

        return res.json({

            linked: true,

            discord:
                req.session.discordUser
        });
    }
);

// =====================================================
// UNLINK
// =====================================================

app.get(
    "/unlink-discord",
    (req, res) => {

        req.session.discordLinked =
            false;

        req.session.discordUser =
            null;

        return res.redirect(
            "/"
        );
    }
);

// =====================================================
// PROTECT WEBSITE
// =====================================================

app.use(
    (req, res, next) => {

        /*
         * أي ملف أو Route داخل الموقع
         * ممنوع بدون Discord.
         */

        if (
            !req.session.discordLinked
        ) {

            return res.redirect(
                "/"
            );
        }

        next();
    }
);

// =====================================================
// WEBSITE FILES
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

        res
            .status(404)
            .send(
                "404 - Page Not Found"
            );
    }
);

// =====================================================
// ERROR
// =====================================================

app.use(
    (err, req, res, next) => {

        console.error(
            "Server error:",
            err
        );

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
