```js
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
    console.error(
        "Missing required environment variables."
    );

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

            secure:
                process.env.NODE_ENV === "production",

            sameSite: "lax",

            maxAge:
                1000 *
                60 *
                60 *
                24
        }
    })
);

// =====================================================
// LOGS
// =====================================================

const logsDir =
    path.join(__dirname, "logs");

const visitsFile =
    path.join(
        logsDir,
        "visit-logs.json"
    );

const loginFile =
    path.join(
        logsDir,
        "discord-links.json"
    );

if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(
        logsDir,
        {
            recursive: true
        }
    );
}

if (!fs.existsSync(visitsFile)) {
    fs.writeFileSync(
        visitsFile,
        "[]",
        "utf8"
    );
}

if (!fs.existsSync(loginFile)) {
    fs.writeFileSync(
        loginFile,
        "[]",
        "utf8"
    );
}

// =====================================================
// GET IP
// =====================================================

function getIP(req) {

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
// SAVE VISIT
// =====================================================

function saveVisit(req) {

    let logs = [];

    try {

        logs = JSON.parse(
            fs.readFileSync(
                visitsFile,
                "utf8"
            )
        );

        if (!Array.isArray(logs)) {
            logs = [];
        }

    } catch {

        logs = [];

    }

    logs.push({

        type:
            "site_visit",

        ip:
            getIP(req),

        time:
            new Date().toISOString(),

        userAgent:
            req.headers["user-agent"] ||
            "unknown",

        language:
            req.headers["accept-language"] ||
            "unknown",

        path:
            req.originalUrl || "/"

    });

    if (logs.length > 10000) {

        logs =
            logs.slice(-10000);

    }

    fs.writeFileSync(
        visitsFile,
        JSON.stringify(
            logs,
            null,
            2
        ),
        "utf8"
    );

    console.log(
        `[VISIT] ${getIP(req)}`
    );
}

// =====================================================
// SAVE DISCORD LINK
// =====================================================

function saveDiscordLink(
    user,
    req
) {

    let logs = [];

    try {

        logs = JSON.parse(
            fs.readFileSync(
                loginFile,
                "utf8"
            )
        );

        if (!Array.isArray(logs)) {
            logs = [];
        }

    } catch {

        logs = [];

    }

    logs.push({

        type:
            "discord_link",

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
            getIP(req),

        time:
            new Date().toISOString(),

        userAgent:
            req.headers["user-agent"] ||
            "unknown"

    });

    if (logs.length > 10000) {

        logs =
            logs.slice(-10000);

    }

    fs.writeFileSync(
        loginFile,
        JSON.stringify(
            logs,
            null,
            2
        ),
        "utf8"
    );

    console.log(
        `[DISCORD LINK] ${user.username} | ${user.id}`
    );
}

// =====================================================
// LINK PAGE
// =====================================================

app.get(
    "/",
    (req, res) => {

        // Already linked
        if (req.session.user) {

            return res.sendFile(
                path.join(
                    __dirname,
                    "public",
                    "index.html"
                )
            );
        }

        // Record first visit
        saveVisit(req);

        // Show Discord link page
        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "link-discord.html"
            )
        );
    }
);

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

        const code =
            req.query.code;

        if (!code) {

            return res
                .status(400)
                .send(
                    "Discord authorization was cancelled."
                );
        }

        try {

            // -----------------------------------------
            // Exchange code
            // -----------------------------------------

            const tokenResponse =
                await fetch(
                    "https://discord.com/api/oauth2/token",
                    {

                        method:
                            "POST",

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

                console.error(
                    await tokenResponse.text()
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
            // Get Discord user
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

                return res
                    .status(500)
                    .send(
                        "Could not retrieve Discord account."
                    );
            }

            const discordUser =
                await userResponse.json();

            // -----------------------------------------
            // User data
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

            req.session.user =
                user;

            // -----------------------------------------
            // Save link
            // -----------------------------------------

            saveDiscordLink(
                user,
                req
            );

            // -----------------------------------------
            // Redirect
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
                    "Discord connection failed."
                );
        }
    }
);

// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/me",
    (req, res) => {

        if (!req.session.user) {

            return res.json({
                linked: false
            });
        }

        res.json({

            linked:
                true,

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
            () => {

                res.redirect(
                    "/"
                );

            }
        );
    }
);

// =====================================================
// PROTECT EVERYTHING
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
// PUBLIC WEBSITE
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
            `CIA RP running on port ${PORT}`
        );

    }
);
```

### 2. أنشئ هذا الملف

داخل:

```text
public/
```

أنشئ:

```text
link-discord.html
```

وحط فيه:

```html
<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>ربط حساب Discord</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;

            min-height: 100vh;

            display: flex;

            align-items: center;

            justify-content: center;

            background:
                radial-gradient(
                    circle at top,
                    #182238,
                    #070b12 60%
                );

            color: white;

            font-family:
                Arial,
                sans-serif;
        }

        .card {

            width: min(
                92%,
                480px
            );

            padding: 42px 32px;

            text-align: center;

            border:
                1px solid
                rgba(255,255,255,.1);

            border-radius: 18px;

            background:
                rgba(14,19,30,.92);

            box-shadow:
                0 25px 80px
                rgba(0,0,0,.45);

        }

        .logo {

            width: 72px;

            height: 72px;

            margin:
                0 auto 22px;

            border-radius: 50%;

            display: flex;

            align-items: center;

            justify-content: center;

            background:
                #5865F2;

            font-size: 32px;

            font-weight: bold;

        }

        h1 {

            margin:
                0 0 12px;

            font-size: 27px;

        }

        p {

            margin:
                0 auto 28px;

            max-width: 380px;

            line-height: 1.8;

            color:
                #aeb7c8;

        }

        .button {

            display: block;

            width: 100%;

            padding: 14px;

            border: 0;

            border-radius: 10px;

            background:
                #5865F2;

            color: white;

            text-decoration: none;

            font-size: 16px;

            font-weight: bold;

            cursor: pointer;

            transition:
                .2s;

        }

        .button:hover {

            background:
                #4752c4;

            transform:
                translateY(-1px);

        }

        .note {

            margin-top: 18px;

            font-size: 12px;

            color:
                #687386;

        }

    </style>

</head>

<body>

    <main class="card">

        <div class="logo">
            D
        </div>

        <h1>
            يجب ربط حسابك في Discord
        </h1>

        <p>
            للوصول إلى النظام، يجب ربط حساب
            Discord الخاص بك أولًا.
            اضغط على الزر أدناه لإتمام عملية الربط
            بشكل آمن.
        </p>

        <a
            class="button"
            href="/auth/discord"
        >
            ربط حساب Discord
        </a>

        <div class="note">
            لن تتمكن من متابعة الموقع قبل إتمام الربط.
        </div>

    </main>

</body>

</html>
```
