const express = require("express");
const session = require("express-session");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !SESSION_SECRET) {
    console.error("Missing Discord environment variables.");
    process.exit(1);
}

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
            secure: true,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

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

        // -------------------------------------------------
        // Exchange OAuth code
        // -------------------------------------------------

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
                    code: code,
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

        // -------------------------------------------------
        // Get Discord account
        // -------------------------------------------------

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

        // -------------------------------------------------
        // Discord verification only
        // -------------------------------------------------

        req.session.discord = {
            id: discordUser.id,
            username: discordUser.username,
            globalName: discordUser.global_name || null,
            avatar: discordUser.avatar || null
        };

        // لا ننشئ حساب CIA هنا
        // لا ننشئ username
        // لا ننشئ password
        // لا نضيف مستخدم إلى قاعدة البيانات

        req.session.save((error) => {

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
// HOME
// =====================================================

app.get("/", (req, res) => {

    // Discord غير مربوط
    if (!req.session.discord) {

        return res.redirect(
            "/auth/discord"
        );
    }

    // Discord مربوط
    return res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

// =====================================================
// PROTECT ALL WEBSITE FILES
// =====================================================

app.use((req, res, next) => {

    // السماح لـ Discord OAuth routes
    if (
        req.path === "/auth/discord" ||
        req.path === "/auth/discord/callback"
    ) {
        return next();
    }

    // أي شيء آخر يحتاج Discord
    if (!req.session.discord) {

        return res.redirect(
            "/auth/discord"
        );
    }

    next();
});

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
// LOGOUT DISCORD SESSION
// =====================================================

app.get("/discord/logout", (req, res) => {

    req.session.discord = null;

    req.session.save(() => {
        res.redirect("/");
    });
});

// =====================================================
// 404
// =====================================================

app.use((req, res) => {

    res.status(404).send(
        "404 - Page Not Found"
    );
});

// =====================================================
// START SERVER
// =====================================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `CIA RP running on port ${PORT}`
        );

        console.log(
            `Discord Redirect: ${REDIRECT_URI}`
        );
    }
);
