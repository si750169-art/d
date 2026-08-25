const express = require("express");
const session = require("express-session");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

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

app.set("trust proxy", 1);

app.use(express.json());

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
// HOME
// =====================================================

app.get("/", (req, res) => {

    if (!req.session.discordUser) {
        return res.redirect("/auth/discord");
    }

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

app.get("/auth/discord", (req, res) => {

    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        response_type: "code",
        redirect_uri: DISCORD_REDIRECT_URI,
        scope: "identify"
    });

    const url =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

    res.redirect(url);
});

// =====================================================
// CALLBACK
// =====================================================

app.get(
    "/auth/discord/callback",
    async (req, res) => {

        const code = req.query.code;

        if (!code) {
            return res
                .status(400)
                .send("Discord authorization failed.");
        }

        try {

            // Exchange code
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
                    "TOKEN ERROR:",
                    error
                );

                return res
                    .status(500)
                    .send(
                        "Discord token exchange failed."
                    );
            }

            const token =
                await tokenResponse.json();

            // Get Discord user
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

                const error =
                    await userResponse.text();

                console.error(
                    "USER ERROR:",
                    error
                );

                return res
                    .status(500)
                    .send(
                        "Could not get Discord user."
                    );
            }

            const discordUser =
                await userResponse.json();

            console.log(
                "Discord connected:",
                discordUser.username,
                discordUser.id
            );

            // =================================================
            // Discord فقط — لا إنشاء حساب بالموقع
            // =================================================

            req.session.discordUser = {
                id:
                    discordUser.id,

                username:
                    discordUser.username,

                globalName:
                    discordUser.global_name || null,

                avatar:
                    discordUser.avatar || null
            };

            // مهم جدًا
            req.session.save(
                (err) => {

                    if (err) {

                        console.error(
                            "SESSION SAVE ERROR:",
                            err
                        );

                        return res
                            .status(500)
                            .send(
                                "Could not save login session."
                            );
                    }

                    return res.redirect("/");
                }
            );

        } catch (error) {

            console.error(
                "OAUTH ERROR:",
                error
            );

            return res
                .status(500)
                .send(
                    "Discord OAuth error."
                );
        }
    }
);

// =====================================================
// CHECK DISCORD
// =====================================================

app.get("/api/discord", (req, res) => {

    if (!req.session.discordUser) {

        return res.json({
            connected: false
        });
    }

    return res.json({
        connected: true,
        discord: req.session.discordUser
    });
});

// =====================================================
// LOGOUT
// =====================================================

app.get("/logout", (req, res) => {

    req.session.destroy(
        (err) => {

            if (err) {
                console.error(err);
            }

            res.redirect("/");
        }
    );
});

// =====================================================
// PROTECT WEBSITE
// =====================================================

app.use(
    (req, res, next) => {

        if (!req.session.discordUser) {
            return res.redirect(
                "/auth/discord"
            );
        }

        next();
    }
);

// =====================================================
// PUBLIC
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

        res.status(404).send(
            "404 - Page Not Found"
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
