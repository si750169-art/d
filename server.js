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
    console.error("Missing Discord OAuth environment variables.");
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
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

    // إذا Discord مربوط بالفعل
    if (req.session.discordUser) {

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }

    // إذا غير مربوط → Discord مباشرة
    return res.redirect(
        "/auth/discord"
    );
});

// =====================================================
// DISCORD LOGIN
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
                "identify"
        });

        return res.redirect(
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
            return res
                .status(400)
                .send(
                    "Discord authorization cancelled."
                );
        }

        try {

            // الحصول على Access Token
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

                console.error(
                    await tokenResponse.text()
                );

                return res
                    .status(500)
                    .send(
                        "Discord authentication failed."
                    );
            }

            const token =
                await tokenResponse.json();

            // الحصول على بيانات Discord
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
                        "Could not retrieve Discord account."
                    );
            }

            const discordUser =
                await userResponse.json();

            // =================================================
            // IMPORTANT:
            // لا يوجد إنشاء حساب في الموقع.
            // فقط تخزين هوية Discord في Session.
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

            return res.redirect("/");

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
// GET CONNECTED DISCORD
// =====================================================

app.get(
    "/api/discord",
    (req, res) => {

        if (!req.session.discordUser) {

            return res.json({
                connected: false
            });
        }

        return res.json({
            connected: true,

            discord:
                req.session.discordUser
        });
    }
);

// =====================================================
// LOGOUT / DISCONNECT
// =====================================================

app.get(
    "/logout",
    (req, res) => {

        req.session.destroy(
            () => {
                res.redirect("/");
            }
        );
    }
);

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
// WEBSITE
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
