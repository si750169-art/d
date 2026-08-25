const express = require("express");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// ===============================
// Discord configuration
// ===============================

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;

const REDIRECT_URI =
    process.env.DISCORD_REDIRECT_URI ||
    "https://d-1-c9e5.onrender.com/auth/discord/callback";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "change-this-secret";

if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error(
        "ERROR: DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET is missing."
    );

    process.exit(1);
}

app.set("trust proxy", 1);

app.use(express.json());

// ===============================
// Session
// ===============================

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

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {

    // Already connected
    if (req.session.discord) {

        return res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );
    }

    // Not connected
    // Send directly to Discord
    return res.redirect(
        "/auth/discord"
    );
});

// ===============================
// Discord OAuth
// ===============================

app.get("/auth/discord", (req, res) => {

    const params = new URLSearchParams();

    params.set(
        "client_id",
        CLIENT_ID
    );

    params.set(
        "redirect_uri",
        REDIRECT_URI
    );

    params.set(
        "response_type",
        "code"
    );

    params.set(
        "scope",
        "identify"
    );

    const url =
        "https://discord.com/oauth2/authorize?" +
        params.toString();

    console.log(
        "Redirecting to Discord..."
    );

    res.redirect(url);
});

// ===============================
// Discord callback
// ===============================

app.get(
    "/auth/discord/callback",
    async (req, res) => {

        const code = req.query.code;

        if (!code) {

            return res
                .status(400)
                .send(
                    "No Discord authorization code."
                );
        }

        try {

            // ===============================
            // Exchange code
            // ===============================

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

                                code:
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
                    "DISCORD TOKEN ERROR:"
                );

                console.error(
                    tokenText
                );

                return res
                    .status(500)
                    .send(
                        "Discord token exchange failed."
                    );
            }

            const token =
                JSON.parse(tokenText);

            // ===============================
            // Get Discord user
            // ===============================

            const userResponse =
                await fetch(
                    "https://discord.com/api/users/@me",
                    {
                        headers: {
                            Authorization:
                                `Bearer ${token.access_token}`
                        }
                    }
                );

            const userText =
                await userResponse.text();

            if (!userResponse.ok) {

                console.error(
                    "DISCORD USER ERROR:"
                );

                console.error(
                    userText
                );

                return res
                    .status(500)
                    .send(
                        "Could not retrieve Discord account."
                    );
            }

            const discordUser =
                JSON.parse(userText);

            console.log(
                "Discord login successful:",
                discordUser.username,
                discordUser.id
            );

            // ===============================
            // ONLY STORE DISCORD SESSION
            // ===============================

            req.session.discord = {
                id:
                    discordUser.id,

                username:
                    discordUser.username,

                globalName:
                    discordUser.global_name || null,

                avatar:
                    discordUser.avatar || null
            };

            // ===============================
            // IMPORTANT
            // ===============================
            //
            // NO DATABASE
            // NO WEBSITE ACCOUNT
            // NO PASSWORD
            // NO USER CREATION
            //
            // Just Discord session.
            //

            req.session.save(
                (error) => {

                    if (error) {

                        console.error(
                            "SESSION SAVE ERROR:",
                            error
                        );

                        return res
                            .status(500)
                            .send(
                                "Could not save Discord session."
                            );
                    }

                    console.log(
                        "Session saved successfully."
                    );

                    return res.redirect(
                        "/"
                    );
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
                    "Discord OAuth failed."
                );
        }
    }
);

// ===============================
// Check Discord session
// ===============================

app.get(
    "/api/discord",
    (req, res) => {

        if (!req.session.discord) {

            return res.json({
                connected: false
            });
        }

        return res.json({
            connected: true,
            discord:
                req.session.discord
        });
    }
);

// ===============================
// Logout
// ===============================

app.get(
    "/logout",
    (req, res) => {

        req.session.destroy(
            (error) => {

                if (error) {
                    console.error(error);
                }

                res.redirect("/");
            }
        );
    }
);

// ===============================
// Protect website
// ===============================

app.use(
    (req, res, next) => {

        if (!req.session.discord) {

            return res.redirect(
                "/auth/discord"
            );
        }

        next();
    }
);

// ===============================
// Public website
// ===============================

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

// ===============================
// 404
// ===============================

app.use(
    (req, res) => {

        res.status(404).send(
            "404 - Page Not Found"
        );
    }
);

// ===============================
// Start
// ===============================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `CIA RP running on port ${PORT}`
        );

        console.log(
            `Redirect URI: ${REDIRECT_URI}`
        );
    }
);
