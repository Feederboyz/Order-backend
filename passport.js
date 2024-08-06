import GoogleStrategy from "passport-google-oauth2";
import passport from "passport";
import pool from "./pool.js";
import { v4 as uuidv4 } from "uuid";

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env["GOOGLE_CLIENT_ID"],
            clientSecret: process.env["GOOGLE_CLIENT_SECRET"],
            callbackURL: process.env["GOOGLE_CB_URL"],
            scope: ["profile", "email"],
            state: true,
        },
        function verify(accessToken, refreshToken, profile, cb) {
            pool.query(
                "SELECT * FROM users WHERE auth_id = $1",
                [profile.id],
                (err, res) => {
                    if (err) {
                        cb(err);
                    } else if (res.rows.length == 1) {
                        cb(null, { user_id: res.rows[0].user_id });
                    } else {
                        const uuid = uuidv4();
                        pool.query(
                            "INSERT INTO users (user_id, username, email, auth_type, auth_id, avatar) VALUES ($1, $2, $3, $4, $5, $6)",
                            [
                                uuid,
                                profile.displayName,
                                profile.email,
                                "google",
                                profile.id,
                                profile.picture,
                            ],
                            (err, res) => {
                                if (err) {
                                    cb(err);
                                }
                                cb(null, {
                                    user_id: uuid,
                                });
                            }
                        );
                    }
                }
            );
        }
    )
);

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser(async (user, cb) => {
    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE user_id = $1",
            [user.user_id]
        );
        if (result.rows.length == 1) {
            cb(null, result.rows[0]);
        } else {
            cb(null, false);
        }
    } catch (err) {
        cb(err);
    }
});

export default passport;
