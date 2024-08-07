import pool from "./pool.js";
import cors from "cors";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcrypt";
import passport from "./passport.js";
import dotenv from "dotenv";
import fs from "fs";
import https from "https";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
dotenv.config();
const SALT_ROUNDS = 10;
const PORT = 3080;
const TOKEN_EXPIRY_TIME = "7d";

const app = express();
const pgSession = connectPgSimple(session);

app.use(
    cors({
        origin: process.env.CLIENT_URL,
        credentials: true,
    })
);
app.use(express.json());
app.use(
    session({
        store: new pgSession({
            pool: pool,
            tableName: "session",
        }),
        secret: process.env.SESSIONSECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
            // secure: true,
            httpOnly: true,
        },
    })
);
app.use(passport.initialize());
app.use(passport.session());

app.post("/auth", async (req, res) => {
    const { email, password } = req.body;
    const results = await pool.query("SELECT * FROM users WHERE email = $1", [
        email,
    ]);
    if (!isAccountExist(results)) {
        res.status(400).json({ message: "Account not exist" });
    } else {
        bcrypt.compare(
            password,
            results.rows[0].password,
            function (err, result) {
                if (result) {
                    const token = jwt.sign(
                        { user_id: results.rows[0].user_id },
                        process.env.JWT_SECRET,
                        {
                            expiresIn: TOKEN_EXPIRY_TIME,
                        }
                    );
                    const user_info = results.rows[0];
                    return res.json({
                        userId: user_info.user_id,
                        username: user_info.username,
                        email: user_info.email,
                        isTeacher: user_info.is_teacher,
                        avatar: user_info.avatar,
                        token,
                    });
                } else {
                    return res
                        .status(400)
                        .json({ message: "Password mismatch" });
                }
            }
        );
    }
});

app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    const results = await pool.query("SELECT * FROM users WHERE email = $1", [
        email,
    ]);
    if (isAccountExist(results)) {
        console.log("Account already exist");
        res.status(400).json({ message: "Account already exist" });
    } else {
        bcrypt.hash(password, SALT_ROUNDS, async (err, hash) => {
            const avatar = `https://ui-avatars.com/api/?name=${username.replaceAll(
                " ",
                "+"
            )}`;
            const uuid = uuidv4();
            await pool.query(
                "INSERT INTO users (user_id, username, email, password, avatar) VALUES($1, $2, $3, $4, $5)",
                [uuid, username, email, hash, avatar]
            );
        });
        res.status(200).json({ message: "Create account" });
    }
});

app.post("/courses", async (req, res) => {
    const data = req.body;
    try {
        await pool.query(
            "INSERT INTO courses (course_name, teacher_id, start_time, end_time, max_students) VALUES($1, $2, $3, $4, $5)",
            [
                data.courseName,
                data.teacherId,
                data.startTime,
                data.endTime,
                data.maxStudents,
            ]
        );
        return res.json({ message: "Course added" });
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ message: "Error adding course" });
    }
});

app.delete("/courses", async (req, res) => {
    const id = req.body.courseId;
    try {
        await pool.query("DELETE FROM courses WHERE id = $1", [id]);
        await pool.query("DELETE FROM enrollments WHERE course_id = $1", [id]);
        return res.json({ message: "Course deleted" });
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ message: "Error deleting course" });
    }
});

app.patch("/courses", async (req, res) => {
    const courseId = req.body.id;
    const startTime = req.body.startTime;
    const endTime = req.body.endTime;
    const maxStudents = req.body.maxStudents;
    const courseName = req.body.courseName;
    try {
        await pool.query(
            "UPDATE courses SET start_time = $1, end_time = $2, max_students = $3, course_name = $4 WHERE id = $5;",
            [startTime, endTime, maxStudents, courseName, courseId]
        );
        return res.json({ message: "Course Edited" });
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ message: "Error editing course" });
    }
});

app.get(
    "/auth/google",
    passport.authenticate("google", { prompt: "select_account" })
);

app.get("/auth/google/callback", (req, res, next) => {
    passport.authenticate("google", (err, user, info) => {
        if (err) {
            console.error("Authentication Error: ", err);
            return res.status(500).send("Authentication Failed");
        }
        req.login(user, (err) => {
            if (err) {
                return next(err);
            }
            const authCode = jwt.sign(
                { message: "Authentication Success", user_id: user.user_id },
                process.env.JWT_SECRET,
                {
                    expiresIn: TOKEN_EXPIRY_TIME,
                }
            );
            return res.redirect(
                `${process.env.CLIENT_URL}/authcode?authcode=${authCode}`
            );
        });
    })(req, res, next);
});

app.post("/authcodeexchange", async (req, res) => {
    const authHeader = req.headers["authorization"];
    const authCode = authHeader && authHeader.split(" ")[1];
    jwt.verify(authCode, process.env.JWT_SECRET, async (err, authCode) => {
        if (err) {
            console.log(err);
            return res.sendStatus(403);
        }
        const user_id = authCode.user_id;
        const newToken = jwt.sign({ user_id }, process.env.JWT_SECRET, {
            expiresIn: TOKEN_EXPIRY_TIME,
        });
        const results = await pool.query(
            "SELECT user_id, username, email, is_teacher, avatar FROM users WHERE user_id = $1",
            [user_id]
        );
        if (results.rows.length === 0) {
            return res.sendStatus(404);
        } else {
            return res.json({ ...results.rows[0], token: newToken });
        }
    });
});

app.get("/profile", async (req, res) => {
    const authHeader = req.headers["authorization"];
    const tokenInHeader = authHeader && authHeader.split(" ")[1];
    if (tokenInHeader == null) return res.sendStatus(401);
    jwt.verify(tokenInHeader, process.env.JWT_SECRET, async (err, token) => {
        if (err) {
            console.log(err);
            return res.sendStatus(403);
        }
        const user_id = token.user_id;
        const newToken = jwt.sign({ user_id }, process.env.JWT_SECRET, {
            expiresIn: TOKEN_EXPIRY_TIME,
        });
        const results = await pool.query(
            "SELECT user_id, username, email, is_teacher, avatar FROM users WHERE user_id = $1",
            [user_id]
        );
        if (results.rows.length === 0) {
            return res.sendStatus(404);
        } else {
            return res.json({ ...results.rows[0], token: newToken });
        }
        return res.json(token);
    });
});

app.get("/courses", async (req, res) => {
    try {
        let events;
        const results = await pool.query(
            "SELECT id, username, course_name, teacher_id, start_time, end_time, max_students  FROM courses INNER JOIN users ON courses.teacher_id = users.user_id"
        );
        if (results.rows.length === 0) {
            events = [];
        } else {
            events = results.rows;
        }
        return res.json(results.rows);
    } catch (err) {
        console.error(err.message);
    }
});

app.post("/enroll", async (req, res) => {
    const body = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO enrollments (course_id, student_id) VALUES($1, $2)",
            [body.courseId, body.studentId]
        );
        return res.json({ message: "Enrolled" });
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ message: "Error enrolling" });
    }
});

app.get("/enroll", async (req, res) => {
    const studentId = req.query.studentid;
    try {
        const result = await pool.query(
            "SELECT * FROM enrollments WHERE student_id = $1",
            [studentId]
        );
        return res.json(result.rows);
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({ message: "Error enrolling" });
    }
});

function isAccountExist(results) {
    if (results.rows.length === 1) {
        return true;
    }
    return false;
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// const pfxFilePath = "./certs/server.pfx";
// const passphrase = process.env.PASSPHRASE;
// const options = {
//     pfx: fs.readFileSync(pfxFilePath),
//     passphrase: passphrase,
// };
// https.createServer(options, app).listen(PORT, () => {
//     console.log(`HTTPS server running on ${PORT}`);
// });
