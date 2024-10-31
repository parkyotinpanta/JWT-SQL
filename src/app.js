const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

const SECRET_KEY = 'your_secret_key';
const REFRESH_SECRET_KEY = 'your_refresh_secret_key';
const TOKEN_EXPIRY = '1h';
const REFRESH_TOKEN_EXPIRY = '1d';
const INACTIVITY_LIMIT = 60000; // 1 นาที (60,000 ms)

// เชื่อมต่อฐานข้อมูล MySQL
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

let userActivity = {}; // เก็บเวลาการใช้งานล่าสุดของผู้ใช้

// API สำหรับลงทะเบียนผู้ใช้
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const [existingUser] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser.length > 0) {
        return res.status(400).json({ message: 'ชื่อผู้ใช้นี้มีอยู่แล้ว' });
    }

    const hashedPassword = await bcrypt.hash(password, 10); 
    await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    
    res.status(201).json({ message: 'ลงทะเบียนสำเร็จ!' });
});

// API สำหรับล็อกอิน
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = users[0];

    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET_KEY, { expiresIn: REFRESH_TOKEN_EXPIRY });

    await db.query('INSERT INTO refresh_tokens (user_id, token) VALUES (?, ?)', [user.id, refreshToken]);

    return res.json({ accessToken, refreshToken });
});

// Middleware สำหรับตรวจสอบ JWT และการหมดอายุของเซสชันการใช้งาน
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];

        jwt.verify(token, SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'กรุณาล็อกอินใหม่' });
            }

            const lastActivity = userActivity[user.id];

            if (Date.now() - lastActivity > INACTIVITY_LIMIT) {
                delete userActivity[user.id]; // ลบข้อมูลการใช้งาน
                return res.status(403).json({ message: 'เซสชันหมดอายุ กรุณาล็อกอินใหม่' });
            }

            userActivity[user.id] = Date.now(); // อัปเดตเวลาการใช้งาน
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ message: 'กรุณาล็อกอิน' });
    }
};

// API สำหรับดึงรายชื่อ (protected route)
app.get('/users', authenticateJWT, (req, res) => {
    const users = [
        { id: 1, name: 'หิวไก่ต้ม' },
        { id: 2, name: 'ชาไข่มุก' }
    ];

    res.json({ users });
});

// API สำหรับ Refresh Token
app.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ message: 'กรุณาให้ Refresh Token' });
    }

    const [tokens] = await db.query('SELECT * FROM refresh_tokens WHERE token = ?', [refreshToken]);

    if (tokens.length === 0) {
        return res.status(403).json({ message: 'Refresh Token ไม่ถูกต้อง' });
    }

    jwt.verify(refreshToken, REFRESH_SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Refresh Token หมดอายุ กรุณาล็อกอินใหม่' });
        }

        const newToken = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: TOKEN_EXPIRY });
        userActivity[user.id] = Date.now(); // อัปเดตเวลาการใช้งานหลังจากได้ JWT ใหม่
        res.json({ token: newToken });
    });
});

// เริ่มเซิร์ฟเวอร์
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
