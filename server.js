const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const db = new sqlite3.Database('./bank.db');
const SECRET = 'ultra_secret_2026';

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

db.serialize(() => {
    // Додаємо таблицю користувачів з підтримкою доходу
    db.run(`CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, card_number TEXT, 
        balance REAL DEFAULT 0, income REAL DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS Messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Auth error' });
    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Session' });
        req.userId = decoded.id;
        next();
    });
};

// --- ВИХІД (Очищення кукі) ---
app.post('/api/logout', (req, res) => {
    res.clearCookie('token').json({ success: true });
});

// --- КАЗИНО (Шанс 40% на перемогу) ---
app.post('/api/casino', auth, (req, res) => {
    const { bet } = req.body;
    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (!user || user.balance < bet || bet <= 0) return res.status(400).json({ error: 'Недостатньо коштів' });
        
        const win = Math.random() < 0.4; // 40% шанс
        const multiplier = 2;
        const change = win ? bet * (multiplier - 1) : -bet;
        
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [change, req.userId], () => {
            res.json({ win, change, newBalance: user.balance + change });
        });
    });
});

// --- АПГРЕЙДИ (Купівля доходу) ---
app.post('/api/upgrade', auth, (req, res) => {
    const { cost, addIncome } = req.body;
    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (!user || user.balance < cost) return res.status(400).json({ error: 'Недостатньо грошей' });
        
        db.run(`UPDATE Users SET balance = balance - ?, income = income + ? WHERE id = ?`, 
        [cost, addIncome, req.userId], () => {
            res.json({ success: true });
        });
    });
});

// Інші маршрути (register, login, me, click, collect, chat) залишаються як були...
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const card = Array.from({length:16},()=>Math.floor(Math.random()*10)).join('');
    db.run(`INSERT INTO Users (username, password, card_number) VALUES (?, ?, ?)`, [username, hashed, card], (err) => {
        if (err) return res.status(400).json({error: 'Зайнято'});
        res.json({success: true});
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Users WHERE username = ?`, [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '24h' });
            res.cookie('token', token, { httpOnly: true, sameSite: 'strict' }).json({ success: true });
        } else res.status(401).json({error: 'Данні невірні'});
    });
});

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT username, card_number, balance, income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        res.json(user);
    });
});

app.post('/api/click', auth, (req, res) => {
    db.run(`UPDATE Users SET balance = balance + 1 WHERE id = ?`, [req.userId], () => {
        db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({balance: row.balance}));
    });
});

app.post('/api/collect', auth, (req, res) => {
    db.get(`SELECT income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        const inc = user ? user.income : 0;
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [inc, req.userId], () => {
            db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({newBalance: row.balance, added: inc}));
        });
    });
});

app.get('/api/chat', (req, res) => {
    db.all(`SELECT * FROM Messages ORDER BY timestamp DESC LIMIT 15`, (err, rows) => res.json(rows ? rows.reverse() : []));
});

app.post('/api/chat', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        db.run(`INSERT INTO Messages (username, text) VALUES (?, ?)`, [user.username, req.body.text], () => res.json({success:true}));
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started`));
