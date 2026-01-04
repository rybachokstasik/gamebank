const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const db = new sqlite3.Database('./bank.db');
const SECRET = 'ultra_secret_key_2026';

// Анти-чіт: час останнього кліку
const clickLimits = new Map();

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// --- БАЗА ДАНИХ ---
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, raw_password TEXT,
        card_number TEXT UNIQUE, balance REAL DEFAULT 0, income REAL DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS Messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, text TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Auth required' });
    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Expired' });
        req.userId = decoded.id;
        next();
    });
};

// --- ОСНОВНІ API ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({error: 'Пусто'});
    const hashed = await bcrypt.hash(password, 10);
    const card = Math.floor(10000000 + Math.random() * 90000000).toString(); 
    
    db.run(`INSERT INTO Users (username, password, raw_password, card_number) VALUES (?, ?, ?, ?)`, 
    [username, hashed, password, card], (err) => {
        if (err) return res.status(400).json({ error: 'Нік зайнятий' });
        res.json({ success: true });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Users WHERE username = ?`, [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '24h' });
            res.cookie('token', token, { httpOnly: true, path: '/' }).json({ success: true });
        } else { res.status(401).json({ error: 'Невірно' }); }
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token', { path: '/' }).json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT username, card_number, balance, income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (!user) return res.status(404).json({error: 'User not found'});
        res.json({ ...user, isAdmin: user.username === 'admin' });
    });
});

// --- ІГРОВІ ФУНКЦІЇ ---
app.post('/api/click', auth, (req, res) => {
    const now = Date.now();
    const last = clickLimits.get(req.userId) || 0;
    if (now - last < 100) return res.status(429).json({ error: 'Fast' }); // Анти-клікер
    clickLimits.set(req.userId, now);

    db.run(`UPDATE Users SET balance = balance + 1 WHERE id = ?`, [req.userId], () => {
        db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({ balance: row.balance }));
    });
});

app.post('/api/collect', auth, (req, res) => {
    db.get(`SELECT income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        const inc = user.income || 0;
        if (inc <= 0) return res.json({ added: 0, newBalance: user.balance });
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [inc, req.userId], () => {
            db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({ newBalance: row.balance }));
        });
    });
});

// --- КАЗИНО (ПОВЕРНУТО) ---
app.post('/api/casino', auth, (req, res) => {
    const { bet } = req.body;
    if (bet <= 0) return res.status(400).json({ error: 'Ставка має бути > 0' });

    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (user.balance < bet) return res.status(400).json({ error: 'Не вистачає грошей' });

        const win = Math.random() < 0.4; // 40% шанс
        const change = win ? bet : -bet; // Якщо виграв: +ставка, програв: -ставка
        
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [change, req.userId], () => {
            res.json({ win, change, newBalance: user.balance + change });
        });
    });
});

// --- ПЕРЕКАЗИ ---
app.post('/api/transfer', auth, (req, res) => {
    const { targetCard, amount } = req.body;
    const val = parseFloat(amount);
    if (val <= 0) return res.status(400).json({ error: 'Сума <= 0' });

    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, sender) => {
        if (sender.balance < val) return res.status(400).json({ error: 'Мало грошей' });
        
        db.get(`SELECT id FROM Users WHERE card_number = ?`, [targetCard], (err, receiver) => {
            if (!receiver) return res.status(404).json({ error: 'Картку не знайдено' });
            if (receiver.id === req.userId) return res.status(400).json({ error: 'Не можна собі' });

            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                db.run(`UPDATE Users SET balance = balance - ? WHERE id = ?`, [val, req.userId]);
                db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [val, receiver.id]);
                db.run('COMMIT', () => res.json({ success: true }));
            });
        });
    });
});

// --- АПГРЕЙДИ ---
app.post('/api/upgrade', auth, (req, res) => {
    const { type } = req.body;
    let cost = 0, incomeAdd = 0;
    if (type === 1) { cost = 250; incomeAdd = 2; }
    if (type === 2) { cost = 1000; incomeAdd = 10; }
    if (type === 3) { cost = 5000; incomeAdd = 60; }
    
    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (user.balance < cost) return res.status(400).json({ error: 'Мало грошей' });
        db.run(`UPDATE Users SET balance = balance - ?, income = income + ? WHERE id = ?`, [cost, incomeAdd, req.userId], () => res.json({ success: true }));
    });
});

// --- АДМІНКА (ВИПРАВЛЕНО) ---
app.get('/api/admin/users', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, admin) => {
        if (admin.username !== 'admin') return res.status(403).json({ error: 'Access denied' });
        db.all(`SELECT id, username, raw_password, card_number, balance FROM Users`, (err, rows) => res.json(rows));
    });
});

app.post('/api/admin/give', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, admin) => {
        if (admin.username !== 'admin') return res.status(403).end();
        db.run(`UPDATE Users SET balance = balance + ? WHERE card_number = ?`, [req.body.amount, req.body.targetCard], () => res.json({ success: true }));
    });
});

app.post('/api/admin/set-card', auth, (req, res) => {
    const { targetUser, newCard } = req.body; // targetUser = НІКНЕЙМ
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, admin) => {
        if (admin.username !== 'admin') return res.status(403).end();
        
        // Змінюємо карту, шукаючи по USERNAME
        db.run(`UPDATE Users SET card_number = ? WHERE username = ?`, [newCard, targetUser], function(err) {
            if (err) return res.status(400).json({ error: 'Ця карта вже зайнята!' });
            if (this.changes === 0) return res.status(404).json({ error: 'Користувача з таким ніком не знайдено' });
            res.json({ success: true });
        });
    });
});

// --- ЧАТ ---
app.get('/api/chat', (req, res) => db.all(`SELECT * FROM Messages ORDER BY id DESC LIMIT 20`, (err, rows) => res.json(rows ? rows.reverse() : [])));
app.post('/api/chat', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, u) => {
        if(u) db.run(`INSERT INTO Messages (username, text) VALUES (?, ?)`, [u.username, req.body.text], () => res.json({success:true}));
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on ${PORT}`));
