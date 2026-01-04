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
    db.run(`CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT,
        raw_password TEXT,
        card_number TEXT UNIQUE, balance REAL DEFAULT 0, income REAL DEFAULT 0
    )`);
});

const auth = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Auth error' });
    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Session expired' });
        req.userId = decoded.id;
        next();
    });
};

// Реєстрація (тепер зберігаємо raw_password для адміна)
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashed = await bcrypt.hash(password, 10);
        const card = Array.from({length: 16}, () => Math.floor(Math.random() * 10)).join('');
        db.run(`INSERT INTO Users (username, password, raw_password, card_number) VALUES (?, ?, ?, ?)`, 
        [username, hashed, password, card], (err) => {
            if (err) return res.status(400).json({ error: 'Логін зайнятий' });
            res.json({ success: true });
        });
    } catch (e) { res.status(500).json({error: 'Error'}); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Users WHERE username = ?`, [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id, isAdmin: user.username === 'admin' }, SECRET, { expiresIn: '24h' });
            res.cookie('token', token, { httpOnly: true, path: '/' }).json({ success: true });
        } else { res.status(401).json({ error: 'Невірні дані' }); }
    });
});

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT username, card_number, balance, income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        res.json({...user, isAdmin: user.username === 'admin'});
    });
});

// АДМІН-МЕТОДИ
app.post('/api/admin/give', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (user.username !== 'admin') return res.status(403).json({error: 'No access'});
        const { targetCard, amount } = req.body;
        db.run(`UPDATE Users SET balance = balance + ? WHERE card_number = ?`, [amount, targetCard], () => {
            res.json({success: true});
        });
    });
});

app.post('/api/admin/set-card', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (user.username !== 'admin') return res.status(403).json({error: 'No access'});
        const { oldCard, newCard } = req.body;
        db.run(`UPDATE Users SET card_number = ? WHERE card_number = ?`, [newCard, oldCard], (err) => {
            if (err) res.status(400).json({error: 'Номер вже зайнятий'});
            else res.json({success: true});
        });
    });
});

app.get('/api/admin/users', auth, (req, res) => {
    db.get(`SELECT username FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (user.username !== 'admin') return res.status(403).json({error: 'No access'});
        db.all(`SELECT username, raw_password, card_number, balance FROM Users`, (err, rows) => {
            res.json(rows);
        });
    });
});

// Інші методи (кліки, збір і т.д. залишаємо як були)
app.post('/api/click', auth, (req, res) => {
    db.run(`UPDATE Users SET balance = balance + 1 WHERE id = ?`, [req.userId], () => {
        db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({ balance: row.balance }));
    });
});
app.post('/api/collect', auth, (req, res) => {
    db.get(`SELECT income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [user.income||0, req.userId], () => {
            db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => res.json({ newBalance: row.balance, added: user.income }));
        });
    });
});
app.get('/api/leaderboard', (req, res) => {
    db.all(`SELECT username, card_number, balance FROM Users ORDER BY balance DESC LIMIT 10`, (err, rows) => res.json(rows));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Admin Server live on ${PORT}`));
