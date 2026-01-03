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
        card_number TEXT UNIQUE, balance REAL DEFAULT 0, income REAL DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS Transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER, receiver_id INTEGER,
        amount REAL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
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

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if(!username || !password) return res.status(400).json({error: 'Заповніть поля'});
        const hashed = await bcrypt.hash(password, 10);
        const card = Array.from({length: 16}, () => Math.floor(Math.random() * 10)).join('');
        db.run(`INSERT INTO Users (username, password, card_number) VALUES (?, ?, ?)`, [username, hashed, card], (err) => {
            if (err) return res.status(400).json({ error: 'Логін зайнятий' });
            res.json({ success: true });
        });
    } catch (e) { res.status(500).json({error: 'Error'}); }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM Users WHERE username = ?`, [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id }, SECRET, { expiresIn: '24h' });
            res.cookie('token', token, { httpOnly: true, path: '/' }).json({ success: true });
        } else { res.status(401).json({ error: 'Невірні дані' }); }
    });
});

app.get('/api/me', auth, (req, res) => {
    db.get(`SELECT username, card_number, balance, income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        res.json(user);
    });
});

app.post('/api/click', auth, (req, res) => {
    db.run(`UPDATE Users SET balance = balance + 1 WHERE id = ?`, [req.userId], () => {
        db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => {
            res.json({ balance: row.balance });
        });
    });
});

app.post('/api/collect', auth, (req, res) => {
    db.get(`SELECT income FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        const inc = user.income || 0;
        db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [inc, req.userId], () => {
            db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, row) => {
                res.json({ added: inc, newBalance: row.balance });
            });
        });
    });
});

app.post('/api/buy-upgrade', auth, (req, res) => {
    const cost = 100;
    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, user) => {
        if (!user || user.balance < cost) return res.status(400).json({ error: 'Немає $100' });
        db.run(`UPDATE Users SET balance = balance - ?, income = income + 2 WHERE id = ?`, [cost, req.userId], () => {
            res.json({ success: true });
        });
    });
});

app.post('/api/transfer', auth, (req, res) => {
    const { targetCard, amount } = req.body;
    const val = parseFloat(amount);
    if(val <= 0) return res.status(400).json({error: 'Невірна сума'});
    db.get(`SELECT balance FROM Users WHERE id = ?`, [req.userId], (err, sender) => {
        if (!sender || sender.balance < val) return res.status(400).json({ error: 'Мало грошей' });
        db.get(`SELECT id FROM Users WHERE card_number = ?`, [targetCard], (err, receiver) => {
            if (!receiver) return res.status(404).json({ error: 'Карту не знайдено' });
            if (receiver.id === req.userId) return res.status(400).json({ error: 'Собі не можна' });
            db.serialize(() => {
                db.run('BEGIN TRANSACTION');
                db.run(`UPDATE Users SET balance = balance - ? WHERE id = ?`, [val, req.userId]);
                db.run(`UPDATE Users SET balance = balance + ? WHERE id = ?`, [val, receiver.id]);
                db.run(`INSERT INTO Transactions (sender_id, receiver_id, amount) VALUES (?, ?, ?)`, [req.userId, receiver.id, val]);
                db.run('COMMIT', () => res.json({ success: true }));
            });
        });
    });
});

app.get('/api/leaderboard', (req, res) => {
    db.all(`SELECT username, card_number, balance FROM Users ORDER BY balance DESC LIMIT 5`, [], (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/api/transactions', auth, (req, res) => {
    db.all(`SELECT t.*, u.username as receiver FROM Transactions t JOIN Users u ON t.receiver_id = u.id WHERE t.sender_id = ? ORDER BY timestamp DESC LIMIT 5`, [req.userId], (err, rows) => {
        res.json(rows || []);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server live on ${PORT}`));
