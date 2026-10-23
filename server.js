const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const crypto = require('crypto');
const path = require('path');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'data.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS teachers(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT);
CREATE TABLE IF NOT EXISTS rooms(id INTEGER PRIMARY KEY, teacher_id INTEGER, name TEXT, code TEXT UNIQUE, roll_limit INTEGER, start_at INTEGER, end_at INTEGER, radius INTEGER, tlat REAL, tlng REAL, tacc REAL, tloc_at INTEGER);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, room_id INTEGER, roll INTEGER, name TEXT, password_hash TEXT, UNIQUE(room_id, roll));
CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, room_id INTEGER, token TEXT UNIQUE, created_at INTEGER, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY, session_id INTEGER, room_id INTEGER, roll INTEGER, name TEXT, lat REAL, lng REAL, accuracy REAL, distance REAL, created_at INTEGER, UNIQUE(session_id, roll));
`);

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sign = (p, exp) => jwt.sign(p, SECRET, { expiresIn: exp });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const auth = role => (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    if (p.role !== role) throw 0;
    req.user = p; next();
  } catch { bad(res, 'Parat login kara', 401); }
};
const dist = (a, b, c, d) => {
  const R = 6371000, t = x => x * Math.PI / 180;
  const h = Math.sin(t(c - a) / 2) ** 2 + Math.cos(t(a)) * Math.cos(t(c)) * Math.sin(t(d - b) / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
};
const WIN = 60000; // rotating QR window
const nonce = (token, w) => crypto.createHmac('sha256', SECRET).update(token + ':' + w).digest('hex').slice(0, 10);
const qrToken = token => token + '.' + nonce(token, Math.floor(Date.now() / WIN));
const myRoom = (id, tid) => db.prepare('SELECT * FROM rooms WHERE id=? AND teacher_id=?').get(Number(id), tid);
const mySession = (id, tid) => db.prepare('SELECT s.* FROM sessions s JOIN rooms r ON r.id=s.room_id WHERE s.id=? AND r.teacher_id=?').get(Number(id), tid);

/* ---------- Teacher ---------- */
app.post('/api/teacher/register', (req, res) => {
  const { username, password, key } = req.body || {};
  if (ADMIN_KEY && key !== ADMIN_KEY) return bad(res, 'Admin key chukicha', 403);
  if (!username || !password || password.length < 6) return bad(res, 'Username ani 6+ akshari password dya');
  try {
    const r = db.prepare('INSERT INTO teachers(username,password_hash) VALUES(?,?)').run(username.trim().toLowerCase(), bcrypt.hashSync(password, 10));
    res.json({ token: sign({ role: 'teacher', id: r.lastInsertRowid }, '7d') });
  } catch { bad(res, 'Ha username already ahe'); }
});
app.post('/api/teacher/login', (req, res) => {
  const { username, password } = req.body || {};
  const t = db.prepare('SELECT * FROM teachers WHERE username=?').get(String(username || '').trim().toLowerCase());
  if (!t || !bcrypt.compareSync(String(password || ''), t.password_hash)) return bad(res, 'Username/password chukicha', 401);
  res.json({ token: sign({ role: 'teacher', id: t.id }, '7d') });
});

app.post('/api/rooms', auth('teacher'), (req, res) => {
  const b = req.body || {};
  const limit = parseInt(b.roll_limit), radius = parseInt(b.radius) || 100;
  if (!b.name || !(limit >= 1 && limit <= 500)) return bad(res, 'Name ani roll limit (1-500) dya');
  if (!(b.end_at > b.start_at)) return bad(res, 'Lecture chi vel barobar nahi');
  if (typeof b.lat !== 'number' || typeof b.lng !== 'number') return bad(res, 'Aadhi location ghya');
  let code;
  for (;;) { code = crypto.randomBytes(3).toString('hex').toUpperCase(); if (!db.prepare('SELECT 1 FROM rooms WHERE code=?').get(code)) break; }
  const r = db.prepare('INSERT INTO rooms(teacher_id,name,code,roll_limit,start_at,end_at,radius,tlat,tlng,tacc,tloc_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(req.user.id, b.name.trim(), code, limit, b.start_at, b.end_at, Math.min(Math.max(radius, 20), 2000), b.lat, b.lng, b.acc || 0, Date.now());
  res.json({ id: r.lastInsertRowid, code });
});
app.get('/api/rooms', auth('teacher'), (req, res) =>
  res.json(db.prepare('SELECT id,name,code,roll_limit,start_at,end_at,radius FROM rooms WHERE teacher_id=? ORDER BY id DESC').all(req.user.id)));

app.get('/api/rooms/:id', auth('teacher'), (req, res) => {
  const room = myRoom(req.params.id, req.user.id);
  if (!room) return bad(res, 'Room sapadla nahi', 404);
  const students = db.prepare('SELECT roll,name FROM students WHERE room_id=? ORDER BY roll').all(room.id);
  const sessions = db.prepare('SELECT s.id,s.created_at,s.expires_at,(SELECT COUNT(*) FROM attendance a WHERE a.session_id=s.id) AS present FROM sessions s WHERE s.room_id=? ORDER BY s.id DESC').all(room.id);
  res.json({ room, students, sessions });
});

app.post('/api/rooms/:id/location', auth('teacher'), (req, res) => {
  const room = myRoom(req.params.id, req.user.id);
  if (!room) return bad(res, 'Room nahi', 404);
  const { lat, lng, acc } = req.body || {};
  if (typeof lat !== 'number' || typeof lng !== 'number') return bad(res, 'Location chukichi');
  db.prepare('UPDATE rooms SET tlat=?,tlng=?,tacc=?,tloc_at=? WHERE id=?').run(lat, lng, acc || 0, Date.now(), room.id);
  res.json({ ok: true });
});

app.post('/api/rooms/:id/session', auth('teacher'), (req, res) => {
  const room = myRoom(req.params.id, req.user.id);
  if (!room) return bad(res, 'Room nahi', 404);
  const min = Math.min(Math.max(parseInt((req.body || {}).minutes) || 5, 1), 60);
  const now = Date.now();
  const r = db.prepare('INSERT INTO sessions(room_id,token,created_at,expires_at) VALUES(?,?,?,?)').run(room.id, crypto.randomBytes(8).toString('hex'), now, now + min * 60000);
  res.json({ id: r.lastInsertRowid, expires_at: now + min * 60000 });
});

app.get('/api/sessions/:id/qr', auth('teacher'), async (req, res) => {
  const s = mySession(req.params.id, req.user.id);
  if (!s) return bad(res, 'Session nahi', 404);
  const room = db.prepare('SELECT code FROM rooms WHERE id=?').get(s.room_id);
  const url = `${req.protocol}://${req.get('host')}/student.html?code=${room.code}&t=${qrToken(s.token)}`;
  res.json({ qr: await QRCode.toDataURL(url, { width: 400, margin: 1 }), url });
});

app.get('/api/sessions/:id/attendance', auth('teacher'), (req, res) => {
  const s = mySession(req.params.id, req.user.id);
  if (!s) return bad(res, 'Session nahi', 404);
  res.json({ expires_at: s.expires_at, rows: db.prepare('SELECT roll,name,distance,created_at FROM attendance WHERE session_id=? ORDER BY roll').all(s.id) });
});

app.get('/api/rooms/:id/export', auth('teacher'), (req, res) => {
  const room = myRoom(req.params.id, req.user.id);
  if (!room) return bad(res, 'Room nahi', 404);
  const sess = db.prepare('SELECT id,created_at FROM sessions WHERE room_id=? ORDER BY id').all(room.id);
  const st = Object.fromEntries(db.prepare('SELECT roll,name FROM students WHERE room_id=?').all(room.id).map(s => [s.roll, s.name]));
  const pres = new Set(db.prepare('SELECT session_id,roll FROM attendance WHERE room_id=?').all(room.id).map(a => a.session_id + '-' + a.roll));
  const fmt = t => new Date(t).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }).replace(',', '');
  let csv = 'Roll,Name,' + sess.map(s => fmt(s.created_at)).join(',') + ',Total\n';
  for (let r = 1; r <= room.roll_limit; r++) {
    const marks = sess.map(s => pres.has(s.id + '-' + r) ? 'P' : 'A');
    csv += [r, '"' + (st[r] || '').replace(/"/g, '""') + '"', ...marks, marks.filter(m => m === 'P').length].join(',') + '\n';
  }
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename=${room.code}.csv`);
  res.send(csv);
});

/* ---------- Student ---------- */
app.get('/api/room/:code', (req, res) => {
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(String(req.params.code).toUpperCase());
  if (!room) return bad(res, 'Room code chukicha', 404);
  res.json({ name: room.name, roll_limit: room.roll_limit, taken: db.prepare('SELECT roll FROM students WHERE room_id=?').all(room.id).map(r => r.roll) });
});

app.post('/api/student/login', (req, res) => {
  const { code, roll, name, password } = req.body || {};
  const room = db.prepare('SELECT * FROM rooms WHERE code=?').get(String(code || '').toUpperCase());
  if (!room) return bad(res, 'Room code chukicha', 404);
  if (!(roll >= 1 && roll <= room.roll_limit)) return bad(res, 'Roll number limit baher ahe');
  if (!password || password.length < 4) return bad(res, 'Password kamit kami 4 akshari dya');
  let st = db.prepare('SELECT * FROM students WHERE room_id=? AND roll=?').get(room.id, roll);
  if (!st) {
    if (!name || !name.trim()) return bad(res, 'Nav taka');
    db.prepare('INSERT INTO students(room_id,roll,name,password_hash) VALUES(?,?,?,?)').run(room.id, roll, name.trim(), bcrypt.hashSync(password, 10));
    st = db.prepare('SELECT * FROM students WHERE room_id=? AND roll=?').get(room.id, roll);
  } else if (!bcrypt.compareSync(password, st.password_hash)) {
    return bad(res, 'Password chukicha (kiva ha roll dusryane ghetlay)', 401);
  }
  res.json({ token: sign({ role: 'student', room_id: room.id, roll: st.roll, name: st.name }, '12h'), roll: st.roll, name: st.name, room: room.name });
});

app.post('/api/attend', auth('student'), (req, res) => {
  const { token, lat, lng, accuracy } = req.body || {};
  if (typeof lat !== 'number' || typeof lng !== 'number') return bad(res, 'Location milali nahi');
  const [tk, nc] = String(token || '').split('.');
  const s = db.prepare('SELECT * FROM sessions WHERE token=?').get(tk || '');
  if (!s) return bad(res, 'QR chukicha ahe');
  const w = Math.floor(Date.now() / WIN);
  if (nc !== nonce(tk, w) && nc !== nonce(tk, w - 1)) return bad(res, 'QR expire jhala, navin QR scan kara');
  const now = Date.now();
  if (now > s.expires_at) return bad(res, 'Attendance chi vel sampli');
  if (s.room_id !== req.user.room_id) return bad(res, 'Ha QR tumchya room cha nahi', 403);
  const room = db.prepare('SELECT * FROM rooms WHERE id=?').get(s.room_id);
  if (now < room.start_at || now > room.end_at) return bad(res, 'Lecture chya velet nahi');
  if (now - room.tloc_at > 3 * 60000) return bad(res, 'Teacher chi live location nahi, teacher ne dashboard open theva');
  const d = dist(lat, lng, room.tlat, room.tlng);
  if (d > room.radius) return bad(res, `Tumhi class madhe nahit (${Math.round(d)} m dur, limit ${room.radius} m)`);
  try {
    db.prepare('INSERT INTO attendance(session_id,room_id,roll,name,lat,lng,accuracy,distance,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(s.id, room.id, req.user.roll, req.user.name, lat, lng, accuracy || 0, Math.round(d), now);
    res.json({ ok: true, distance: Math.round(d) });
  } catch { bad(res, 'Attendance aadhich lagli ahe'); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log('Running on port ' + PORT));
