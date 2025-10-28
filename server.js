// TEXAS HOLD'EM — FULL SERVER (Express + WS + better-sqlite3)
// =============================================================
// - 2 stola (small 0.2/0.5, big 1/2)
// - Buy-in 50–200 BB
// - No Limit Hold'em
// - Time 30s + Timebank 90s (reset 1h)
// - Rake 1%
// - Showdown evaluator + muck slabijih
// - Re-entry 6h pravilo
// - Top-up poslije fold-a ili između ruku
// =============================================================

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const WebSocket = require("ws");

// ----------------- CONFIG -----------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const TOKEN_NAME = "token";

const ADMIN_KEY = process.env.ADMIN_KEY || "x admin key";  // <-- kako si tražio
const RAKE_PERCENT = 1; // 1%
const MIN_BUYIN_BB = 50;
const MAX_BUYIN_BB = 200;

// ----------------- PATHS -----------------
const PUBLIC_DIR = path.join(__dirname, "public");
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

// Obriši fajlove koji počinju sa '0'
try {
  for (const ent of fs.readdirSync(PUBLIC_DIR)) {
    if (ent.startsWith("0")) fs.rmSync(path.join(PUBLIC_DIR, ent), { force: true, recursive: true });
  }
} catch {}

// ----------------- DB -----------------
const DB_FILE = path.join(__dirname, "data", "poker.db");
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new Database(DB_FILE);

// Users tabela
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT,
 nick TEXT UNIQUE,
 pass TEXT,
 avatar TEXT DEFAULT '/avatar_1.png',
 balance REAL DEFAULT 0,
 disabled INTEGER DEFAULT 0,
 is_admin INTEGER DEFAULT 0,
 timebank INTEGER DEFAULT 90,       -- sekunde rezerve
 timebank_refill_at INTEGER DEFAULT (strftime('%s','now')),
 created_at TEXT DEFAULT (datetime('now')),
 last_seen  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_nick ON users(nick);
`);

// Tables
db.exec(`
CREATE TABLE IF NOT EXISTS tables (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT,
 seats INTEGER,
 sb REAL,
 bb REAL,
 min_buyin_bb INTEGER,
 max_buyin_bb INTEGER
);
`);

// Seats
db.exec(`
CREATE TABLE IF NOT EXISTS seats (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 table_id INTEGER,
 seat_index INTEGER,
 user_id INTEGER,
 stack REAL DEFAULT 0,
 in_hand INTEGER DEFAULT 0,
 sitout_next INTEGER DEFAULT 0,
 FOREIGN KEY(table_id) REFERENCES tables(id),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_seats_table ON seats(table_id);
`);

// Re-entry pravilo (6h)
db.exec(`
CREATE TABLE IF NOT EXISTS reentry (
 user_id INTEGER PRIMARY KEY,
 min_amount REAL,
 expires_at INTEGER
);
`);

// Ako stolovi ne postoje → kreiraj
if (!db.prepare(`SELECT COUNT(*) AS c FROM tables`).get().c) {
  const insT = db.prepare(`
    INSERT INTO tables(name,seats,sb,bb,min_buyin_bb,max_buyin_bb)
    VALUES (?,?,?,?,?,?)
  `);
  const smallID = insT.run("small", 9, 0.2, 0.5, MIN_BUYIN_BB, MAX_BUYIN_BB).lastInsertRowid;
  const bigID   = insT.run("big",   9, 1.0, 2.0, MIN_BUYIN_BB, MAX_BUYIN_BB).lastInsertRowid;

  const insS = db.prepare(`INSERT INTO seats(table_id,seat_index,user_id,stack,in_hand) VALUES(?,?,?,?,0)`);
  for (let i=0;i<9;i++) insS.run(smallID, i, null, 0);
  for (let i=0;i<9;i++) insS.run(bigID,   i, null, 0);

  console.log("✅ Inicijalizovana tabla small i big");
}

// ----------------- APP / HTTP -----------------
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(cookieParser());
app.use(express.static(PUBLIC_DIR, { index: false }));

// Alias za card back
app.get("/card_bach.png", (req, res) => {
  const normal = path.join(PUBLIC_DIR, "card_bach.png");
  const spaced = path.join(PUBLIC_DIR, "card_ bach.png");
  if (fs.existsSync(normal)) return res.sendFile(normal);
  if (fs.existsSync(spaced)) return res.sendFile(spaced);
  res.status(404).end();
});

// Serve front
app.get("/", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/admin", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "admin.html")));

// ----------------- AUTH -----------------
function makeToken(u) {
  return jwt.sign({ uid: u.id, nick: u.nick }, JWT_SECRET, { expiresIn: "30d" });
}
function readToken(req) {
  const t = req.cookies?.[TOKEN_NAME];
  if (!t) return null;
  try { return jwt.verify(t, JWT_SECRET); } catch { return null; }
}
function authRequired(req, res, next) {
  const p = readToken(req);
  if (!p) return res.status(401).json({ ok:false, error:"unauthorized" });
  req.user = p;
  next();
}
function adminKeyRequired(req,res,next){
  if (req.header("x-admin-key") !== ADMIN_KEY) return res.status(401).json({ ok:false, error:"bad_admin_key" });
  next();
}

// Register
app.post("/api/register", (req,res)=>{
  const { email, nick, pass } = req.body||{};
  if(!nick || !pass) return res.json({ok:false,error:"nick_pass_required"});
  if(db.prepare(`SELECT id FROM users WHERE nick=?`).get(nick)) return res.json({ok:false,error:"nick_exists"});
  const hash = bcrypt.hashSync(String(pass),10);
  const id = db.prepare(`INSERT INTO users(email,nick,pass) VALUES(?,?,?)`).run(email||null,nick,hash).lastInsertRowid;
  const u = db.prepare(`SELECT id,nick,avatar,balance FROM users WHERE id=?`).get(id);
  const token = makeToken(u);
  res.cookie(TOKEN_NAME, token, { httpOnly:true,sameSite:"lax",secure:false });
  res.json({ok:true,user:u});
});

// Login
app.post("/api/login",(req,res)=>{
  const { nick, pass } = req.body||{};
  const u = db.prepare(`SELECT * FROM users WHERE nick=?`).get(nick);
  if(!u) return res.json({ok:false,error:"invalid"});
  if(!bcrypt.compareSync(String(pass),u.pass||"")) return res.json({ok:false,error:"invalid"});
  if(u.disabled) return res.json({ok:false,error:"disabled"});
  const token = makeToken(u);
  db.prepare(`UPDATE users SET last_seen=datetime('now') WHERE id=?`).run(u.id);
  res.cookie(TOKEN_NAME,token,{httpOnly:true,sameSite:"lax",secure:false});
  res.json({ok:true,user:{id:u.id,nick:u.nick,avatar:u.avatar,balance:u.balance}});
});

// Logout
app.post("/api/logout",(req,res)=>{ res.clearCookie(TOKEN_NAME); res.json({ok:true}); });

// ----------------- ADMIN (FIXED & ENHANCED) -----------------
app.get("/api/admin/users", adminKeyRequired, (req, res) => {
  const qRaw   = (req.query.q || "").toString().trim().toLowerCase();
  const sortIn = (req.query.sort || "id").toString().toLowerCase();
  const ascIn  = req.query.asc === "1" ? "ASC" : "DESC";
  const limit  = Math.max(0, Math.min(Number(req.query.limit ?? 500), 5000));
  const offset = Math.max(0, Number(req.query.offset ?? 0));
  const sortCol = ({ id:"id", nick:"nick", balance:"balance" }[sortIn]) || "id";
  const hasQ = qRaw.length > 0;
  const params = { limit, offset };
  let where = "";
  if (hasQ) {
    params.like = `%${qRaw}%`;
    where = "WHERE LOWER(COALESCE(nick,'')) LIKE @like OR LOWER(COALESCE(email,'')) LIKE @like";
  }
  const rows = db.prepare(`
    SELECT
      id,
      CASE
        WHEN nick IS NULL OR TRIM(nick) = '' THEN 'user_' || id
        ELSE nick
      END AS nick,
      email,
      avatar,
      CAST(balance AS REAL) AS balance,
      disabled
    FROM users
    ${where}
    ORDER BY ${sortCol} ${ascIn}
    LIMIT @limit OFFSET @offset
  `).all(params);
  res.json({ ok:true, users: rows, count: rows.length });
});

app.post("/api/admin/chips", adminKeyRequired, (req, res) => {
  let { nick, amount } = req.body || {};
  nick = (nick ?? "").toString().trim();
  const delta = Number(amount);
  if (!nick || !Number.isFinite(delta) || delta === 0) {
    return res.json({ ok:false, error:"bad_params" });
  }
  const u = db.prepare(`
    SELECT
      id,
      CASE WHEN nick IS NULL OR TRIM(nick)='' THEN 'user_'||id ELSE nick END AS nick,
      CAST(balance AS REAL) AS balance
    FROM users
    WHERE LOWER(COALESCE(nick,'')) = LOWER(?)
  `).get(nick);
  if (!u) return res.json({ ok:false, error:"notfound" });
  const desired = u.balance + delta;
  const newBal  = desired < 0 ? 0 : Math.round(desired * 100) / 100;
  const applied = Math.round((newBal - u.balance) * 100) / 100;
  const tx = db.transaction(() => {
    db.prepare(`UPDATE users SET balance = ?, last_seen = datetime('now') WHERE id = ?`)
      .run(newBal, u.id);
  });
  tx();
  return res.json({
    ok:true,
    user_id: u.id,
    nick: u.nick,
    old_balance: u.balance,
    delta_requested: delta,
    delta_applied: applied,
    balance: newBal
  });
});

app.post("/api/admin/disable", adminKeyRequired, (req, res) => {
  let { nick, flag } = req.body || {};
  nick = (nick ?? "").toString().trim();
  const f = Number(flag) ? 1 : 0;
  if (!nick) return res.json({ ok:false, error:"bad_params" });
  const u = db.prepare(`
    SELECT id FROM users
    WHERE LOWER(COALESCE(nick,'')) = LOWER(?)
  `).get(nick);
  if (!u) return res.json({ ok:false, error:"notfound" });
  const tx = db.transaction(() => {
    db.prepare(`UPDATE users SET disabled = ? WHERE id = ?`).run(f, u.id);
  });
  tx();
  const out = db.prepare(`
    SELECT
      id,
      CASE WHEN nick IS NULL OR TRIM(nick)='' THEN 'user_'||id ELSE nick END AS nick,
      email,
      avatar,
      CAST(balance AS REAL) AS balance,
      disabled
    FROM users WHERE id = ?
  `).get(u.id);
  res.json({ ok:true, user: out });
});


// ----------------- BUY-IN (sit) -----------------
function getTable(name){ return db.prepare(`SELECT * FROM tables WHERE name=?`).get(name); }

app.post("/api/table/sit",authRequired,(req,res)=>{
  const { table, seat_index, buyin } = req.body||{};
  const t = getTable(table);
  if(!t) return res.json({ok:false,error:"table"});
  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.uid);
  if(u.disabled) return res.json({ok:false,error:"disabled"});
  const min = Math.round(t.bb * MIN_BUYIN_BB);
  const max = Math.round(t.bb * MAX_BUYIN_BB);
  const amount = Math.round(Number(buyin||0));
  if(amount<min || amount>max) return res.json({ok:false,error:`buyin_${min}_${max}`});
  if(u.balance<amount) return res.json({ok:false,error:"balance"});
  const seat = db.prepare(`SELECT * FROM seats WHERE table_id=? AND seat_index=?`).get(t.id,seat_index);
  if(!seat||seat.user_id) return res.json({ok:false,error:"seat"});
  const tx=db.transaction(()=>{
    db.prepare(`UPDATE users SET balance=balance-? WHERE id=?`).run(amount,u.id);
    db.prepare(`UPDATE seats SET user_id=?,stack=? WHERE id=?`).run(u.id,amount,seat.id);
  });
  tx();
  res.json({ok:true});
});


// ================== DIO 2 — TABLE STATE & TOPUP & LEAVE ==================

// Helpers za seats
const qSeatByUid = db.prepare(`
  SELECT s.*, t.id AS tid, t.name AS table_name, t.bb AS table_bb
  FROM seats s
  JOIN tables t ON t.id = s.table_id
  WHERE s.user_id = ?
`);

const qSeatsByTid = db.prepare(`
  SELECT seat_index, user_id, stack, in_hand, sitout_next
  FROM seats WHERE table_id = ?
  ORDER BY seat_index
`);

const qTableByName = db.prepare(`SELECT * FROM tables WHERE name = ?`);
const qTableById   = db.prepare(`SELECT * FROM tables WHERE id = ?`);

// ----------------- STATE SNAPSHOT (za refresh UI) -----------------
app.get("/api/tables/state", (req, res) => {
  const name = (req.query.table || "small").toString();
  const t = qTableByName.get(name);
  if (!t) return res.json({ ok:false, error:"table_not_found" });

  const seats = qSeatsByTid.all(t.id);

  res.json({
    ok:true,
    table:{
      id: t.id,
      name: t.name,
      sb: t.sb,
      bb: t.bb,
      min_buyin_bb: t.min_buyin_bb,
      max_buyin_bb: t.max_buyin_bb
    },
    seats
  });
});

// ----------------- SIT OUT NEXT HAND -----------------
app.post("/api/table/sitout", authRequired, (req, res) => {
  const { sitout } = req.body || {};
  const s = qSeatByUid.get(req.user.uid);
  if (!s) return res.json({ ok:false, error:"not_seated" });

  db.prepare(`UPDATE seats SET sitout_next=? WHERE id=?`).run(sitout ? 1 : 0, s.id);
  res.json({ ok:true, sitout_next: sitout?1:0 });
});

// ----------------- TOP-UP (poslije folda ili između ruku) -----------------
app.post("/api/table/topup", authRequired, (req, res) => {
  const { amount } = req.body || {};
  const add = Math.round(Number(amount || 0) * 100) / 100; // 2 dec
  if (!Number.isFinite(add) || add <= 0) return res.json({ ok:false, error:"bad_amount" });

  const seat = qSeatByUid.get(req.user.uid);
  if (!seat) return res.json({ ok:false, error:"not_seated" });

  // mora biti izvan aktivne ruke
  if (seat.in_hand) return res.json({ ok:false, error:"not_between_hands" });

  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.uid);
  if (u.balance < add) return res.json({ ok:false, error:"not_enough_balance" });

  const t = qTableById.get(seat.tid);
  const maxStack = Math.round(t.bb * MAX_BUYIN_BB * 100) / 100;
  const newStack = Math.min(seat.stack + add, maxStack);
  const realAdd = newStack - seat.stack;
  if (realAdd <= 0) return res.json({ ok:false, error:"max_reached" });

  const tx = db.transaction(()=>{
    db.prepare(`UPDATE users SET balance=balance-? WHERE id=?`).run(realAdd, u.id);
    db.prepare(`UPDATE seats SET stack=? WHERE id=?`).run(newStack, seat.id);
  });
  tx();

  res.json({ ok:true, stack:newStack, debited:realAdd });
});

// ----------------- LEAVE TABLE (između ruku) -----------------
app.post("/api/table/leave", authRequired, (req, res) => {
  const seat = qSeatByUid.get(req.user.uid);
  if (!seat) return res.json({ ok:false, error:"not_seated" });

  // ne može napustiti tokom ruke
  if (seat.in_hand) return res.json({ ok:false, error:"cannot_leave_midhand" });

  const tx = db.transaction(() => {
    // vrati stack u wallet
    db.prepare(`UPDATE users SET balance=balance+? WHERE id=?`).run(seat.stack, req.user.uid);

    // oslobodi mjesto
    db.prepare(`UPDATE seats SET user_id=NULL, stack=0, in_hand=0, sitout_next=0 WHERE id=?`).run(seat.id);
  });
  tx();

  // upiši re-entry minimum (mora se vratiti sa >= toliko, do 6h)
  const minAmount = seat.stack;
  const expires = Date.now() + 6 * 60 * 60 * 1000; // 6h
  db.prepare(`
    INSERT INTO reentry(user_id, min_amount, expires_at)
    VALUES(?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET min_amount=excluded.min_amount, expires_at=excluded.expires_at
  `).run(req.user.uid, minAmount, expires);

  return res.json({ ok:true });
});

// ----------------- PRIMIJENI RE-ENTRY PRAVILO PRILIKOM /table/sit -----------------
const oldSit = app._router.stack.find(r=>r.route && r.route.path==="/api/table/sit").route.stack[0].handle;

app._router.stack.find(r=>r.route && r.route.path==="/api/table/sit").route.stack[0].handle = (req,res)=>{
  const { table, buyin } = req.body||{};
  const t = getTable(table);
  if (!t) return oldSit(req,res);

  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.uid);

  // check re-entry
  const re = db.prepare(`SELECT * FROM reentry WHERE user_id=?`).get(req.user.uid);
  if (re && re.expires_at > Date.now()) {
    const enforcedMin = Math.max(re.min_amount, Math.round(t.bb * MIN_BUYIN_BB));
    if (buyin < enforcedMin) {
      return res.json({ ok:false, error:`reentry_min_${enforcedMin}` });
    }
  } else {
    db.prepare(`DELETE FROM reentry WHERE user_id=?`).run(req.user.uid);
  }

  return oldSit(req,res);
};

// ================== DIO 3 — WEBSOCKET ENGINE (POČETAK) ==================

// Pomoć: izvuci user iz websocket konekcije (cookie -> JWT)
function wsAuth(req) {
  try {
    const cookie = req.headers.cookie || "";
    const part = cookie.split(";").find(x => x.trim().startsWith(TOKEN_NAME+"="));
    if (!part) return null;
    const token = part.split("=")[1];
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Format karata: r + s (npr. "Ah", "Td")
const RANKS = ["2","3","4","5","6","7","8","9","T","J","Q","K","A"];
const SUITS = ["c","d","h","s"]; // ♣ ♦ ♥ ♠

// Fisher-Yates shuffle
function shuffle(deck) {
  for (let i = deck.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random()* (i+1));
    [deck[i], deck[j]] = [deck[j], deck[i]];
  }
}

// Kreiraj novi špil
function makeDeck() {
  const d = [];
  for (const r of RANKS) for (const s of SUITS) d.push(r+s);
  shuffle(d);
  return d;
}

// Runtime stanje (small i big stol odvojeno)
function initialTableRuntime(tid, bb) {
  return {
    table_id: tid,
    bb: bb,
    seats: Array(9).fill(null),        // user_id or null
    stacks: Array(9).fill(0),
    in_hand: Array(9).fill(0),
    folded: Array(9).fill(0),
    allin: Array(9).fill(0),
    bets: Array(9).fill(0),
    dealer: -1,                        // dealer button seat index
    to_act: -1,                        // seat index whose turn
    pot: 0,
    board: [],                         // community cards
    deck: [],
    phase: "waiting",                  // waiting | preflop | flop | turn | river | showdown
    lastAction: Date.now(),
    timebank: {},                      // uid -> seconds
  };
}

// Učitaj DB ID-ove stolova
const smallTable = qTableByName.get("small");
const bigTable   = qTableByName.get("big");

let T = {
  small: initialTableRuntime(smallTable.id, smallTable.bb),
  big:   initialTableRuntime(bigTable.id,   bigTable.bb)
};

// Mapa konekcija: uid -> ws socket
let SESS = {};

// Broadcast utility
function broadcast(tableName, msg) {
  const rt = T[tableName];
  for (let i = 0; i < rt.seats.length; i++) {
    const uid = rt.seats[i];
    if (!uid) continue;
    const ws = SESS[uid];
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  }
}

// Pošalji privatne karte samo jednom igraču
function sendHoleCards(uid, cards) {
  const ws = SESS[uid];
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type:"HOLE", cards }));
  }
}

// Sync cijelog stanja stola klijentu
function sendTableState(tableName) {
  const rt = T[tableName];
  const snapshot = {
    type: "STATE",
    table: tableName,
    seats: rt.seats,
    stacks: rt.stacks,
    in_hand: rt.in_hand,
    folded: rt.folded,
    allin: rt.allin,
    bets: rt.bets,
    pot: rt.pot,
    board: rt.board,
    dealer: rt.dealer,
    to_act: rt.to_act,
    phase: rt.phase
  };
  broadcast(tableName, snapshot);
}

// ----------------- WEBSOCKET CONNECTION -----------------
wss.on("connection", (ws, req) => {
  const auth = wsAuth(req);
  if (!auth) {
    ws.close();
    return;
  }
  const uid = auth.uid;
  SESS[uid] = ws;
  ws.isAlive = true;

  ws.on("pong", () => (ws.isAlive = true));
  ws.on("close", () => { delete SESS[uid]; });

  ws.on("message", (msg) => {
    let data;
    try { data = JSON.parse(msg.toString()); } catch { return; }

    // switch akcija (nastavlja se u DIO 3/5 — SLJEDEĆI DIO)
    handleWS(uid, ws, data);
  });
});

// Keep-alive da Render ne prekine konekcije
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);

// Handler akcija (nastavak u sljedećem dijelu)
function handleWS(uid, ws, data) {
  // Ovo ćemo popuniti u nastavku (DIO 3 — nastavak)
}
// ================== DIO 3B — AKCIJE, BETTING LOGIKA, FAZE, SHOWDOWN ==================

// Pomagala
function nextOccupiedSeat(rt, start) {
  for (let k = 1; k <= 9; k++) {
    const i = (start + k) % 9;
    if (rt.seats[i] && rt.in_hand[i] && !rt.folded[i] && (rt.stacks[i] > 0 || rt.bets[i] >= 0)) return i;
  }
  return -1;
}
function aliveInHand(rt) {
  const arr = [];
  for (let i=0;i<9;i++) if (rt.seats[i] && rt.in_hand[i] && !rt.folded[i]) arr.push(i);
  return arr;
}
function streetAllBetsEqualOrAllIn(rt) {
  const actives = aliveInHand(rt);
  if (actives.length <= 1) return true;
  // Ako je neko all-in, uspoređujemo efektivne uloge
  let ref = null;
  for (const i of actives) {
    if (rt.allin[i]) continue;
    ref = rt.bets[i];
    break;
  }
  if (ref === null) return true; // svi all-in
  for (const i of actives) {
    if (rt.allin[i]) continue;
    if (rt.bets[i] !== ref) return false;
  }
  return true;
}
function collectBetsToPot(rt) {
  for (let i=0;i<9;i++) {
    rt.pot += rt.bets[i];
    rt.bets[i] = 0;
  }
}
function minRaiseSize(rt, bb) {
  // Min-raise = zadnja veličina raise-a; ako nema, to je BB (NLH)
  return Math.max(bb, rt._lastRaiseSize || bb);
}
function dealBoard(rt, n) {
  for (let k=0;k<n;k++) rt.board.push(rt.deck.pop());
}

// Praćenje agresora (za showdown red)
function markAggressor(rt, seat) { rt._lastAggressor = seat; }

// Prijelaz na sljedeću fazu / završetak
function advancePhase(tableName) {
  const rt = T[tableName];
  // Ako je ostao 1 igrač → odmah show pot njemu
  const alive = aliveInHand(rt);
  if (alive.length === 1) {
    collectBetsToPot(rt);
    const winnerSeat = alive[0];
    const rake = Math.floor(rt.pot * RAKE_PERCENT) / 100;
    const winAmt = rt.pot - rake;
    rt.stacks[winnerSeat] += winAmt;
    rt.pot = 0;
    broadcast(tableName, { type:"WIN", seat:winnerSeat, amount:winAmt, rake });
    return endHand(tableName);
  }

  switch (rt.phase) {
    case "preflop": {
      collectBetsToPot(rt);
      rt.phase = "flop";
      dealBoard(rt, 3);
      rt._lastRaiseSize = null;
      pickFirstToActPostflop(rt, tableName);
      break;
    }
    case "flop": {
      collectBetsToPot(rt);
      rt.phase = "turn";
      dealBoard(rt, 1);
      rt._lastRaiseSize = null;
      pickFirstToActPostflop(rt, tableName);
      break;
    }
    case "turn": {
      collectBetsToPot(rt);
      rt.phase = "river";
      dealBoard(rt, 1);
      rt._lastRaiseSize = null;
      pickFirstToActPostflop(rt, tableName);
      break;
    }
    case "river": {
      collectBetsToPot(rt);
      rt.phase = "showdown";
      doShowdown(tableName);
      return;
    }
  }
  rt.lastAction = Date.now();
  sendTableState(tableName);
}

// Tko prvi govori postflop: prvi lijevo od dealera koji je živ
function pickFirstToActPostflop(rt, tableName) {
  let i = rt.dealer;
  for (;;) {
    i = (i + 1) % 9;
    if (rt.seats[i] && rt.in_hand[i] && !rt.folded[i]) { rt.to_act = i; break; }
  }
  broadcast(tableName, { type:"TO_ACT", seat: rt.to_act });
}

// Kraj ruke → priprema sljedeće
function endHand(tableName) {
  const rt = T[tableName];
  rt.phase = "waiting";
  rt.board = [];
  rt.bets = Array(9).fill(0);
  rt.in_hand = Array(9).fill(0);
  rt.folded = Array(9).fill(0);
  rt.allin = Array(9).fill(0);
  rt._lastRaiseSize = null;
  rt._lastAggressor = null;
  rt.to_act = -1;
  rt.deck = [];
  rt.pot = 0;

  sendTableState(tableName);

  // Auto-start sljedeće ruke kad su ≥2 igrača
  setTimeout(()=>tryStartHand(tableName), 800);
}

// Validacija i izvršenje akcija
function actFold(tableName, seat) {
  const rt = T[tableName];
  if (!rt.in_hand[seat] || rt.folded[seat]) return;
  rt.folded[seat] = 1;
}
function actCheck(tableName, seat) {
  const rt = T[tableName];
  const maxBet = Math.max(...rt.bets);
  if (rt.bets[seat] !== maxBet) return false; // ne može check ako ima betToCall
  return true;
}
function actCall(tableName, seat) {
  const rt = T[tableName];
  const maxBet = Math.max(...rt.bets);
  const need = maxBet - rt.bets[seat];
  if (need <= 0) return true; // nema šta callati
  const pay = Math.min(need, rt.stacks[seat]);
  rt.stacks[seat] -= pay;
  rt.bets[seat] += pay;
  if (rt.stacks[seat] <= 0) rt.allin[seat] = 1;
  return true;
}
function actRaise(tableName, seat, amount) {
  const rt = T[tableName];
  const bb = T[tableName].bb;

  // brojke s 2 dec
  amount = Math.round(Number(amount||0)*100)/100;
  if (!Number.isFinite(amount) || amount <= 0) return false;

  const currentMax = Math.max(...rt.bets);
  const toCall = currentMax - rt.bets[seat];
  if (toCall < 0) return false;

  // Ako igrač unese više nego ima → ALL-IN (cap na stack)
  let totalPut = toCall + amount;
  const maxCanPut = rt.stacks[seat]; // sve iz stacka
  if (totalPut >= maxCanPut) {
    // ALL-IN (može biti za manje od minRaise i/ili manje od call-a → NLH dopušta)
    const pay = Math.min(currentMax - rt.bets[seat] + amount, maxCanPut);
    rt.stacks[seat] -= pay;
    rt.bets[seat] += pay;
    rt.allin[seat] = 1;
    markAggressor(rt, seat);
    return true;
  }

  // Nije all-in: mora ispoštovati min raise
  const minR = minRaiseSize(rt, bb);
  if (amount < minR) return false;

  // Izvrši call + raise
  const pay = toCall + amount;
  if (pay > rt.stacks[seat]) return false; // ne bi trebalo ovdje (obrađeno gore)
  rt.stacks[seat] -= pay;
  rt.bets[seat] += pay;
  rt._lastRaiseSize = amount; // nova minimalna visina raise-a
  markAggressor(rt, seat);
  return true;
}

// Sljedeći na potezu ili kraj ulice/ruke
function advanceTurnOrStreet(tableName) {
  const rt = T[tableName];
  if (aliveInHand(rt).length <= 1) return advancePhase(tableName);

  if (streetAllBetsEqualOrAllIn(rt)) {
    // Kraj ulice
    return advancePhase(tableName);
  }

  // inače: sljedeći aktivni
  rt.to_act = nextOccupiedSeat(rt, rt.to_act);
  rt.lastAction = Date.now();
  broadcast(tableName, { type:"TO_ACT", seat: rt.to_act });
}

// Timer: 30s + timebank 90s (reset 1h per user)
setInterval(() => {
  const now = Date.now();
  for (const tableName of ["small","big"]) {
    const rt = T[tableName];
    if (rt.phase === "waiting" || rt.to_act < 0) continue;

    const seat = rt.to_act;
    const uid = rt.seats[seat];
    if (!uid) continue;

    const u = db.prepare(`SELECT id,timebank,timebank_refill_at FROM users WHERE id=?`).get(uid);
    if (!u) continue;

    // refill timebank ako prošlo 1h
    if (u.timebank_refill_at && u.timebank_refill_at <= Math.floor(now/1000)) {
      db.prepare(`UPDATE users SET timebank=90, timebank_refill_at=strftime('%s','now','+1 hour') WHERE id=?`).run(uid);
      u.timebank = 90;
    }

    const elapsed = Math.floor((now - rt.lastAction)/1000);
    if (elapsed <= 30) continue;

    const over = elapsed - 30;
    if (over <= u.timebank) {
      // troši timebank – ništa ne radimo osim sync
      continue;
    }

    // isteklo sve: auto-akcija
    const maxBet = Math.max(...rt.bets);
    const myBet  = rt.bets[seat];
    const betToCall = maxBet - myBet;

    if (betToCall > 0) {
      // auto-fold
      rt.folded[seat] = 1;
      broadcast(tableName, { type:"AUTO", seat, action:"FOLD" });
    } else {
      // auto-check
      broadcast(tableName, { type:"AUTO", seat, action:"CHECK" });
    }
    advanceTurnOrStreet(tableName);
  }
}, 1000);

// SHOWDOWN
function doShowdown(tableName) {
  const rt = T[tableName];
  const alive = aliveInHand(rt);
  // Saberi sve betove
  collectBetsToPot(rt);

  // Skupi ruke iz DB-a: mi nismo pohranjivali hole karte u DB; šaljemo ih privatno.
  // Ovdje radimo evaluaciju preko evaluator funkcije (DIO 4).
  // Pretpostavljamo da svako ima 2 hole (mi smo ih poslali putem sendHoleCards), ali za evaluaciju trebamo znati karte.
  // Rješenje: držimo ih privremeno u runtime-u.
  // => Ugradimo držanje HOLE karata:
}

// Dodaj runtime polje za hole karte (uid -> [c1,c2])
T.small.holes = {};
T.big.holes = {};

const _oldSendHole = sendHoleCards;
sendHoleCards = function(uid, cards){
  const tab = tableOf(uid);
  if (tab) {
    T[tab].holes[uid] = cards.slice();
  }
  _oldSendHole(uid, cards);
};

// Evaluacija i raspodjela
function showdownAndPayout(tableName) {
  const rt = T[tableName];
  const aliveSeats = aliveInHand(rt);
  const board = rt.board.slice();
  const contenders = aliveSeats.map(seat => {
    const uid = rt.seats[seat];
    const hole = (rt.holes[uid] || []).slice();
    return { seat, uid, hole };
  });

  // Evaluiraj sve (fun. evaluateHand u DIO 4)
  const scored = contenders.map(c => ({
    seat: c.seat,
    uid: c.uid,
    hole: c.hole,
    score: evaluateHand(c.hole, board) // {rank, kickers, label}
  }));

  // Sortiraj od najboljeg do najgoreg
  scored.sort((a,b)=>{
    // viši rank pobjeđuje; compare lexicographically [rank,...kickers]
    for (let i=0;i< a.score.arr.length;i++){
      const d = b.score.arr[i] - a.score.arr[i];
      if (d !== 0) return d;
    }
    return 0;
  });

  // Muck pravilo: otvaramo redoslijedom — zadnji agresor prvi; ako nije bilo raisa, SB→BB
  const order = showdownOpenOrder(rt, scored.map(s=>s.seat));

  // Emit otvaranja uz muck slabijih od trenutnog najboljeg
  let bestSoFar = null; // array rank
  const opened = [];
  for (const seat of order) {
    const obj = scored.find(s=>s.seat===seat);
    if (!obj) continue;
    if (!bestSoFar) {
      opened.push(obj);
      bestSoFar = obj.score.arr;
      broadcast(tableName, { type:"SHOW", seat, hole: obj.hole, label: obj.score.label });
    } else {
      // ako je slabiji od bestSoFar → muck (ne pokazuj)
      if (compareScore(obj.score.arr, bestSoFar) < 0) {
        // muck: samo javi da je muck
        broadcast(tableName, { type:"MUCK", seat });
      } else {
        opened.push(obj);
        bestSoFar = obj.score.arr;
        broadcast(tableName, { type:"SHOW", seat, hole: obj.hole, label: obj.score.label });
      }
    }
  }

  // Pobjednik(i): prvi element scored je najbolji
  const top = scored[0].score.arr;
  const winners = scored.filter(s=>compareScore(s.score.arr, top)===0);

  collectBetsToPot(rt);
  const rake = Math.floor(rt.pot * RAKE_PERCENT) / 100;
  const distributable = rt.pot - rake;
  const winEach = Math.floor(distributable / winners.length * 100) / 100;

  for (const w of winners) {
    rt.stacks[w.seat] += winEach;
    broadcast(tableName, { type:"WIN", seat:w.seat, amount:winEach, label:w.score.label });
  }
  rt.pot = 0;

  // Očisti privremene hole
  if (tableName==="small") T.small.holes = {};
  else T.big.holes = {};

  endHand(tableName);
}

// Redoslijed otvaranja
function showdownOpenOrder(rt, seatOrderByStrength) {
  // Ako imamo zadnjeg agresora → on otvara prvi, pa udesno
  if (typeof rt._lastAggressor === "number" && rt._lastAggressor >= 0) {
    const order = [];
    let i = rt._lastAggressor;
    for (let k=0;k<9;k++){
      if (rt.seats[i] && rt.in_hand[i] && !rt.folded[i]) order.push(i);
      i = (i+1)%9;
    }
    return order;
  }
  // Inače SB → BB → …
  const order = [];
  let i = rt.dealer;
  for (let k=0;k<9;k++){
    i = (i+1)%9;
    if (rt.seats[i] && rt.in_hand[i] && !rt.folded[i]) order.push(i);
  }
  return order;
}

// Usporedba score array-a
function compareScore(a, b) {
  for (let i=0;i<Math.max(a.length,b.length);i++){
    const d = (a[i]||0) - (b[i]||0);
    if (d!==0) return d;
  }
  return 0;
}

// Obrada WS akcija od klijenta
// data: { type:"ACT", table:"small"|"big", action:"FOLD"|"CHECK"|"CALL"|"RAISE", amount? }
function handleWS(uid, ws, data) {
  // JOIN je u DIO 3A
  if (data.type === "JOIN") {
    const tableName = data.table === "big" ? "big" : "small";
    joinTable(uid, tableName);
    tryStartHand(tableName);
    return;
  }

  if (data.type !== "ACT") return;
  const tableName = data.table === "big" ? "big" : "small";
  const rt = T[tableName];

  // provjeri je li na potezu
  const seat = rt.seats.indexOf(uid);
  if (seat !== rt.to_act) return;

  const action = (data.action||"").toUpperCase();
  let ok = false;

  switch (action) {
    case "FOLD": {
      actFold(tableName, seat);
      ok = true;
      broadcast(tableName, { type:"ACT", seat, action:"FOLD" });
      break;
    }
    case "CHECK": {
      ok = actCheck(tableName, seat);
      if (ok) broadcast(tableName, { type:"ACT", seat, action:"CHECK" });
      break;
    }
    case "CALL": {
      ok = actCall(tableName, seat);
      if (ok) broadcast(tableName, { type:"ACT", seat, action:"CALL" });
      break;
    }
    case "RAISE": {
      const amt = Number(data.amount||0);
      ok = actRaise(tableName, seat, amt);
      if (ok) broadcast(tableName, { type:"ACT", seat, action:"RAISE", amount: Math.round(Number(amt)*100)/100 });
      break;
    }
  }

  if (!ok) {
    ws.send(JSON.stringify({ ok:false, error:"bad_action_or_amount" }));
    return;
  }

  // Napredak poteza/ulice
  advanceTurnOrStreet(tableName);
}
// ================== DIO 4 — EVALUATOR TEXAS HOLD'EM ==================
//
// Jednostavan ali točan evaluator 7-card best hand.
// Vraća objekt: { arr:[rank, k1,k2,k3,k4,k5], label:string }
//
// rank: 9=StraightFlush, 8=FourKind, 7=FullHouse, 6=Flush, 5=Straight, 4=Trips, 3=TwoPair, 2=Pair, 1=HighCard

const RVAL = { "2":0,"3":1,"4":2,"5":3,"6":4,"7":5,"8":6,"9":7,"T":8,"J":9,"Q":10,"K":11,"A":12 };

function evaluateHand(hole, board) {
  const cards = hole.concat(board); // 7 karata
  // odvoji rank/suit
  const ranks = cards.map(c=>c[0]);
  const suits = cards.map(c=>c[1]);

  // count ranks
  const rc = {};
  for(const r of ranks) rc[r] = (rc[r]||0)+1;

  // group by suit
  const sc = {};
  for (let i=0;i<cards.length;i++){
    const s = suits[i], r=ranks[i];
    (sc[s] ||= []).push(r);
  }

  // helper: sort desc by RVAL
  const sortDesc = arr => arr.sort((a,b)=>RVAL[b]-RVAL[a]);

  // check flush
  let flushSuit = null, flushRanks = null;
  for (const s in sc) if (sc[s].length >= 5) { flushSuit = s; flushRanks = sortDesc(sc[s].slice()); break; }

  // straight helper (A-5 low straight)
  function bestStraight(arr) {
    // unique
    const u = Array.from(new Set(arr.map(r=>RVAL[r]))).sort((a,b)=>b-a);
    // Ace-low: dodaj -1 za A
    if (u.includes(12)) u.push(-1);
    let run=1, best=null, prev=null;
    for (let i=0;i<u.length;i++){
      if (prev===null || u[i] === prev-1) {
        run++;
      } else if (u[i] === prev) {
        // skip dup
      } else {
        run=1;
      }
      if (run>=5) best = u[i-4]; // najniži u nizu
      prev = u[i];
    }
    if (best===null) return null;
    return best+4; // high card value
  }

  // StraightFlush
  if (flushRanks) {
    const hi = bestStraight(flushRanks);
    if (hi!==null) return { arr:[9, hi,0,0,0,0], label:`Straight Flush` };
  }

  // FourKind / FullHouse / Trips / TwoPair / Pair / High
  const rankCounts = Object.entries(rc).map(([r,c])=>({r,c,v:RVAL[r]})).sort((a,b)=> b.c - a.c || b.v - a.v);

  // quads?
  const quad = rankCounts.find(x=>x.c===4);
  if (quad) {
    const kick = sortDesc(ranks.filter(r=>r!==quad.r))[0];
    return { arr:[8, RVAL[quad.r], RVAL[kick],0,0,0], label:`Four of a Kind` };
  }

  // trips & pairs
  const trips = rankCounts.filter(x=>x.c===3).map(x=>x.r).sort((a,b)=>RVAL[b]-RVAL[a]);
  const pairs = rankCounts.filter(x=>x.c===2).map(x=>x.r).sort((a,b)=>RVAL[b]-RVAL[a]);
  const singles = rankCounts.filter(x=>x.c===1).map(x=>x.r).sort((a,b)=>RVAL[b]-RVAL[a]);

  // full house
  if (trips.length) {
    if (pairs.length || trips.length>=2) {
      const t = trips[0];
      const p = pairs.length ? pairs[0] : trips[1];
      return { arr:[7, RVAL[t], RVAL[p],0,0,0], label:`Full House` };
    }
  }

  // flush
  if (flushRanks) {
    const top5 = flushRanks.slice(0,5).map(r=>RVAL[r]);
    return { arr:[6, ...top5], label:`Flush` };
  }

  // straight
  const hiS = bestStraight(ranks);
  if (hiS!==null) return { arr:[5, hiS,0,0,0,0], label:`Straight` };

  // trips
  if (trips.length) {
    const t = trips[0];
    const kickers = sortDesc(ranks.filter(r=>r!==t)).slice(0,2).map(r=>RVAL[r]);
    return { arr:[4, RVAL[t], ...kickers], label:`Three of a Kind` };
  }

  // two pair
  if (pairs.length >= 2) {
    const [p1,p2] = pairs.slice(0,2);
    const kicker = sortDesc(ranks.filter(r=>r!==p1 && r!==p2))[0];
    return { arr:[3, RVAL[p1], RVAL[p2], RVAL[kicker],0,0], label:`Two Pair` };
  }

  // one pair
  if (pairs.length === 1) {
    const p = pairs[0];
    const ks = sortDesc(ranks.filter(r=>r!==p)).slice(0,3).map(r=>RVAL[r]);
    return { arr:[2, RVAL[p], ...ks], label:`Pair` };
  }

  // high card
  const top = sortDesc(ranks).slice(0,5).map(r=>RVAL[r]);
  return { arr:[1, ...top], label:`High Card` };
}
// ================== DIO 5 — HEALTH & START ==================

// Render health
app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.get("/health",  (_req, res) => res.json({ ok:true, ts: Date.now() }));

// START
server.listen(PORT, HOST, () => {
  console.log(`✅ Poker server running at http://${HOST}:${PORT}`);
});
