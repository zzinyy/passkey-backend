// 과제 8 - 패스키(WebAuthn) 백엔드
// 등록(register) / 로그인(login) / 로그아웃(logout) / 비공개 자료 조회(/api/private) 를 처리한다.
// 저장소는 과제용으로 단순화하기 위해 JSON 파일을 사용한다. (실서비스라면 DB를 쓸 것)

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();

// ---- 환경설정 -------------------------------------------------------
// RP = Relying Party. 프론트엔드가 떠 있는 origin과 정확히 일치해야 한다.
const RP_NAME = "패스키 소개 페이지";
const RP_ID = process.env.RP_ID || "zzinyy.github.io"; // 도메인만 (스킴/포트 제외)
const ORIGIN = process.env.ORIGIN || "https://zzinyy.github.io"; // 프론트엔드 origin
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

app.use(express.json());
app.use(
  cors({
    origin: ORIGIN,
    credentials: true,
  })
);
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true, // https 필수 (배포 환경)
      sameSite: "none", // 프론트/백엔드 도메인이 다르므로 필요
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---- 아주 단순한 JSON 파일 저장소 ------------------------------------
const DB_PATH = path.join(__dirname, "data", "db.json");
function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    return { users: {} };
    // users[userId] = { id, username, credentials: [{credentialID, publicKey, counter, name, createdAt}] }
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// 등록/로그인 중 발급한 challenge를 잠깐 들고 있는 저장소 (메모리, 세션별)
// 실서비스라면 만료시간을 두고 DB나 redis에 저장해야 한다.
const pendingChallenges = new Map(); // key: userId or "anon:"+sessionID, value: { challenge, createdAt }

function getUserByUsername(db, username) {
  return Object.values(db.users).find((u) => u.username === username);
}

// 이미 쓴 로그인 challenge 재사용을 막기 위한 기록
const usedChallenges = new Set();

// ---- 데모용 비공개 콘텐츠 (계정별) -----------------------------------
const PRIVATE_CONTENT = {}; // userId -> array of items, seedPrivateContent()에서 채움
function seedPrivateContent(userId, username) {
  if (PRIVATE_CONTENT[userId]) return;
  PRIVATE_CONTENT[userId] = [
    { title: `${username}의 진행 중 프로젝트 메모`, body: "패스키 인증 과제 진행 중 - 이건 만들어 넣은 데모 데이터입니다." },
    { title: `${username}이 지원하려는 곳 목록`, body: "가상의 회사 A, 가상의 회사 B (실제 정보 아님)" },
    { title: `${username}의 회고`, body: "이번 주 회고: WebAuthn 흐름을 이해하는 데 시간이 걸렸다." },
  ];
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }
  next();
}

// ---- 등록: 1) 옵션 발급 ----------------------------------------------
app.post("/api/register/options", async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: "username이 필요합니다." });

  const db = loadDB();
  let user = getUserByUsername(db, username);
  if (!user) {
    user = { id: crypto.randomUUID(), username, credentials: [] };
    db.users[user.id] = user;
    saveDB(db);
  }

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(user.id),
    userName: user.username,
    attestationType: "none",
    excludeCredentials: user.credentials.map((c) => ({
      id: c.credentialID,
      type: "public-key",
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  // challenge는 서버가 직접 들고 있는다 (클라이언트를 믿지 않는다)
  pendingChallenges.set("reg:" + user.id, { challenge: options.challenge, createdAt: Date.now() });
  req.session.pendingUserId = user.id;

  res.json(options);
});

// ---- 등록: 2) 응답 검증 -----------------------------------------------
app.post("/api/register/verify", async (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) return res.status(400).json({ error: "등록 세션이 없습니다." });

  const pending = pendingChallenges.get("reg:" + userId);
  if (!pending) return res.status(400).json({ error: "만료되었거나 없는 challenge입니다." });

  const db = loadDB();
  const user = db.users[userId];
  if (!user) return res.status(400).json({ error: "사용자를 찾을 수 없습니다." });

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body.attResp,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "검증 실패" });
    }

    const { credential } = verification.registrationInfo;
    user.credentials.push({
      credentialID: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64"),
      counter: credential.counter,
      name: req.body.nickname || `패스키 ${user.credentials.length + 1}`,
      createdAt: new Date().toISOString(),
    });
    saveDB(db);
    pendingChallenges.delete("reg:" + userId);
    seedPrivateContent(user.id, user.username);

    res.json({ verified: true });
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

// ---- 로그인: 1) 옵션 발급 ----------------------------------------------
app.post("/api/login/options", async (req, res) => {
  const { username } = req.body;
  const db = loadDB();
  const user = getUserByUsername(db, username);
  if (!user || user.credentials.length === 0) {
    return res.status(400).json({ error: "등록된 패스키가 없습니다." });
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: "preferred",
    allowCredentials: user.credentials.map((c) => ({ id: c.credentialID, type: "public-key" })),
  });

  pendingChallenges.set("auth:" + user.id, { challenge: options.challenge, createdAt: Date.now() });
  req.session.pendingUserId = user.id;

  res.json(options);
});

// ---- 로그인: 2) 응답 검증 -----------------------------------------------
app.post("/api/login/verify", async (req, res) => {
  const userId = req.session.pendingUserId;
  if (!userId) return res.status(400).json({ error: "로그인 세션이 없습니다." });

  const pending = pendingChallenges.get("auth:" + userId);
  if (!pending) return res.status(400).json({ error: "만료되었거나 없는 challenge입니다." });

  // 이미 쓴 challenge 재사용 방지
  if (usedChallenges.has(pending.challenge)) {
    return res.status(400).json({ error: "이미 사용된 challenge입니다." });
  }

  const db = loadDB();
  const user = db.users[userId];
  const credId = req.body.authResp.id;
  const cred = user.credentials.find((c) => c.credentialID === credId);
  if (!cred) return res.status(400).json({ error: "등록되지 않은 패스키입니다." });

  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body.authResp,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credentialID,
        publicKey: Buffer.from(cred.publicKey, "base64"),
        counter: cred.counter,
      },
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "서명 검증 실패" });
    }

    cred.counter = verification.authenticationInfo.newCounter;
    saveDB(db);

    usedChallenges.add(pending.challenge);
    pendingChallenges.delete("auth:" + userId);

    req.session.userId = user.id;
    req.session.username = user.username;
    delete req.session.pendingUserId;

    res.json({ verified: true, username: user.username });
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

// ---- 로그아웃 ----------------------------------------------------------
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ---- 내 패스키 목록 / 삭제 -----------------------------------------------
app.get("/api/passkeys", requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users[req.session.userId];
  res.json(
    user.credentials.map((c) => ({ id: c.credentialID, name: c.name, createdAt: c.createdAt }))
  );
});

app.delete("/api/passkeys/:credentialID", requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users[req.session.userId];
  const before = user.credentials.length;
  user.credentials = user.credentials.filter((c) => c.credentialID !== req.params.credentialID);
  saveDB(db);
  if (user.credentials.length === before) return res.status(404).json({ error: "없음" });
  if (user.credentials.length === 0) {
    // 마지막 패스키를 지우면 더 이상 로그인할 방법이 없다 -> 안내만 하고 세션은 유지
    return res.json({ ok: true, warning: "마지막 패스키를 삭제했습니다. 더 이상 이 계정으로 로그인할 수 없습니다." });
  }
  res.json({ ok: true });
});

// ---- 비공개 자료 -----------------------------------------------------
app.get("/api/private", requireAuth, (req, res) => {
  const items = PRIVATE_CONTENT[req.session.userId] || [];
  res.json({ username: req.session.username, items });
});

app.get("/api/me", (req, res) => {
  res.json({ loggedIn: !!req.session.userId, username: req.session.username || null });
});

app.listen(PORT, () => console.log(`listening on ${PORT}`));