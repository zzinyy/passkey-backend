// 과제 8 - 패스키(WebAuthn) 백엔드
// 등록(register) / 로그인(login) / 로그아웃(logout) / 비공개 자료 조회(/api/private) 를 처리한다.
// 프론트(GitHub Pages)와 백엔드(Render)가 서로 다른 도메인이라 교차 사이트 쿠키가
// 브라우저에 따라 차단될 수 있어, 쿠키 대신 "토큰을 응답 본문으로 주고받는" 방식을 쓴다.
// 저장소는 과제용으로 단순화하기 위해 JSON 파일을 사용한다. (실서비스라면 DB를 쓸 것)

const express = require("express");
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
const RP_NAME = "패스키 소개 페이지";
const RP_ID = process.env.RP_ID || "zzinyy.github.io";
const ORIGIN = process.env.ORIGIN || "https://zzinyy.github.io";
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({ origin: ORIGIN }));

// ---- 아주 단순한 JSON 파일 저장소 ------------------------------------
const DB_PATH = path.join(__dirname, "data", "db.json");
function loadDB() {
  if (!fs.existsSync(DB_PATH)) return { users: {} };
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}
function saveDB(db) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ---- 토큰 기반 세션 (쿠키 대신) ----------------------------------------
// pendingSessions: 등록/로그인 "진행 중" 상태만 짧게 들고 있는 토큰
// authSessions: 로그인 완료 후 발급하는 토큰 (Authorization: Bearer 로 보내옴)
const pendingSessions = new Map(); // token -> { userId, createdAt }
const authSessions = new Map(); // token -> { userId, username, createdAt }
function newToken() {
  return crypto.randomBytes(24).toString("base64url");
}
function getBearerToken(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

// 등록/로그인 중 발급한 WebAuthn challenge (userId 기준으로 서버가 보관)
const pendingChallenges = new Map(); // key: "reg:"+userId 또는 "auth:"+userId
const usedChallenges = new Set(); // 이미 쓴 로그인 challenge 재사용 방지

function getUserByUsername(db, username) {
  return Object.values(db.users).find((u) => u.username === username);
}

// ---- 데모용 비공개 콘텐츠 (계정별) -----------------------------------
const PRIVATE_CONTENT = {};
function seedPrivateContent(userId, username) {
  if (PRIVATE_CONTENT[userId]) return;
  PRIVATE_CONTENT[userId] = [
    { title: `${username}의 진행 중 프로젝트 메모`, body: "패스키 인증 과제 진행 중 - 이건 만들어 넣은 데모 데이터입니다." },
    { title: `${username}이 지원하려는 곳 목록`, body: "가상의 회사 A, 가상의 회사 B (실제 정보 아님)" },
    { title: `${username}의 회고`, body: "이번 주 회고: WebAuthn 흐름을 이해하는 데 시간이 걸렸다." },
  ];
}

function requireAuth(req, res, next) {
  const token = getBearerToken(req);
  const session = token && authSessions.get(token);
  if (!session) return res.status(401).json({ error: "로그인이 필요합니다." });
  req.userId = session.userId;
  req.username = session.username;
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
    excludeCredentials: user.credentials.map((c) => ({ id: c.credentialID, type: "public-key" })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
      authenticatorAttachment: "platform", // 이 기기(노트북/휴대폰 내장 인증기)만 사용, 다른 기기로 유도 안 함
    },
  });

  pendingChallenges.set("reg:" + user.id, { challenge: options.challenge, createdAt: Date.now() });

  const regToken = newToken();
  pendingSessions.set(regToken, { userId: user.id, createdAt: Date.now() });

  res.json({ ...options, regToken });
});

// ---- 등록: 2) 응답 검증 -----------------------------------------------
app.post("/api/register/verify", async (req, res) => {
  const { attResp, nickname, regToken } = req.body;
  const pendingSession = regToken && pendingSessions.get(regToken);
  if (!pendingSession) return res.status(400).json({ error: "등록 세션이 없습니다." });
  const userId = pendingSession.userId;

  const pending = pendingChallenges.get("reg:" + userId);
  if (!pending) return res.status(400).json({ error: "만료되었거나 없는 challenge입니다." });

  const db = loadDB();
  const user = db.users[userId];
  if (!user) return res.status(400).json({ error: "사용자를 찾을 수 없습니다." });

  try {
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: "검증 실패" });
    }

    const info = verification.registrationInfo;
    // @simplewebauthn/server 버전에 따라 registrationInfo의 필드 이름이 다르다.
    // 신버전: info.credential.{id, publicKey, counter}
    // 구버전: info.credentialID / info.credentialPublicKey / info.counter
    const cred = info.credential ?? {
      id: Buffer.from(info.credentialID).toString("base64url"),
      publicKey: info.credentialPublicKey,
      counter: info.counter,
    };

    user.credentials.push({
      credentialID: cred.id,
      publicKey: Buffer.from(cred.publicKey).toString("base64"),
      counter: cred.counter,
      transports: attResp.response?.transports || [],
      name: nickname || `패스키 ${user.credentials.length + 1}`,
      createdAt: new Date().toISOString(),
    });
    saveDB(db);
    pendingChallenges.delete("reg:" + userId);
    pendingSessions.delete(regToken);
    seedPrivateContent(user.id, user.username);

    res.json({ verified: true });
  } catch (e) {
    console.error("register/verify 오류:", e);
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
    allowCredentials: user.credentials.map((c) => ({
      id: c.credentialID,
      type: "public-key",
      transports: c.transports && c.transports.length ? c.transports : undefined,
    })),
  });

  pendingChallenges.set("auth:" + user.id, { challenge: options.challenge, createdAt: Date.now() });

  const loginToken = newToken();
  pendingSessions.set(loginToken, { userId: user.id, createdAt: Date.now() });

  res.json({ ...options, loginToken });
});

// ---- 로그인: 2) 응답 검증 -----------------------------------------------
app.post("/api/login/verify", async (req, res) => {
  const { authResp, loginToken } = req.body;
  const pendingSession = loginToken && pendingSessions.get(loginToken);
  if (!pendingSession) return res.status(400).json({ error: "로그인 세션이 없습니다." });
  const userId = pendingSession.userId;

  const pending = pendingChallenges.get("auth:" + userId);
  if (!pending) return res.status(400).json({ error: "만료되었거나 없는 challenge입니다." });

  if (usedChallenges.has(pending.challenge)) {
    return res.status(400).json({ error: "이미 사용된 challenge입니다." });
  }

  const db = loadDB();
  const user = db.users[userId];
  const credId = authResp.id;
  const cred = user.credentials.find((c) => c.credentialID === credId);
  if (!cred) return res.status(400).json({ error: "등록되지 않은 패스키입니다." });

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      // 버전에 따라 신버전은 credential, 구버전은 authenticator 파라미터를 쓴다.
      // 둘 다 넘겨두면 설치된 버전이 필요한 쪽만 읽고 나머지는 무시한다.
      credential: {
        id: cred.credentialID,
        publicKey: Buffer.from(cred.publicKey, "base64"),
        counter: cred.counter,
      },
      authenticator: {
        credentialID: Buffer.from(cred.credentialID, "base64url"),
        credentialPublicKey: Buffer.from(cred.publicKey, "base64"),
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
    pendingSessions.delete(loginToken);

    const sessionToken = newToken();
    authSessions.set(sessionToken, { userId: user.id, username: user.username, createdAt: Date.now() });

    res.json({ verified: true, username: user.username, sessionToken });
  } catch (e) {
    console.error("login/verify 오류:", e);
    res.status(400).json({ error: String(e) });
  }
});

// ---- 로그아웃 ----------------------------------------------------------
app.post("/api/logout", (req, res) => {
  const token = getBearerToken(req);
  if (token) authSessions.delete(token);
  res.json({ ok: true });
});

// ---- 내 패스키 목록 / 삭제 -----------------------------------------------
app.get("/api/passkeys", requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users[req.userId];
  res.json(user.credentials.map((c) => ({ id: c.credentialID, name: c.name, createdAt: c.createdAt })));
});

app.delete("/api/passkeys/:credentialID", requireAuth, (req, res) => {
  const db = loadDB();
  const user = db.users[req.userId];
  const before = user.credentials.length;
  user.credentials = user.credentials.filter((c) => c.credentialID !== req.params.credentialID);
  saveDB(db);
  if (user.credentials.length === before) return res.status(404).json({ error: "없음" });
  if (user.credentials.length === 0) {
    return res.json({ ok: true, warning: "마지막 패스키를 삭제했습니다. 더 이상 이 계정으로 로그인할 수 없습니다." });
  }
  res.json({ ok: true });
});

// ---- 비공개 자료 -----------------------------------------------------
app.get("/api/private", requireAuth, (req, res) => {
  const items = PRIVATE_CONTENT[req.userId] || [];
  res.json({ username: req.username, items });
});

app.get("/api/me", (req, res) => {
  const token = getBearerToken(req);
  const session = token && authSessions.get(token);
  res.json({ loggedIn: !!session, username: session?.username || null });
});

// 디버그용: 프론트 라이브러리 버전을 서버와 정확히 맞추기 위해 실제 설치된 버전을 확인
app.get("/api/debug/version", (req, res) => {
  try {
    const pkgPath = path.join(__dirname, "node_modules", "@simplewebauthn", "server", "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    res.json({ "@simplewebauthn/server": pkg.version });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.listen(PORT, () => console.log(`listening on ${PORT}`));
