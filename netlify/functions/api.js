// Single Netlify function — handles ALL routes
// auth / results / users / leaderboard

const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "gmat_secret_change_me";

// ── DB ──────────────────────────────────────────────────────────────
function getDb() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL not set in Netlify environment variables.");
  return neon(process.env.DATABASE_URL);
}

// ── Response helpers ────────────────────────────────────────────────
const HEADERS = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
};
const ok  = (data, s = 200) => ({ statusCode: s, headers: HEADERS, body: JSON.stringify(data) });
const err = (msg,  s = 400) => ({ statusCode: s, headers: HEADERS, body: JSON.stringify({ error: msg }) });

// ── JWT ─────────────────────────────────────────────────────────────
function verifyToken(event) {
  const auth = event.headers.authorization || event.headers.Authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  try { return jwt.verify(auth.slice(7), JWT_SECRET); } catch { return null; }
}

// ── MAIN HANDLER ────────────────────────────────────────────────────
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: HEADERS, body: "" };

  // Route is passed via query param: ?route=auth / results / users / leaderboard
  const route = (event.queryStringParameters?.route || "").toLowerCase();
  const method = event.httpMethod;

  try {
    if (route === "auth")        return await handleAuth(event, method);
    if (route === "results")     return await handleResults(event, method);
    if (route === "users")       return await handleUsers(event, method);
    if (route === "leaderboard") return await handleLeaderboard(event);
    return err("Unknown route. Use ?route=auth|results|users|leaderboard", 404);
  } catch (e) {
    console.error("Function error:", e.message);
    return err(e.message || "Internal server error", 500);
  }
};

// ══════════════════════════════════════════════════════════════════════
// AUTH — login & register
// ══════════════════════════════════════════════════════════════════════
async function handleAuth(event, method) {
  if (method !== "POST") return err("POST only", 405);

  const body = JSON.parse(event.body || "{}");
  const { action, email, password, name } = body;

  if (!email || !password) return err("Email and password are required");

  const sql = getDb();

  // LOGIN
  if (action === "login") {
    const rows = await sql`
      SELECT id, name, email, password, role, join_date
      FROM users WHERE email = ${email.toLowerCase().trim()} LIMIT 1
    `;
    if (!rows.length) return err("Invalid email or password", 401);
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return err("Invalid email or password", 401);
    await sql`UPDATE users SET last_login = NOW() WHERE id = ${user.id}`;
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
    return ok({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, joinDate: user.join_date } });
  }

  // REGISTER
  if (action === "register") {
    if (!name || name.trim().length < 2) return err("Full name is required");
    const existing = await sql`SELECT id FROM users WHERE email = ${email.toLowerCase().trim()} LIMIT 1`;
    if (existing.length) return err("An account with this email already exists");
    const hashed = await bcrypt.hash(password, 10);
    const rows = await sql`
      INSERT INTO users (name, email, password, role)
      VALUES (${name.trim()}, ${email.toLowerCase().trim()}, ${hashed}, 'student')
      RETURNING id, name, email, role, join_date
    `;
    const user = rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
    return ok({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, joinDate: user.join_date } }, 201);
  }

  return err("action must be login or register");
}

// ══════════════════════════════════════════════════════════════════════
// RESULTS — save & fetch test results
// ══════════════════════════════════════════════════════════════════════
async function handleResults(event, method) {
  const user = verifyToken(event);
  if (!user) return err("Unauthorized. Please log in.", 401);
  const sql = getDb();

  if (method === "GET") {
    const allFlag = event.queryStringParameters?.all === "true";
    if (allFlag && user.role === "admin") {
      const rows = await sql`
        SELECT r.id, r.test_id, r.test_name, r.total_score, r.accuracy,
               r.time_taken, r.section_stats, r.completed_at,
               u.id AS user_id, u.name AS user_name, u.email AS user_email
        FROM test_results r JOIN users u ON u.id = r.user_id
        ORDER BY r.completed_at DESC LIMIT 500
      `;
      return ok(rows.map(fmtResult));
    }
    const rows = await sql`
      SELECT id, test_id, test_name, total_score, accuracy,
             time_taken, answers, section_stats, completed_at
      FROM test_results WHERE user_id = ${user.id}
      ORDER BY completed_at DESC
    `;
    return ok(rows.map(r => ({ ...fmtResult(r), userId: user.id, userName: user.name })));
  }

  if (method === "POST") {
    const b = JSON.parse(event.body || "{}");
    const { testId, testName, totalScore, accuracy, timeTaken, answers, sectionStats } = b;
    if (!testId || !testName || totalScore == null) return err("testId, testName, totalScore required");
    const rows = await sql`
      INSERT INTO test_results (user_id, test_id, test_name, total_score, accuracy, time_taken, answers, section_stats)
      VALUES (${user.id}, ${testId}, ${testName}, ${totalScore}, ${accuracy||0}, ${timeTaken||0},
              ${JSON.stringify(answers||{})}, ${JSON.stringify(sectionStats||{})})
      RETURNING id, test_id, test_name, total_score, accuracy, time_taken, completed_at
    `;
    return ok({ ...fmtResult(rows[0]), userId: user.id, userName: user.name }, 201);
  }

  return err("Method not allowed", 405);
}

function fmtResult(r) {
  return {
    id: r.id, testId: r.test_id, testName: r.test_name,
    totalScore: r.total_score, accuracy: r.accuracy, timeTaken: r.time_taken,
    sectionStats: r.section_stats, date: r.completed_at,
    userId: r.user_id, userName: r.user_name, userEmail: r.user_email,
  };
}

// ══════════════════════════════════════════════════════════════════════
// USERS — admin user management
// ══════════════════════════════════════════════════════════════════════
async function handleUsers(event, method) {
  const user = verifyToken(event);
  if (!user) return err("Unauthorized", 401);
  if (user.role !== "admin") return err("Admin only", 403);
  const sql = getDb();

  if (method === "GET") {
    const rows = await sql`SELECT id, name, email, role, join_date, last_login FROM users ORDER BY join_date DESC`;
    return ok(rows.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, joinDate: u.join_date, lastLogin: u.last_login })));
  }

  if (method === "POST") {
    const { name, email, password, role = "student" } = JSON.parse(event.body || "{}");
    if (!name || !email || !password) return err("name, email, password required");
    const existing = await sql`SELECT id FROM users WHERE email = ${email.toLowerCase()} LIMIT 1`;
    if (existing.length) return err("Email already in use");
    const hashed = await bcrypt.hash(password, 10);
    const rows = await sql`
      INSERT INTO users (name, email, password, role)
      VALUES (${name.trim()}, ${email.toLowerCase()}, ${hashed}, ${role})
      RETURNING id, name, email, role, join_date
    `;
    const u = rows[0];
    return ok({ id: u.id, name: u.name, email: u.email, role: u.role, joinDate: u.join_date }, 201);
  }

  if (method === "DELETE") {
    const userId = event.queryStringParameters?.id;
    if (!userId) return err("id param required");
    if (userId === user.id) return err("Cannot delete your own account");
    const target = await sql`SELECT role FROM users WHERE id = ${userId} LIMIT 1`;
    if (!target.length) return err("User not found", 404);
    if (target[0].role === "admin") return err("Cannot delete admin users");
    await sql`DELETE FROM users WHERE id = ${userId}`;
    return ok({ deleted: true });
  }

  return err("Method not allowed", 405);
}

// ══════════════════════════════════════════════════════════════════════
// LEADERBOARD — top 20 scores
// ══════════════════════════════════════════════════════════════════════
async function handleLeaderboard(event) {
  const user = verifyToken(event);
  if (!user) return err("Unauthorized", 401);
  const sql = getDb();
  const rows = await sql`
    SELECT DISTINCT ON (r.user_id) u.name, r.total_score, r.accuracy, r.test_name, r.completed_at
    FROM test_results r JOIN users u ON u.id = r.user_id
    ORDER BY r.user_id, r.total_score DESC
  `;
  const sorted = [...rows]
    .sort((a, b) => b.total_score - a.total_score)
    .slice(0, 20)
    .map((r, i) => ({ rank: i+1, name: r.name, score: r.total_score, accuracy: r.accuracy, testName: r.test_name, date: r.completed_at, isCurrentUser: r.name === user.name }));
  return ok(sorted);
}
