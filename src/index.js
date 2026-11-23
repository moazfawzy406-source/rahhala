// حلقة — class hub worker: JSON API + static PWA assets
const enc = new TextEncoder();
const b2h = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const h2b = (hex) => new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
const uid = () => crypto.randomUUID().replaceAll("-", "");

async function hashPass(pass, saltHex, iters = 100000) {
  const salt = saltHex ? h2b(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iters }, key, 256);
  return `${b2h(salt)}:${iters}:${b2h(bits)}`;
}
function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function verifyPass(pass, stored) {
  const [salt, iters] = stored.split(":");
  const calc = await hashPass(pass, salt, parseInt(iters));
  return ctEq(calc, stored);
}

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const err = (msg, status = 400) => json({ error: msg }, status);

const authCache = new Map();
const IDLE_MS = 2 * 3600 * 1000;
const textEnc = new TextEncoder();
async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey("raw", textEnc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, textEnc.encode(msg));
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, "0")).join("");
}
async function canReadAsset(env,u,key,kind) {
  if (!u || !u.approved || key === "source-archive") return false;
  if (kind === "file") {
    const av=await env.DB.prepare("SELECT id FROM users WHERE avatar_key=? AND approved=1").bind(key).first();
    if(av) return true;
  }
  const col=kind === "audio" ? "audio_key" : "file_key";
  const gate=(u.role === "owner" || u.role === "admin" || u.history_granted) ? null : u.created_at;
  const row=await env.DB.prepare(`SELECT m.id FROM messages m LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=? WHERE m.${col}=? AND m.deleted_at IS NULL AND h.message_id IS NULL ${gate ? "AND m.created_at>=?" : ""} LIMIT 1`).bind(...(gate ? [u.id,key,gate] : [u.id,key])).first();
  return !!row;
}
async function signKeys(env, keys, u, kind="file") {
  if(!env.FILE_SIG) throw new Error("Signing unavailable");
  const out={}; const exp=Math.floor(Date.now()/1000)+600;
  const list=[...new Set(keys.filter(k=>typeof k === "string" && k && k!=="source-archive"))];
  if(!u || !u.approved || !list.length) return out;
  if(list.length>80) {for(let i=0;i<list.length;i+=80) Object.assign(out,await signKeys(env,list.slice(i,i+80),u,kind));return out;}
  const ph=list.map(()=>"?").join(","),col=kind === "audio" ? "audio_key" : "file_key";
  const gate=(u.role === "owner" || u.role === "admin" || u.history_granted) ? null : u.created_at;
  const statements=[env.DB.prepare(`SELECT DISTINCT m.${col} AS key FROM messages m LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=? WHERE m.${col} IN (${ph}) AND m.deleted_at IS NULL AND h.message_id IS NULL ${gate ? "AND m.created_at>=?" : ""}`).bind(...(gate?[u.id,...list,gate]:[u.id,...list]))];
  if(kind === "file") statements.push(env.DB.prepare(`SELECT DISTINCT avatar_key AS key FROM users WHERE approved=1 AND avatar_key IN (${ph})`).bind(...list));
  const rows=await env.DB.batch(statements),allowed=new Set(rows.flatMap(r=>r.results.map(x=>x.key)));
  await Promise.all(list.filter(k=>allowed.has(k)).map(async k=>{
    const sig=await hmacHex(env.FILE_SIG,[kind,k,u.id,exp].join(":"));
    out[k]="?sig="+sig+"&exp="+exp+"&uid="+encodeURIComponent(u.id);
  }));
  return out;
}
async function checkToken(env,t,touch=true) {
  if(!t) return null;
  const row=await env.DB.prepare("SELECT k.last_seen ls,u.id,u.name,u.role,u.approved,u.created_at,u.history_granted,u.avatar_key,u.email,u.username,u.bio FROM tokens k JOIN users u ON u.id=k.user_id WHERE k.token=?").bind(t).first();
  if(!row || !row.approved) return null;
  const seen=row.ls ? Date.parse(String(row.ls).replace(" ","T")+"Z") : Date.now();
  if(!Number.isFinite(seen) || Date.now()-seen>=IDLE_MS) {
    await env.DB.prepare("DELETE FROM tokens WHERE token=?").bind(t).run(); return null;
  }
  if(!row.ls || (touch && Date.now()-seen>=30000)) await env.DB.prepare("UPDATE tokens SET last_seen=datetime('now') WHERE token=?").bind(t).run();
  delete row.ls; return row;
}
async function getUser(req,env) {
  const h=req.headers.get("authorization")||"";
  return h.startsWith("Bearer ") ? checkToken(env,h.slice(7),req.headers.get("x-session-passive")!=="1") : null;
}
async function assetAllowed(req,env,kind,key) {
  const q=new URL(req.url).searchParams;
  const raw=q.get("exp")||""; const exp=Number(raw); const now=Math.floor(Date.now()/1000);
  const uid=q.get("uid")||""; const sig=q.get("sig")||"";
  if(!env.FILE_SIG || !/^\d+$/.test(raw) || exp<=now || exp>now+600 || !/^[a-f0-9]{64}$/.test(sig)) return false;
  const expected=await hmacHex(env.FILE_SIG,[kind,key,uid,exp].join(":"));
  if(!ctEq(sig,expected)) return false;
  const u=await env.DB.prepare("SELECT id,role,approved,created_at,history_granted FROM users WHERE id=?").bind(uid).first();
  return canReadAsset(env,u,key,kind);
}
async function readUpload(req,max) {
  if(Number(req.headers.get("content-length")||0)>max) throw new Error("UPLOAD_SIZE");
  if(!req.body) return new ArrayBuffer(0);
  const reader=req.body.getReader(),chunks=[];let size=0;
  while(true) {const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max){await reader.cancel();throw new Error("UPLOAD_SIZE");}chunks.push(value);}
  const out=new Uint8Array(size);let offset=0;for(const c of chunks){out.set(c,offset);offset+=c.byteLength;}return out.buffer;
}
function sniffType(b) {
  if (b.length < 12) return null;
  if (b.length>=45 && [137,80,78,71,13,10,26,10].every((x,i)=>b[i]===x) && b[12]===73&&b[13]===72&&b[14]===68&&b[15]===82 && b.slice(-8,-4).every((x,i)=>x===[73,69,78,68][i])) return "image/png";
  if (b.length>=20 && b[0]===0xFF&&b[1]===0xD8&&b[2]===0xFF && b[b.length-2]===255&&b[b.length-1]===217) return "image/jpeg";
  if (b.length>=20 && ["GIF87a","GIF89a"].includes(new TextDecoder().decode(b.slice(0,6))) && b[b.length-1]===59) return "image/gif";
  if (b[0]===0x52&&b[1]===0x49&&b[2]===0x46&&b[3]===0x46&&b[8]===0x57&&b[9]===0x45&&b[10]===0x42&&b[11]===0x50) return "image/webp";
  if (new TextDecoder().decode(b.slice(0,8)).match(/^%PDF-[12]\.[0-9]/) && new TextDecoder().decode(b.slice(-1024)).includes("%%EOF")) return "application/pdf";
  if (b[0]===0x4F&&b[1]===0x67&&b[2]===0x67&&b[3]===0x53) return "audio/ogg";
  if (b[0]===0x1A&&b[1]===0x45&&b[2]===0xDF&&b[3]===0xA3) return "audio/webm";
  if (b[0]===0x49&&b[1]===0x44&&b[2]===0x33) return "audio/mpeg";
  if (b[0]===0xFF&&(b[1]&0xE0)===0xE0) return "audio/mpeg";
  if (b[4]===0x66&&b[5]===0x74&&b[6]===0x79&&b[7]===0x70) return "audio/mp4";
  if (b[0]===0x52&&b[1]===0x49&&b[2]===0x46&&b[3]===0x46&&b[8]===0x57&&b[9]===0x41&&b[10]===0x56&&b[11]===0x45) return "audio/wav";
  if (b[0]===0x50&&b[1]===0x4B&&b[2]===0x03&&b[3]===0x04) {
    const text=new TextDecoder().decode(b);
    if(text.includes("[Content_Types].xml") && ["word/","xl/","ppt/"].some(x=>text.includes(x))) return "application/zip";
  }
  return null;
}
async function sendResetEmail(env, to, name, code) {
  try {
    const html = `<div dir="rtl" style="font-family:system-ui,sans-serif;line-height:2;color:#222;max-width:420px;margin:auto"><h2 style="color:#b8912f;margin:0 0 8px">رَحّالَة</h2><p>أهلًا ${name || ""}،</p><p>رمز إعادة تعيين كلمة المرور بتاعك هو:</p><div style="font-size:32px;font-weight:800;letter-spacing:8px;text-align:center;background:#f6f1e3;border-radius:12px;padding:14px;direction:ltr">${code}</div><p style="color:#777;font-size:13px">الرمز صالح لمدة ١٠ دقائق وبيتستخدم مرة واحدة. لو مش انت اللي طلبته، تجاهل الإيميل ده.</p></div>`;
    const r = await fetch("https://api.smtp2go.com/v3/email/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        api_key: env.SMTP2GO_API_KEY,
        sender: (env.RESET_FROM_NAME || "رَحّالَة") + " <" + env.RESET_FROM + ">",
        to: [to],
        subject: "رمز إعادة تعيين كلمة المرور — رَحّالَة",
        html_body: html
      })
    });
    if (!r.ok) return false;
    const j = await r.json().catch(() => null);
    return !!(j && j.data && j.data.succeeded === 1);
  } catch (e) { return false; }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const p = url.pathname;
    const M = req.method;
    try {
      if (p === "/api/version") return json({ version: "v19 · 22-11-2026" });
      if (p === "/api/signup" && M === "POST") {
        const ip = req.headers.get("cf-connecting-ip") || "?";
        const ipAtt = await env.DB.prepare("SELECT * FROM login_attempts WHERE name=?").bind("ip:" + ip).first();
        if (ipAtt && ipAtt.fails >= 10) return err("محاولات كثيرة — جرب بعد شوية", 429);
        await env.DB.prepare("INSERT INTO login_attempts (name,fails) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET fails=fails+1").bind("ip:" + ip).run();
        const { name, password, email, username } = await req.json();
        if (!name || !password || name.trim().length < 2 || password.length < 6) return err("الاسم أو كلمة المرور غير صالحة");
        const em = (email || "").trim().toLowerCase().slice(0, 120);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return err("اكتب إيميل صحيح — هتحتاجه لو نسيت كلمة المرور");
        const un = (username || "").trim().toLowerCase();
        if (!un) return err("اسم المستخدم مطلوب — هتدخل بيه كل مرة");
        if (!/^[a-z0-9._]{3,30}$/.test(un)) return err("اسم المستخدم: حروف إنجليزية صغيرة وأرقام و . _ بس (من ٣ لـ ٣٠ حرف)");
        const takenU = await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(un).first();
        if (takenU) return err("اسم المستخدم ده محجوز — جرب غيره", 409);
        const exists = await env.DB.prepare("SELECT id FROM users WHERE name=?").bind(name.trim()).first();
        if (exists) return err("هذا الاسم مستخدم بالفعل", 409);
        await env.DB.prepare("INSERT INTO users (id,name,username,pass_hash,email) VALUES (?,?,?,?,?)").bind(uid(), name.trim(), un, await hashPass(password), em).run();
        return json({ pending: true });
      }
      if (p === "/api/login" && M === "POST") {
        const { name, password } = await req.json();
        const uname = (name || "").trim();
        const att = await env.DB.prepare("SELECT * FROM login_attempts WHERE name=?").bind(uname).first();
        if (att && att.locked_until && att.locked_until > new Date().toISOString().replace("T", " ").slice(0, 19))
          return err("محاولات كثيرة — جرب بعد ١٠ دقائق", 429);
        const u = await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(uname.toLowerCase()).first();
        if (!u || !(await verifyPass(password || "", u.pass_hash))) {
          const fails = (att ? att.fails : 0) + 1;
          const lock = fails >= 8 ? new Date(Date.now() + 600000).toISOString().replace("T", " ").slice(0, 19) : null;
          await env.DB.prepare("INSERT INTO login_attempts (name,fails,locked_until) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET fails=excluded.fails, locked_until=excluded.locked_until").bind(uname, fails >= 8 ? 0 : fails, lock).run();
          return err("بيانات الدخول غير صحيحة", 401);
        }
        await env.DB.prepare("DELETE FROM login_attempts WHERE name=?").bind(uname).run();
        if (!u.approved) return err("حسابك بانتظار موافقة المشرف", 403);
        const token = b2h(crypto.getRandomValues(new Uint8Array(32)));
        await env.DB.prepare("INSERT INTO tokens (token,user_id,user_agent,last_seen) VALUES (?,?,?,datetime('now'))").bind(token, u.id, (req.headers.get("user-agent") || "").slice(0, 200)).run();
        return json({ token, user: { id: u.id, name: u.name, role: u.role, username: u.username || null } });
      }
      if (p === "/api/logout" && M === "POST") {
        const h = req.headers.get("authorization") || "";
        const t = h.startsWith("Bearer ") ? h.slice(7) : "";
        if (t) { authCache.delete(t); await env.DB.prepare("DELETE FROM tokens WHERE token=?").bind(t).run(); }
        return json({ ok: true });
      }
      if (p === "/api/auth/forgot" && M === "POST") {
        const fip = req.headers.get("cf-connecting-ip") || "?";
        const fAtt = await env.DB.prepare("SELECT * FROM login_attempts WHERE name=?").bind("fip:" + fip).first();
        if (fAtt && fAtt.fails >= 10) return err("محاولات كثيرة — جرب بعد شوية", 429);
        await env.DB.prepare("INSERT INTO login_attempts (name,fails) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET fails=fails+1").bind("fip:" + fip).run();
        const { email } = await req.json().catch(() => ({}));
        const em = (email || "").trim().toLowerCase().slice(0, 120);
        const generic = () => json({ ok: true, message: "لو الإيميل ده مسجل عندنا، هيوصله رمز إعادة التعيين خلال دقيقة ✉️" });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return generic();
        if (!env.SMTP2GO_API_KEY || !env.RESET_FROM) return err("خدمة إعادة التعيين مش متفعلة لسه — كلم المشرف", 503);
        const fu = await env.DB.prepare("SELECT id,name FROM users WHERE email=? AND approved=1").bind(em).first();
        if (!fu) return generic();
        const nowD = new Date();
        const nowS = nowD.toISOString().replace("T", " ").slice(0, 19);
        const today = nowS.slice(0, 10);
        const ex = await env.DB.prepare("SELECT * FROM password_resets WHERE email=?").bind(em).first();
        if (ex && ex.created_at > new Date(nowD - 60000).toISOString().replace("T", " ").slice(0, 19)) return generic();
        const sentCount = ex && ex.sent_day === today ? ex.sent_count : 0;
        if (sentCount >= 5) return generic();
        const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, "0");
        const codeHash = b2h(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(em + ":" + code)));
        const exp = new Date(nowD.getTime() + 600000).toISOString().replace("T", " ").slice(0, 19);
        await env.DB.prepare("INSERT INTO password_resets (email,code_hash,expires_at,attempts,sent_day,sent_count,created_at) VALUES (?,?,?,0,?,?,datetime('now')) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0, sent_day=excluded.sent_day, sent_count=excluded.sent_count, created_at=excluded.created_at").bind(em, codeHash, exp, today, sentCount + 1).run();
        const sent = await sendResetEmail(env, em, fu.name, code);
        if (!sent) {
          await env.DB.prepare("DELETE FROM password_resets WHERE email=?").bind(em).run();
          return err("مش قادرين نبعت الإيميل دلوقتي — جرب تاني بعد شوية", 503);
        }
        return generic();
      }
      if (p === "/api/auth/reset" && M === "POST") {
        const { email, code, new_password } = await req.json().catch(() => ({}));
        const em = (email || "").trim().toLowerCase().slice(0, 120);
        if (!new_password || new_password.length < 6) return err("كلمة المرور الجديدة ٦ أحرف على الأقل");
        const bad = () => err("الرمز غلط أو انتهت صلاحيته — اطلب رمز جديد", 400);
        const row = await env.DB.prepare("SELECT * FROM password_resets WHERE email=?").bind(em).first();
        if (!row) return bad();
        const nowS = new Date().toISOString().replace("T", " ").slice(0, 19);
        if (row.expires_at < nowS || row.attempts >= 5) {
          await env.DB.prepare("DELETE FROM password_resets WHERE email=?").bind(em).run();
          return bad();
        }
        const codeHash = b2h(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(em + ":" + String(code || "").trim())));
        if (codeHash !== row.code_hash) {
          await env.DB.prepare("UPDATE password_resets SET attempts=attempts+1 WHERE email=?").bind(em).run();
          return bad();
        }
        const ru = await env.DB.prepare("SELECT id,name FROM users WHERE email=?").bind(em).first();
        if (!ru) return bad();
        await env.DB.prepare("UPDATE users SET pass_hash=? WHERE id=?").bind(await hashPass(new_password), ru.id).run();
        await env.DB.prepare("DELETE FROM password_resets WHERE email=?").bind(em).run();
        await env.DB.prepare("DELETE FROM tokens WHERE user_id=?").bind(ru.id).run();
        await env.DB.prepare("DELETE FROM login_attempts WHERE name=?").bind(ru.name).run();
        authCache.clear();
        const ntok = b2h(crypto.getRandomValues(new Uint8Array(32)));
        await env.DB.prepare("INSERT INTO tokens (token,user_id,user_agent,last_seen) VALUES (?,?,?,datetime('now'))").bind(ntok, ru.id, (req.headers.get("user-agent") || "").slice(0, 200)).run();
        const nu = await env.DB.prepare("SELECT id,name,role,username FROM users WHERE id=?").bind(ru.id).first();
        return json({ ok: true, token: ntok, user: { id: nu.id, name: nu.name, role: nu.role, username: nu.username || null } });
      }
      if (p === "/api/sessions" && M === "GET") {
        const su = await getUser(req, env);
        if (!su) return err("غير مسجل", 401);
        const curTok2 = (req.headers.get("authorization") || "").slice(7);
        const rows = (await env.DB.prepare("SELECT token, created_at, user_agent FROM tokens WHERE user_id=? ORDER BY created_at DESC LIMIT 20").bind(su.id).all()).results;
        return json({ sessions: rows.map(r => ({ id: r.token.slice(0, 8), current: r.token === curTok2, created_at: r.created_at, ua: r.user_agent || "" })) });
      }
      if (p === "/api/sessions/revoke" && M === "POST") {
        const su = await getUser(req, env);
        if (!su) return err("غير مسجل", 401);
        const { id, all_others } = await req.json().catch(() => ({}));
        const curTok3 = (req.headers.get("authorization") || "").slice(7);
        if (all_others) await env.DB.prepare("DELETE FROM tokens WHERE user_id=? AND token<>?").bind(su.id, curTok3).run();
        else if (id) await env.DB.prepare("DELETE FROM tokens WHERE user_id=? AND token LIKE ? AND token<>?").bind(su.id, id + "%", curTok3).run();
        return json({ ok: true });
      }
      if (p === "/api/me") {
        const u = await getUser(req, env);
        if (!u) return err("غير مسجل", 401);
        const hr = await env.DB.prepare("SELECT status FROM history_requests WHERE user_id=? ORDER BY id DESC LIMIT 1").bind(u.id).first();
        const histGranted = !!(u.history_granted || u.role === "owner" || u.role === "admin");
        const urlsMe = await signKeys(env, [u.avatar_key],u);
        return json({ user: u, urls: urlsMe, history: { granted: histGranted, req: hr ? hr.status : null } });
      }
      if (p.startsWith("/api/profile/") && M === "GET") {
        let pu = null;
        const auth0 = req.headers.get("authorization") || "";
        if (auth0.startsWith("Bearer ")) pu = await checkToken(env, auth0.slice(7),req.headers.get("x-session-passive")!=="1");
        if (!pu || !pu.approved) return err("غير مسجل", 401);
        const pid = p.split("/").pop();
        const prof = await env.DB.prepare("SELECT id,name,username,role,bio,email,avatar_key,created_at FROM users WHERE id=? AND approved=1").bind(pid).first();
        if (!prof) return err("العضو غير موجود", 404);
        if (prof.id !== pu.id) delete prof.email;
        const mc = await env.DB.prepare("SELECT COUNT(*) c FROM messages WHERE user_id=?").bind(pid).first();
        prof.msg_count = mc ? mc.c : 0;
        prof.has_avatar = !!prof.avatar_key;
        const urlsP = await signKeys(env, [prof.avatar_key],pu);
        return json({ profile: prof, urls: urlsP });
      }
      if (p === "/api/profile" && M === "POST") {
        const u0 = await getUser(req, env);
        if (!u0) return err("غير مسجل", 401);
        const { bio, avatar_key, remove_avatar, email, username, name } = await req.json();
        if (name !== undefined) {
          const nm = (name || "").trim().slice(0, 60);
          if (nm.length < 2) return err("الاسم قصير أوي");
          const takenN = await env.DB.prepare("SELECT id FROM users WHERE name=? AND id<>?").bind(nm, u0.id).first();
          if (takenN) return err("الاسم ده مستخدم بالفعل — اختار غيره", 409);
          await env.DB.prepare("UPDATE users SET name=? WHERE id=?").bind(nm, u0.id).run();
        }
        if (username !== undefined) {
          const un = (username || "").trim().toLowerCase();
          if (!un) {
            await env.DB.prepare("UPDATE users SET username=NULL WHERE id=?").bind(u0.id).run();
          } else {
            if (!/^[a-z0-9._]{3,30}$/.test(un)) return err("اسم المستخدم: حروف إنجليزية صغيرة وأرقام و . _ بس (من ٣ لـ ٣٠ حرف)");
            const takenU = await env.DB.prepare("SELECT id FROM users WHERE username=? AND id<>?").bind(un, u0.id).first();
            if (takenU) return err("اسم المستخدم ده محجوز — جرب غيره", 409);
            await env.DB.prepare("UPDATE users SET username=? WHERE id=?").bind(un, u0.id).run();
          }
        }
        if (email !== undefined) {
          const em = (email || "").trim().toLowerCase().slice(0, 120);
          if (em && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return err("الإيميل مش صحيح");
          await env.DB.prepare("UPDATE users SET email=? WHERE id=?").bind(em || null, u0.id).run();
        }
        if (bio !== undefined) {
          const b = (bio || "").trim().slice(0, 160);
          await env.DB.prepare("UPDATE users SET bio=? WHERE id=?").bind(b || null, u0.id).run();
        }
        if (avatar_key || remove_avatar) {
          const old0 = await env.DB.prepare("SELECT avatar_key FROM users WHERE id=?").bind(u0.id).first();
          const oldKey = old0 && old0.avatar_key;
          if (avatar_key) {
            const fm = await env.DB.prepare("SELECT key FROM file_meta WHERE key=?").bind(avatar_key).first();
            if (!fm) return err("الصورة غير موجودة");
            await env.DB.prepare("UPDATE users SET avatar_key=? WHERE id=?").bind(avatar_key, u0.id).run();
          } else {
            await env.DB.prepare("UPDATE users SET avatar_key=NULL WHERE id=?").bind(u0.id).run();
          }
          if (oldKey && oldKey !== avatar_key) {
            await env.DB.prepare("DELETE FROM file_chunks WHERE key=?").bind(oldKey).run();
            await env.DB.prepare("DELETE FROM file_meta WHERE key=?").bind(oldKey).run();
          }
        }
        return json({ ok: true });
      }
      if (p.startsWith("/api/file/") && M === "GET") {
        const key = p.split("/").pop();
        if(!(await assetAllowed(req,env,"file",key))) return err("رابط غير صالح أو منتهي",401);
        const meta = await env.DB.prepare("SELECT mime,size,name FROM file_meta WHERE key=?").bind(key).first();
        if (!meta) return err("غير موجود", 404);
        const rows = (await env.DB.prepare("SELECT data FROM file_chunks WHERE key=? ORDER BY seq").bind(key).all()).results;
        const parts = rows.map(r => r.data instanceof ArrayBuffer ? new Uint8Array(r.data) : new Uint8Array(r.data.buffer || r.data, r.data.byteOffset || 0, r.data.byteLength || r.data.length));
        const out = new Uint8Array(meta.size);
        let off = 0;
        for (const part of parts) { out.set(part, off); off += part.length; }
        const dlF = url.searchParams.get("dl") === "1";
        const mimeLow = (meta.mime || "").toLowerCase();
        const activeType = !["image/png","image/jpeg","image/gif","image/webp","audio/webm","audio/ogg","audio/mp4","audio/mpeg","audio/wav"].includes(mimeLow);
        const fres = new Response(out, { headers: { "content-type": meta.mime, "content-length": String(meta.size), "content-disposition": `${dlF || activeType ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(meta.name)}`, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
        return fres;
      }
      if (p.startsWith("/api/audio/") && M === "GET") {
        const key = p.split("/").pop();
        if(!(await assetAllowed(req,env,"audio",key))) return err("رابط غير صالح أو منتهي",401);
        const meta = await env.DB.prepare("SELECT mime,size FROM audio_meta WHERE key=?").bind(key).first();
        if (!meta) return err("غير موجود", 404);
        const rows = (await env.DB.prepare("SELECT data FROM audio_chunks WHERE key=? ORDER BY seq").bind(key).all()).results;
        const parts = rows.map(r => r.data instanceof ArrayBuffer ? new Uint8Array(r.data) : new Uint8Array(r.data.buffer || r.data, r.data.byteOffset || 0, r.data.byteLength || r.data.length));
        const out = new Uint8Array(meta.size);
        let off = 0;
        for (const part of parts) { out.set(part, off); off += part.length; }
        const dlA = url.searchParams.get("dl") === "1";
        const extA = (meta.mime || "").includes("ogg") ? "ogg" : (meta.mime || "").includes("mp4") ? "m4a" : (meta.mime || "").includes("mpeg") ? "mp3" : "webm";
        const dispA = (dlA || !["audio/webm","audio/ogg","audio/mp4","audio/mpeg","audio/wav"].includes(meta.mime)) ? `attachment; filename*=UTF-8''${encodeURIComponent("تسجيل-صوتي." + extA)}` : "inline";
        const ares = new Response(out, { headers: { "content-type": meta.mime, "content-length": String(meta.size), "content-disposition": dispA, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
        return ares;
      }
      if (p === "/api/profile/password" && M === "POST") {
        const u0 = await getUser(req, env);
        if (!u0) return err("غير مسجل", 401);
        const { current_password, new_password } = await req.json().catch(() => ({}));
        if (!new_password || new_password.length < 6) return err("كلمة المرور الجديدة ٦ أحرف على الأقل");
        const row = await env.DB.prepare("SELECT pass_hash FROM users WHERE id=?").bind(u0.id).first();
        if (!row || !(await verifyPass(current_password || "", row.pass_hash))) return err("كلمة المرور الحالية غلط", 401);
        await env.DB.prepare("UPDATE users SET pass_hash=? WHERE id=?").bind(await hashPass(new_password), u0.id).run();
        const curTok = (req.headers.get("authorization") || "").slice(7);
        await env.DB.prepare("DELETE FROM tokens WHERE user_id=? AND token<>?").bind(u0.id, curTok).run();
        return json({ ok: true });
      }
      if (p.startsWith("/api/")) {
        const u = await getUser(req, env);
        if (!u) return err("غير مسجل", 401);
        if (!u.approved) return err("بانتظار الموافقة", 403);
        const owner = u.role === "owner";
        const admin = u.role === "admin" || owner;

        if(p === "/api/asset-links" && M === "POST") {
          const {items}=await req.json();
          if(!Array.isArray(items)||items.length>100||items.some(x=>!x||!["file","audio"].includes(x.kind)||typeof x.key!=="string"||!x.key||x.key.length>128)) return err("طلب غير صالح");
          const files=items.filter(x=>x.kind==="file").map(x=>x.key);
          const audio=items.filter(x=>x.kind==="audio").map(x=>x.key);
          return json({urls:{...await signKeys(env,files,u),...await signKeys(env,audio,u,"audio")}});
        }
        if (p === "/api/admin/source.zip" && M === "GET") {
          if (!owner) return err("تحميل الكود للمالك فقط", 403);
          const meta = await env.DB.prepare("SELECT size FROM file_meta WHERE key='source-archive'").first();
          if (!meta) return err("الأرشيف غير مرفوع بعد", 404);
          const rows = (await env.DB.prepare("SELECT data FROM file_chunks WHERE key='source-archive' ORDER BY seq").all()).results;
          const parts = rows.map(r => r.data instanceof ArrayBuffer ? new Uint8Array(r.data) : new Uint8Array(r.data.buffer || r.data, r.data.byteOffset || 0, r.data.byteLength || r.data.length));
          const out = new Uint8Array(meta.size);
          let off = 0;
          for (const part of parts) { out.set(part, off); off += part.length; }
          return new Response(out, { headers: { "content-type": "application/zip", "content-length": String(meta.size), "content-disposition": 'attachment; filename="rahhala-source-v8-2026-11-22.zip"', "cache-control": "private, no-store" } });
        }

        if (p === "/api/bootstrap") {
          const bKey = new Request(url.origin + "/api/bootstrap");
          const hitB = await caches.default.match(bKey);
          if (hitB) { const h = new Headers(hitB.headers); h.delete("cache-control"); return new Response(hitB.body, { status: hitB.status, headers: h }); }
          const subjects = (await env.DB.prepare("SELECT * FROM subjects ORDER BY ord").all()).results;
          const sections = (await env.DB.prepare("SELECT * FROM sections ORDER BY ord").all()).results;
          const counts = (await env.DB.prepare("SELECT subject_id, COUNT(*) c FROM materials GROUP BY subject_id").all()).results;
          const lockB = await env.DB.prepare("SELECT value FROM settings WHERE key='chat_locked'").first();
          const bres = json({ subjects, sections, counts, chat_locked: !!(lockB && lockB.value === "1") });
          const bEdge = bres.clone(); bEdge.headers.set("cache-control", "max-age=30");
          ctx.waitUntil(caches.default.put(bKey, bEdge));
          return bres;
        }
        if (p === "/api/materials" && M === "GET") {
          const sid = url.searchParams.get("subject_id");
          const mKey = new Request(url.origin + "/api/materials?subject_id=" + encodeURIComponent(sid || ""));
          const hitM = await caches.default.match(mKey);
          if (hitM) { const h = new Headers(hitM.headers); h.delete("cache-control"); return new Response(hitM.body, { status: hitM.status, headers: h }); }
          const rows = (await env.DB.prepare("SELECT * FROM materials WHERE subject_id=? ORDER BY COALESCE(ord, 2147483647), created_at DESC").bind(sid).all()).results;
          const mres = json({ materials: rows });
          const mEdge = mres.clone(); mEdge.headers.set("cache-control", "max-age=30");
          ctx.waitUntil(caches.default.put(mKey, mEdge));
          return mres;
        }
        if (p === "/api/messages" && M === "GET") {
          const ch = url.searchParams.get("channel") || "general";
          const after = parseInt(url.searchParams.get("after_id") || "0");
          const gate = (u.role === "owner" || u.role === "admin" || u.history_granted) ? null : u.created_at;
          const [mainRes, editsRes, lockG, typingRes, memberCntRow, mineRes, hrq] = await env.DB.batch([
            env.DB.prepare(`SELECT m.*, r.name AS reply_name, r.user_id AS reply_user_id, u2.avatar_key AS sender_avatar, u2.role AS sender_role, r.created_at AS reply_created,
              CASE WHEN r.deleted_at IS NULL THEN r.body ELSE '' END AS reply_body,
              CASE WHEN r.deleted_at IS NULL THEN r.audio_key ELSE NULL END AS reply_audio,
              CASE WHEN r.id IS NULL OR r.deleted_at IS NOT NULL THEN 1 ELSE 0 END AS reply_deleted
              FROM messages m
              LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=?
              LEFT JOIN messages r ON r.id=m.reply_to
              LEFT JOIN users u2 ON u2.id=m.user_id
              WHERE m.channel=? AND m.id>? AND h.message_id IS NULL ${gate ? "AND m.created_at >= ?" : ""}
              ORDER BY m.id DESC LIMIT 50`).bind(...(gate ? [u.id, ch, after, gate] : [u.id, ch, after])),
            after > 0
              ? env.DB.prepare("SELECT id, body, edited_at FROM messages WHERE channel=? AND edited_at IS NOT NULL AND edited_at > datetime('now','-120 seconds') AND id<=?").bind(ch, after)
              : env.DB.prepare("SELECT id, body, edited_at FROM messages WHERE 1=0"),
            env.DB.prepare("SELECT value FROM settings WHERE key='chat_locked'"),
            env.DB.prepare("SELECT u.name FROM typing t JOIN users u ON u.id=t.user_id WHERE t.channel=? AND t.user_id<>? AND (strftime('%s','now') - strftime('%s',t.ts)) < 6 ORDER BY t.ts DESC LIMIT 3").bind(ch, u.id),
            env.DB.prepare("SELECT COUNT(*) c FROM users WHERE approved=1 AND id<>?").bind(u.id),
            env.DB.prepare("SELECT id FROM messages WHERE channel=? AND user_id=? AND deleted_at IS NULL ORDER BY id DESC LIMIT 40").bind(ch, u.id),
            env.DB.prepare("SELECT status FROM history_requests WHERE user_id=? ORDER BY id DESC LIMIT 1").bind(u.id),
          ]);
          const rows = mainRes.results;
          for (const row of rows) {
            if (row.deleted_at) { row.body = ""; row.audio_key = null; row.file_key = null; row.file_name = null; row.reactions = []; }
            if (gate && row.reply_to && (!row.reply_created || row.reply_created < gate)) { row.reply_deleted = 1; row.reply_body = ""; row.reply_audio = null; row.reply_name = ""; }
          }
          const msgs = rows.reverse();
          const edits = editsRes.results || [];
          const typing = (typingRes.results || []).map(r => r.name);
          const memberCnt = memberCntRow && memberCntRow.results && memberCntRow.results[0] ? memberCntRow.results[0].c : 0;
          const mine = (mineRes.results || []).map(r => r.id);
          const ids = msgs.map(m => m.id);
          const stmts2 = [];
          if (ids.length) {
            const ph = ids.map(() => "?").join(",");
            const lastId = msgs[msgs.length - 1].id;
            stmts2.push(env.DB.prepare(`SELECT message_id, emoji, COUNT(*) c, SUM(CASE WHEN user_id=? THEN 1 ELSE 0 END) mine FROM reactions WHERE message_id IN (${ph}) GROUP BY message_id, emoji`).bind(u.id, ...ids));
            stmts2.push(env.DB.prepare("INSERT INTO reads (user_id,channel,last_id) VALUES (?,?,?) ON CONFLICT(user_id,channel) DO UPDATE SET last_id=MAX(last_id, excluded.last_id)").bind(u.id, ch, lastId));
            stmts2.push(env.DB.prepare(`INSERT INTO receipts (message_id, user_id, delivered_at, read_at)
              SELECT id, ?, datetime('now'), datetime('now') FROM messages
              WHERE channel=? AND id<=? AND user_id<>? AND deleted_at IS NULL ORDER BY id DESC LIMIT 200
              ON CONFLICT(message_id, user_id) DO UPDATE SET delivered_at=COALESCE(receipts.delivered_at, datetime('now')), read_at=COALESCE(receipts.read_at, datetime('now'))`).bind(u.id, ch, lastId, u.id));
          }
          if (memberCnt > 0 && mine.length) {
            const mph = mine.map(() => "?").join(",");
            stmts2.push(env.DB.prepare(`SELECT message_id, COUNT(delivered_at) d, COUNT(read_at) r FROM receipts WHERE message_id IN (${mph}) GROUP BY message_id`).bind(...mine));
          }
          const res2 = stmts2.length ? await env.DB.batch(stmts2) : [];
          if (ids.length) {
            const rs = res2[0].results;
            const byMsg = {};
            for (const r of rs) { (byMsg[r.message_id] = byMsg[r.message_id] || []).push({ emoji: r.emoji, c: r.c, mine: r.mine > 0 }); }
            msgs.forEach(m => { if (!m.deleted_at) m.reactions = byMsg[m.id] || []; });
          }
          let ticks = {};
          if (memberCnt > 0 && mine.length) {
            const rec = res2[res2.length - 1].results;
            const rm = {}; for (const x of rec) rm[x.message_id] = x;
            for (const id of mine) { const x = rm[id]; ticks[id] = (x && x.r >= memberCnt) ? "read" : (x && x.d >= memberCnt) ? "delivered" : "sent"; }
          }
          const urlsM = {...await signKeys(env,msgs.flatMap(m=>[m.file_key,m.sender_avatar]),u), ...await signKeys(env,msgs.flatMap(m=>[m.audio_key,m.reply_audio]),u,"audio")};
          return json({ messages: msgs, urls: urlsM, edits, locked: !!(lockG && lockG.results && lockG.results[0] && lockG.results[0].value === "1"), typing, ticks, history: { gated: !!gate, req: hrq && hrq.results && hrq.results[0] ? hrq.results[0].status : null } });
        }
        if (p === "/api/messages/search" && M === "GET") {
          const ch = url.searchParams.get("channel") || "general";
          const q = (url.searchParams.get("q") || "").trim().slice(0, 80);
          if (q.length < 2) return json({ results: [] });
          const like = "%" + q.replace(/[%_]/g, "") + "%";
          const gateS = (u.role === "owner" || u.role === "admin" || u.history_granted) ? null : u.created_at;
          const rows = (await env.DB.prepare(`SELECT m.id, m.user_id, m.name, m.body, m.created_at FROM messages m LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=? WHERE m.channel=? AND m.deleted_at IS NULL AND h.message_id IS NULL AND m.body LIKE ? ${gateS ? "AND m.created_at >= ?" : ""} ORDER BY m.id DESC LIMIT 30`).bind(...(gateS ? [u.id, ch, like, gateS] : [u.id, ch, like])).all()).results;
          return json({ results: rows });
        }
        if (p === "/api/unread") {
          const gateU = (u.role === "owner" || u.role === "admin" || u.history_granted) ? null : u.created_at;
          const chans = ["announcements", "questions", "general"];
          const stmts = chans.map(c => env.DB.prepare(`SELECT COUNT(*) c FROM messages m LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=? WHERE m.channel=? AND m.user_id<>? AND m.deleted_at IS NULL AND h.message_id IS NULL AND m.id > COALESCE((SELECT last_id FROM reads WHERE user_id=? AND channel=?),0) ${gateU ? "AND m.created_at >= ?" : ""}`).bind(...(gateU ? [u.id, c, u.id, u.id, c, gateU] : [u.id, c, u.id, u.id, c])));
          const isAdminU = u.role === "owner" || u.role === "admin";
          if (isAdminU) {
            stmts.push(env.DB.prepare("SELECT COUNT(*) c FROM users WHERE approved=0"));
            stmts.push(env.DB.prepare("SELECT COUNT(*) c FROM history_requests WHERE status='pending'"));
          }
          const resU = await env.DB.batch(stmts);
          const unread = {};
          chans.forEach((c, i) => { unread[c] = resU[i].results[0] ? resU[i].results[0].c : 0; });
          const admin_pending = isAdminU ? ((resU[3].results[0] ? resU[3].results[0].c : 0) + (resU[4].results[0] ? resU[4].results[0].c : 0)) : 0;
          return json({ unread, admin_pending });
        }
        if (p === "/api/receipt" && M === "POST") {
          const { channel, up_to, kind } = await req.json();
          if (!["announcements", "questions", "general"].includes(channel)) return err("قناة غير معروفة");
          const upTo = Math.min(parseInt(up_to) || 0, 2147483647);
          if (!upTo) return json({ ok: true });
          const read = kind === "read";
          await env.DB.prepare(`INSERT INTO receipts (message_id, user_id, delivered_at, read_at)
            SELECT id, ?, datetime('now'), ${read ? "datetime('now')" : "NULL"} FROM messages
            WHERE channel=? AND id<=? AND user_id<>? AND deleted_at IS NULL ORDER BY id DESC LIMIT 200
            ON CONFLICT(message_id, user_id) DO UPDATE SET delivered_at=COALESCE(receipts.delivered_at, datetime('now'))${read ? ", read_at=COALESCE(receipts.read_at, datetime('now'))" : ""}`).bind(u.id, channel, upTo, u.id).run();
          if (read) await env.DB.prepare("INSERT INTO reads (user_id,channel,last_id) VALUES (?,?,?) ON CONFLICT(user_id,channel) DO UPDATE SET last_id=MAX(last_id, excluded.last_id)").bind(u.id, channel, upTo).run();
          return json({ ok: true });
        }
        if (p === "/api/message-info" && M === "GET") {
          const id = parseInt(url.searchParams.get("id") || "0");
          const m = await env.DB.prepare("SELECT * FROM messages WHERE id=?").bind(id).first();
          if (!m) return err("الرسالة غير موجودة", 404);
          if (m.user_id !== u.id && u.role !== "owner" && u.role !== "admin") return err("متاح لصاحب الرسالة فقط", 403);
          const read = (await env.DB.prepare("SELECT u2.name, r.read_at at FROM receipts r JOIN users u2 ON u2.id=r.user_id WHERE r.message_id=? AND r.read_at IS NOT NULL ORDER BY r.read_at").bind(id).all()).results;
          const delivered = (await env.DB.prepare("SELECT u2.name, r.delivered_at at FROM receipts r JOIN users u2 ON u2.id=r.user_id WHERE r.message_id=? AND r.delivered_at IS NOT NULL ORDER BY r.delivered_at").bind(id).all()).results;
          return json({ read, delivered });
        }
        if (p === "/api/messages/edit" && M === "POST") {
          const { id, body } = await req.json();
          const b = (body || "").trim();
          if (!b || b.length > 2000) return err("النص غير صالح");
          const m = await env.DB.prepare("SELECT * FROM messages WHERE id=?").bind(id).first();
          if (!m || m.deleted_at) return err("الرسالة غير موجودة", 404);
          if (m.user_id !== u.id) return err("تقدر تعدل رسايلك فقط", 403);
          await env.DB.prepare("UPDATE messages SET body=?, edited_at=datetime('now') WHERE id=?").bind(b, id).run();
          return json({ ok: true });
        }
        if (p === "/api/history-request" && M === "POST") {
          if (u.history_granted || u.role === "owner" || u.role === "admin") return err("عندك وصول كامل بالفعل");
          await env.DB.prepare("INSERT INTO history_requests (user_id, status, created_at) VALUES (?, 'pending', datetime('now')) ON CONFLICT(user_id) DO UPDATE SET status='pending', decided_by=NULL, decided_at=NULL, created_at=datetime('now')").bind(u.id).run();
          return json({ ok: true });
        }
        if (p === "/api/admin/history-requests" && admin) {
          const requests = (await env.DB.prepare("SELECT r.id, r.user_id, r.created_at, u2.name FROM history_requests r JOIN users u2 ON u2.id=r.user_id WHERE r.status='pending' ORDER BY r.id").all()).results;
          return json({ requests });
        }
        if (p === "/api/admin/history-decide" && admin && M === "POST") {
          const { id, approve } = await req.json();
          const rq = await env.DB.prepare("SELECT * FROM history_requests WHERE id=?").bind(id).first();
          if (!rq) return err("الطلب غير موجود", 404);
          const st = approve ? "approved" : "rejected";
          await env.DB.prepare("UPDATE history_requests SET status=?, decided_by=?, decided_at=datetime('now') WHERE id=?").bind(st, u.id, id).run();
          if (approve) await env.DB.prepare("UPDATE users SET history_granted=1 WHERE id=?").bind(rq.user_id).run();
          return json({ ok: true });
        }
        if (p === "/api/typing" && M === "POST") {
          const { channel } = await req.json();
          if (!["announcements", "questions", "general"].includes(channel)) return err("قناة غير معروفة");
          await env.DB.prepare("INSERT INTO typing (user_id,channel,ts) VALUES (?,?,datetime('now')) ON CONFLICT(user_id,channel) DO UPDATE SET ts=datetime('now')").bind(u.id, channel).run();
          return json({ ok: true });
        }
        if (p === "/api/members" && M === "GET") {
          const rows = (await env.DB.prepare("SELECT id,name,username,role,email,bio,created_at,avatar_key,(avatar_key IS NOT NULL) AS has_avatar FROM users WHERE approved=1 ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, name COLLATE NOCASE").all()).results;
          if (!admin) rows.forEach(r => delete r.email);
          const urlsMem = await signKeys(env, rows.map(r => r.avatar_key),u);
          return json({ members: rows, urls: urlsMem });
        }
        if (p === "/api/admin/members/email" && admin && M === "POST") {
          const { user_id, email } = await req.json();
          const em = (email || "").trim().toLowerCase().slice(0, 120);
          if (em && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return err("الإيميل مش صحيح");
          const tgt = await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(user_id).first();
          if (!tgt) return err("العضو غير موجود", 404);
          if (!owner && tgt.role !== "member") return err("تعديل إيميل مشرف للمالك فقط", 403);
          await env.DB.prepare("UPDATE users SET email=? WHERE id=?").bind(em || null, user_id).run();
          return json({ ok: true });
        }
        if (p === "/api/admin/members/password" && admin && M === "POST") {
          const { user_id, new_password } = await req.json().catch(() => ({}));
          if (!new_password || String(new_password).length < 6) return err("كلمة المرور المؤقتة ٦ أحرف على الأقل");
          if (String(new_password).length > 100) return err("كلمة المرور طويلة جدًا");
          const tgt = await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(user_id).first();
          if (!tgt) return err("العضو غير موجود", 404);
          if (tgt.role === "owner") return err("لا يمكن تغيير كلمة مرور المالك", 403);
          if (!owner && tgt.role !== "member") return err("تغيير كلمة مرور مشرف للمالك فقط", 403);
          await env.DB.prepare("UPDATE users SET pass_hash=? WHERE id=?").bind(await hashPass(String(new_password)), user_id).run();
          await env.DB.prepare("DELETE FROM tokens WHERE user_id=?").bind(user_id).run();
          return json({ ok: true });
        }
        if (p === "/api/media" && M === "GET") {
          const rows = (await env.DB.prepare(`SELECT m.id, m.file_key, m.name, m.created_at, m.channel FROM messages m LEFT JOIN message_hides h ON h.message_id=m.id AND h.user_id=? WHERE m.file_key IS NOT NULL AND m.deleted_at IS NULL AND h.message_id IS NULL ORDER BY m.id DESC LIMIT 60`).bind(u.id).all()).results;
          const urlsMed = await signKeys(env, rows.map(r => r.file_key),u);
          return json({ media: rows, urls: urlsMed });
        }
        if (p === "/api/messages/delete" && M === "POST") {
          const { id, scope } = await req.json();
          const m = await env.DB.prepare("SELECT * FROM messages WHERE id=?").bind(id).first();
          if (!m) return err("الرسالة غير موجودة", 404);
          if (scope === "all") {
            const own = m.user_id === u.id;
            if (own) {
              const ageOk = await env.DB.prepare("SELECT (strftime('%s','now') - strftime('%s', ?)) < 172800 AS ok").bind(m.created_at).first();
              if (!ageOk || !ageOk.ok) return err("انتهت مهلة الحذف عند الكل — المدة يومين زي واتساب", 403);
            } else if (!admin) return err("يمكنك حذف رسائلك فقط عند الكل", 403);
            await env.DB.prepare("UPDATE messages SET deleted_at=datetime('now'), deleted_by=? WHERE id=?").bind(u.id, id).run();
            await env.DB.prepare("DELETE FROM reactions WHERE message_id=?").bind(id).run();
            if (m.audio_key) {
              await env.DB.prepare("DELETE FROM audio_chunks WHERE key=?").bind(m.audio_key).run();
              await env.DB.prepare("DELETE FROM audio_meta WHERE key=?").bind(m.audio_key).run();
            }
            if (m.file_key) {
              await env.DB.prepare("DELETE FROM file_chunks WHERE key=?").bind(m.file_key).run();
              await env.DB.prepare("DELETE FROM file_meta WHERE key=?").bind(m.file_key).run();
            }
          } else if (scope === "silent") {
            if (u.role !== "owner") return err("الحذف الصامت متاح للمالك فقط", 403);
            await env.DB.prepare("DELETE FROM receipts WHERE message_id=?").bind(id).run();
            await env.DB.prepare("DELETE FROM reactions WHERE message_id=?").bind(id).run();
            await env.DB.prepare("DELETE FROM message_hides WHERE message_id=?").bind(id).run();
            if (m.audio_key) {
              await env.DB.prepare("DELETE FROM audio_chunks WHERE key=?").bind(m.audio_key).run();
              await env.DB.prepare("DELETE FROM audio_meta WHERE key=?").bind(m.audio_key).run();
            }
            if (m.file_key) {
              await env.DB.prepare("DELETE FROM file_chunks WHERE key=?").bind(m.file_key).run();
              await env.DB.prepare("DELETE FROM file_meta WHERE key=?").bind(m.file_key).run();
            }
            await env.DB.prepare("DELETE FROM messages WHERE id=?").bind(id).run();
          } else {
            await env.DB.prepare("INSERT OR IGNORE INTO message_hides (message_id,user_id) VALUES (?,?)").bind(id, u.id).run();
          }
          return json({ ok: true });
        }
        if (p === "/api/messages" && M === "POST") {
          const { channel, body, audio_key, reply_to, file_key, file_name } = await req.json();
          if ((!body || !body.trim()) && !audio_key && !file_key) return err("الرسالة فارغة");
          if (channel === "announcements" && !admin) return err("الإعلانات للمشرف فقط", 403);
          if (!["announcements", "questions", "general"].includes(channel)) return err("قناة غير معروفة");
          const lockP = await env.DB.prepare("SELECT value FROM settings WHERE key='chat_locked'").first();
          if (lockP && lockP.value === "1" && !admin) return err("المحادثة مقفولة حاليًا من الإدارة", 403);
          if (audio_key) {
            const a = await env.DB.prepare("SELECT key FROM audio_meta WHERE key=?").bind(audio_key).first();
            if (!a) return err("الملف الصوتي غير موجود");
          }
          if (reply_to) {
            const rm = await env.DB.prepare("SELECT id FROM messages WHERE id=? AND channel=?").bind(reply_to, channel).first();
            if (!rm) return err("الرسالة المردود عليها غير موجودة");
          }
          if (file_key) {
            const f = await env.DB.prepare("SELECT key FROM file_meta WHERE key=?").bind(file_key).first();
            if (!f) return err("الملف غير موجود");
          }
          await env.DB.prepare("DELETE FROM typing WHERE user_id=? AND channel=?").bind(u.id, channel).run();
          const ins = await env.DB.prepare("INSERT INTO messages (channel,user_id,name,body,audio_key,reply_to,file_key,file_name) VALUES (?,?,?,?,?,?,?,?)").bind(channel, u.id, u.name, (body || "").trim().slice(0, 2000), audio_key || null, reply_to || null, file_key || null, (file_name || "").slice(0, 120) || null).run();
          return json({ ok: true, id: ins.meta.last_row_id, created_at: new Date().toISOString().replace("T", " ").slice(0, 19) });
        }
        if (p === "/api/admin/pending" && admin) {
          const rows = (await env.DB.prepare("SELECT id,name,email,created_at FROM users WHERE approved=0 ORDER BY created_at").all()).results;
          return json({ pending: rows });
        }
        if (p === "/api/admin/decide" && admin && M === "POST") {
          const { user_id, approve } = await req.json();
          authCache.clear();
          if (approve) await env.DB.prepare("UPDATE users SET approved=1 WHERE id=?").bind(user_id).run();
          else {
            await env.DB.prepare("DELETE FROM tokens WHERE user_id=?").bind(user_id).run();
            await env.DB.prepare("DELETE FROM users WHERE id=?").bind(user_id).run();
          }
          return json({ ok: true });
        }
        const bustMats = (origin, sid) =>
          Promise.all([
            caches.default.delete(origin + "/api/bootstrap"),
            caches.default.delete(origin + "/api/materials?subject_id=" + encodeURIComponent(sid || "")),
          ]);
        if (p === "/api/admin/materials" && admin && M === "POST") {
          const { subject_id, section_id, title, kind, url: link, note } = await req.json();
          if (!subject_id || !title || !link) return err("بيانات ناقصة");
          if (!/^https?:\/\//i.test(link)) return err("الرابط لازم يبدأ بـ https://");
          const minOrd = (await env.DB.prepare("SELECT COALESCE(MIN(ord),0) m FROM materials WHERE subject_id=? AND section_id IS ?").bind(subject_id, section_id || null).first()).m;
          await env.DB.prepare("INSERT INTO materials (id,subject_id,section_id,title,kind,url,note,created_by,ord) VALUES (?,?,?,?,?,?,?,?,?)")
            .bind(uid(), subject_id, section_id || null, title, kind || "link", link, note || null, u.name, minOrd - 1).run();
          await bustMats(url.origin, subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/materials/update" && admin && M === "POST") {
          const { id, title, kind, url: link, note } = await req.json();
          if (!id || !title || !link) return err("بيانات ناقصة");
          if (!/^https?:\/\//i.test(link)) return err("الرابط لازم يبدأ بـ https://");
          const m = await env.DB.prepare("SELECT * FROM materials WHERE id=?").bind(id).first();
          if (!m) return err("المادة غير موجودة", 404);
          await env.DB.prepare("UPDATE materials SET title=?, url=?, note=?, kind=? WHERE id=?")
            .bind(title, link, note || null, kind || m.kind || "link", id).run();
          await bustMats(url.origin, m.subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/materials/move" && admin && M === "POST") {
          const { id, section_id } = await req.json();
          const m = await env.DB.prepare("SELECT * FROM materials WHERE id=?").bind(id).first();
          if (!m) return err("المادة غير موجودة", 404);
          const sec = await env.DB.prepare("SELECT id FROM sections WHERE id=? AND subject_id=?").bind(section_id, m.subject_id).first();
          if (!sec) return err("القسم غير موجود", 404);
          const maxOrd = (await env.DB.prepare("SELECT COALESCE(MAX(ord),-1) m FROM materials WHERE subject_id=? AND section_id IS ?").bind(m.subject_id, section_id).first()).m;
          await env.DB.prepare("UPDATE materials SET section_id=?, ord=? WHERE id=?").bind(section_id, maxOrd + 1, id).run();
          await bustMats(url.origin, m.subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/materials/reorder" && admin && M === "POST") {
          const { id, dir } = await req.json();
          const m = await env.DB.prepare("SELECT * FROM materials WHERE id=?").bind(id).first();
          if (!m) return err("المادة غير موجودة", 404);
          const rows = (await env.DB.prepare("SELECT id FROM materials WHERE subject_id=? AND section_id IS ? ORDER BY COALESCE(ord, 2147483647), created_at DESC").bind(m.subject_id, m.section_id).all()).results;
          const i = rows.findIndex(r => r.id === id);
          const j = i + (dir === -1 ? -1 : 1);
          if (i === -1 || j < 0 || j >= rows.length) return json({ ok: true });
          await env.DB.batch(rows.map((r, k) => env.DB.prepare("UPDATE materials SET ord=? WHERE id=?").bind(k, r.id)));
          await env.DB.batch([
            env.DB.prepare("UPDATE materials SET ord=? WHERE id=?").bind(j, rows[i].id),
            env.DB.prepare("UPDATE materials SET ord=? WHERE id=?").bind(i, rows[j].id),
          ]);
          await bustMats(url.origin, m.subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/materials/delete" && admin && M === "POST") {
          const { id } = await req.json();
          const m = await env.DB.prepare("SELECT subject_id FROM materials WHERE id=?").bind(id).first();
          await env.DB.prepare("DELETE FROM materials WHERE id=?").bind(id).run();
          if (m) await bustMats(url.origin, m.subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/subjects" && admin && M === "POST") {
          const { name, color, icon } = await req.json();
          const maxOrd = (await env.DB.prepare("SELECT COALESCE(MAX(ord),-1) m FROM subjects").first()).m;
          await env.DB.prepare("INSERT INTO subjects (id,name,color,icon,ord) VALUES (?,?,?,?,?)").bind(uid(), name, color || "#E3B23C", icon || "book", maxOrd + 1).run();
          await bustMats(url.origin, "");
          return json({ ok: true });
        }
        if (p === "/api/admin/sections" && admin && M === "POST") {
          const { subject_id, label } = await req.json();
          const maxOrd = (await env.DB.prepare("SELECT COALESCE(MAX(ord),-1) m FROM sections WHERE subject_id=?").bind(subject_id).first()).m;
          await env.DB.prepare("INSERT INTO sections (id,subject_id,label,ord) VALUES (?,?,?,?)").bind(uid(), subject_id, label, maxOrd + 1).run();
          await bustMats(url.origin, subject_id);
          return json({ ok: true });
        }
        if (p === "/api/admin/sections/delete" && admin && M === "POST") {
          const { id } = await req.json();
          const sec = await env.DB.prepare("SELECT subject_id FROM sections WHERE id=?").bind(id).first();
          await env.DB.prepare("DELETE FROM sections WHERE id=?").bind(id).run();
          await bustMats(url.origin, sec ? sec.subject_id : "");
          return json({ ok: true });
        }
        if (p === "/api/admin/subjects/delete" && admin && M === "POST") {
          const { id } = await req.json();
          await env.DB.prepare("DELETE FROM subjects WHERE id=?").bind(id).run();
          await env.DB.prepare("DELETE FROM sections WHERE subject_id=?").bind(id).run();
          await env.DB.prepare("DELETE FROM materials WHERE subject_id=?").bind(id).run();
          await bustMats(url.origin, id);
          return json({ ok: true });
        }
        if (p === "/api/audio" && M === "POST") {
          const buf = await readUpload(req, p === "/api/audio" ? 12000000 : 15000000);
          if (!buf.byteLength) return err("الملف فارغ");
          if (buf.byteLength > 12000000) return err("التسجيل طويل جدًا");
          const bytes0 = new Uint8Array(buf);
          const realA = sniffType(bytes0);
          if (!realA || !realA.startsWith("audio/")) return err("ملف الصوت غير صالح");
          const key = uid();
          const mime = realA;
          const bytes = bytes0;
          const CHUNK = 900000;
          const stmts = [];
          for (let i = 0; i < bytes.length; i += CHUNK) {
            stmts.push(env.DB.prepare("INSERT INTO audio_chunks (key,seq,data) VALUES (?,?,?)").bind(key, Math.floor(i / CHUNK), bytes.slice(i, i + CHUNK)));
          }
          stmts.push(env.DB.prepare("INSERT INTO audio_meta (key,mime,size) VALUES (?,?,?)").bind(key, mime, buf.byteLength));
          await env.DB.batch(stmts);
          return json({ key });
        }
        if (p === "/api/messages/react" && M === "POST") {
          const { id, emoji } = await req.json();
          const m = await env.DB.prepare("SELECT id FROM messages WHERE id=?").bind(id).first();
          if (!m) return err("الرسالة غير موجودة", 404);
          const cur = await env.DB.prepare("SELECT emoji FROM reactions WHERE message_id=? AND user_id=?").bind(id, u.id).first();
          if (!emoji || (cur && cur.emoji === emoji)) {
            await env.DB.prepare("DELETE FROM reactions WHERE message_id=? AND user_id=?").bind(id, u.id).run();
          } else {
            await env.DB.prepare("INSERT INTO reactions (message_id,user_id,emoji) VALUES (?,?,?) ON CONFLICT(message_id,user_id) DO UPDATE SET emoji=excluded.emoji").bind(id, u.id, String(emoji).slice(0, 16)).run();
          }
          return json({ ok: true });
        }
        if (p === "/api/file" && M === "POST") {
          const buf = await readUpload(req, p === "/api/audio" ? 12000000 : 15000000);
          if (!buf.byteLength) return err("الملف فارغ");
          if (buf.byteLength > 15000000) return err("الملف كبير — الحد الأقصى ١٥ ميجا");
          const bytesF = new Uint8Array(buf);
          const realF = sniffType(bytesF);
          const okF = realF && (realF.startsWith("image/") || realF === "application/pdf" || realF.startsWith("audio/") || realF === "application/zip");
          if (!okF) return err("نوع الملف غير مدعوم — المسموح: صور أو PDF أو صوت أو مستندات Office");
          const declared = (req.headers.get("content-type") || "application/octet-stream").split(";")[0];
          let mime = realF;


          const key = uid();
          let fname = "file";
          try { fname = decodeURIComponent(req.headers.get("x-file-name") || "file").slice(0, 120); } catch (e) {}
          const bytes = bytesF;
          const CHUNK = 900000;
          const stmts = [];
          for (let i = 0; i < bytes.length; i += CHUNK) {
            stmts.push(env.DB.prepare("INSERT INTO file_chunks (key,seq,data) VALUES (?,?,?)").bind(key, Math.floor(i / CHUNK), bytes.slice(i, i + CHUNK)));
          }
          stmts.push(env.DB.prepare("INSERT INTO file_meta (key,mime,size,name) VALUES (?,?,?,?)").bind(key, mime, buf.byteLength, fname));
          await env.DB.batch(stmts);
          return json({ key, name: fname, size: buf.byteLength });
        }
        if (p === "/api/admin/members" && admin) {
          const rows = (await env.DB.prepare("SELECT id,name,role,created_at,avatar_key,(avatar_key IS NOT NULL) AS has_avatar FROM users WHERE approved=1 ORDER BY created_at").all()).results;
          const urlsMem = await signKeys(env, rows.map(r => r.avatar_key),u);
          return json({ members: rows, urls: urlsMem });
        }
        if (p === "/api/admin/remove" && admin && M === "POST") {
          const { user_id } = await req.json();
          if (user_id === u.id) return err("لا يمكنك إزالة نفسك", 403);
          const target = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(user_id).first();
          if (!target) return err("العضو غير موجود", 404);
          if (target.role === "owner") return err("لا يمكن إزالة المالك", 403);
          if (!owner && target.role === "admin") return err("إزالة المشرفين للمالك فقط", 403);
          await env.DB.prepare("DELETE FROM tokens WHERE user_id=?").bind(user_id).run();
          await env.DB.prepare("DELETE FROM reads WHERE user_id=?").bind(user_id).run();
          await env.DB.prepare("DELETE FROM reactions WHERE user_id=?").bind(user_id).run();
          await env.DB.prepare("DELETE FROM message_hides WHERE user_id=?").bind(user_id).run();
          await env.DB.prepare("DELETE FROM login_attempts WHERE name=?").bind(target.name).run();
          if (target.avatar_key) {
            await env.DB.prepare("DELETE FROM file_chunks WHERE key=?").bind(target.avatar_key).run();
            await env.DB.prepare("DELETE FROM file_meta WHERE key=?").bind(target.avatar_key).run();
          }
          await env.DB.prepare("DELETE FROM users WHERE id=?").bind(user_id).run();
          authCache.clear();
          return json({ ok: true });
        }
        if (p === "/api/admin/chat-lock" && admin && M === "POST") {
          const { locked } = await req.json();
          await env.DB.prepare("INSERT INTO settings (key,value) VALUES ('chat_locked',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(locked ? "1" : "0").run();
          ctx.waitUntil(caches.default.delete(url.origin + "/api/bootstrap"));
          return json({ ok: true, locked: !!locked });
        }
        if (p === "/api/admin/role" && M === "POST") {
          if (!admin) return err("إدارة الأدوار للمشرفين والمالك", 403);
          const { user_id, role } = await req.json();
          if (!["admin", "member"].includes(role)) return err("دور غير معروف");
          if (user_id === u.id) return err("لا يمكنك تغيير دورك بنفسك");
          const target = await env.DB.prepare("SELECT role FROM users WHERE id=?").bind(user_id).first();
          if (!target) return err("العضو غير موجود", 404);
          if (target.role === "owner") return err("لا يمكن تغيير دور المالك", 403);
          await env.DB.prepare("UPDATE users SET role=? WHERE id=?").bind(role, user_id).run();
          authCache.clear();
          return json({ ok: true });
        }
        return err("مسار غير موجود", 404);
      }
      if(p.startsWith("/dl/")) {const u=await getUser(req,env);if(!u || u.role!=="owner") return err("تحميل الكود للمالك فقط",403);}
      return env.ASSETS.fetch(req);
    } catch (e) {
      if(e && e.message === "UPLOAD_SIZE") return err("حجم الملف أكبر من المسموح",413);
      return json({ error: "خطأ في الخادم" }, 500);
    }
  }
};
