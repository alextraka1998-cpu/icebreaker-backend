/**
 * Icebreaker server - Push notifications add-on (Android + iOS installed PWA)
 * Requires: npm i web-push
 *
 * Setup once:
 *  1) node -e "const webpush=require('web-push'); console.log(webpush.generateVAPIDKeys())"
 *  2) Put keys in VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY env vars (or paste below)
 */

const webpush = require("web-push");

// --- CONFIG: set your VAPID keys here OR via env ---
const VAPID_PUBLIC_KEY_RAW = process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY_RAW = process.env.VAPID_PRIVATE_KEY || "";

function cleanKey(s){
  return String(s||"")
    .trim()
    .replace(/^['"\s]+/, "")
    .replace(/[\s'",;]+$/g, "")
    .replace(/^publicKey:\s*/i, "")
    .replace(/^privateKey:\s*/i, "");
}

const VAPID_PUBLIC_KEY = cleanKey(VAPID_PUBLIC_KEY_RAW);
const VAPID_PRIVATE_KEY = cleanKey(VAPID_PRIVATE_KEY_RAW);
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || "mailto:dev@icebreaker.local";

// store subscriptions (simple file)
const path = require("path");
const fs = require("fs");
const SUBS_FILE = path.join(__dirname, "push_subs.json");

function readSubs(){
  try{ return JSON.parse(fs.readFileSync(SUBS_FILE, "utf-8")); }catch(e){ return {}; }
}
function writeSubs(x){
  try{ fs.writeFileSync(SUBS_FILE, JSON.stringify(x,null,2)); }catch(e){}
}

function initWebPush(){
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    console.log("⚠️  Push disabled: missing VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY");
    return false;
  }
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  console.log("✅ Push enabled");
  return true;
}

module.exports.attachPush = function attachPush(app, requireAuth, readUsers, writeUsers){
  const enabled = initWebPush();

  // Public config for client
  app.get("/api/push/config", (req,res)=>{
    res.json({ publicKey: VAPID_PUBLIC_KEY || null, enabled: !!enabled });
  });

  // Save subscription for logged-in user
  app.post("/api/push/subscribe", requireAuth, (req,res)=>{
    try{
      const sub = req.body && req.body.subscription;
      if (!sub || !sub.endpoint) return res.status(400).json({ error: "bad_sub" });
      const all = readSubs();
      all[String(req.user.id)] = sub;
      writeSubs(all);
      res.json({ ok:true });
    }catch(e){
      res.status(500).json({ error: "sub_failed" });
    }
  });

  // Helper to send push by userId
  async function pushTo(userId, payload){
    if (!enabled) return;
    const all = readSubs();
    const sub = all[String(userId)];
    if (!sub) return;
    try{
      await webpush.sendNotification(sub, JSON.stringify(payload));
    }catch(e){
      // remove dead subs
      if (e && (e.statusCode === 410 || e.statusCode === 404)) {
        delete all[String(userId)];
        writeSubs(all);
      }
    }
  }

  // Expose hook to your existing message/interaction code:
  return { pushTo };
};
