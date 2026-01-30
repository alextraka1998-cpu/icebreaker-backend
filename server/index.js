import express from "express";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: [
    "https://icebreakerparty.com",
    "https://www.icebreakerparty.com"
  ],
  credentials: true
}));

app.use(express.json());

app.post("/api/login", (req, res) => {
  const { username, pin } = req.body;

  console.log("LOGIN ATTEMPT:", username, pin);

  if (!username || !pin) {
    return res.status(400).json({ error: "Missing data" });
  }

  if (!/^\d{4}$/.test(pin)) {
    return res.status(401).json({ error: "Invalid PIN" });
  }

  return res.json({
    success: true,
    user: { username }
  });
});

app.get("/api/ping", (req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Icebreaker escuchando en puerto ${PORT}`);
});
