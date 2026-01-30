import express from "express";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;

// Fix ES Modules paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// PUBLIC is one level above /server
const publicPath = path.resolve(__dirname, "../public");

// Serve frontend
app.use(express.static(publicPath));

// Catch-all for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Icebreaker escuchando en puerto ${PORT}`);
});