import Fastify from "fastify";
import crypto from "crypto";
import fetch from "node-fetch";

// --- ENV VARS ---
const APP_SECRET = process.env.APP_SECRET;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const WHATSAPP_NUMBER_ID = process.env.WHATSAPP_NUMBER_ID;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;

// --- FASTIFY INSTANCE ---
const fastify = Fastify({
  logger: true,
  // disable request logging untuk serverless
  disableRequestLogging: true,
});

fastify.listen({ port: 3000 }, (err, address) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log(`Server running at ${address}`);
});

// --- ROUTES ---
fastify.get("/api/webhook", async (req, reply) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return reply.code(200).send(challenge);
  }
  return reply.code(403).send("Forbidden");
});

fastify.post("/api/webhook", async (req, reply) => {
  const signature = req.headers["x-hub-signature-256"];
  const bodyRaw = JSON.stringify(req.body || {});

  const hash = `sha256=${crypto
    .createHmac("sha256", APP_SECRET)
    .update(bodyRaw)
    .digest("hex")}`;

  if (signature !== hash) {
    return reply.code(401).send("Invalid signature");
  }

  const entries = req.body.entry || [];
  for (const entry of entries) {
    for (const change of entry.changes || []) {
      if (change.field === "messages") {
        const messages = change.value?.messages || [];
        for (const message of messages) {
          const from = message.from;
          const text = message.text?.body || "";

          console.log("Pesan masuk:", from, text);

          // Kirim balasan otomatis
          try {
            await fetch(`https://graph.facebook.com/v24.0/${WHATSAPP_NUMBER_ID}/messages`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${ACCESS_TOKEN}`,
              },
              body: JSON.stringify({
                messaging_product: "whatsapp",
                to: from,
                type: "text",
                text: { body: `Halo, kami terima pesanmu: "${text}"` },
              }),
            });
          } catch (err) {
            console.error("Gagal kirim balasan:", err);
          }
        }
      }
    }
  }

  return reply.code(200).send("EVENT_RECEIVED");
});

// --- VERCEL SERVERLESS HANDLER ---
export default async function handler(req, res) {
  await fastify.ready();
  fastify.server.emit("request", req, res);
}
