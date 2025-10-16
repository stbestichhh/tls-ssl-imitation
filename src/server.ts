import net from "net";
import crypto from "crypto";

const PORT = 4000;

function encryptRSA(publicKey: string, data: Buffer) {
  return crypto.publicEncrypt(publicKey, data);
}

function decryptRSA(privateKey: string, data: Buffer) {
  return crypto.privateDecrypt(privateKey, data);
}

function aesEncrypt(key: Buffer, text: string) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { enc, iv, tag };
}

function aesDecrypt(key: Buffer, enc: Buffer, iv: Buffer, tag: Buffer) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

async function main() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const server = net.createServer((socket) => {
    console.log("Client connected");
    let sessionKey: Buffer;
    let serverRandom: Buffer;
    let clientRandom: Buffer;

    socket.on("data", (d) => {
      const msg = JSON.parse(d.toString());

      if (msg.type === "CLIENT_HELLO") {
        clientRandom = Buffer.from(msg.random, "base64");
        serverRandom = crypto.randomBytes(32);

        console.log("CLIENT_RANDOM:", clientRandom.toString("hex"));
        console.log("SERVER_RANDOM:", serverRandom.toString("hex"));

        socket.write(JSON.stringify({
          type: "SERVER_HELLO",
          random: serverRandom.toString("base64"),
          publicKey,
        }));
      }

      else if (msg.type === "CLIENT_KEY_EXCHANGE") {
        const premaster = decryptRSA(privateKey, Buffer.from(msg.encrypted, "base64"));

        console.log("PREMASTER (server decrypted):", premaster.toString("hex"));

        const keyBuffer = crypto.hkdfSync(
          "sha256",
          premaster,
          Buffer.concat([clientRandom, serverRandom]),
          Buffer.from("handshake"),
          32
        );
        sessionKey = Buffer.from(keyBuffer);

        console.log("SESSION_KEY (server):", sessionKey.toString("hex"));

        const { enc, iv, tag } = aesEncrypt(sessionKey, "server ready");
        socket.write(JSON.stringify({ type: "SERVER_READY", enc: enc.toString("base64"), iv: iv.toString("base64"), tag: tag.toString("base64") }));
      }

      else if (msg.type === "APP_DATA") {
        const { enc, iv, tag } = msg;
        const text = aesDecrypt(sessionKey, Buffer.from(enc, "base64"), Buffer.from(iv, "base64"), Buffer.from(tag, "base64"));
        console.log("Received:", text);
        const { enc: e, iv: i, tag: t } = aesEncrypt(sessionKey, `Echo: ${text}`);
        socket.write(JSON.stringify({ type: "APP_DATA", enc: e.toString("base64"), iv: i.toString("base64"), tag: t.toString("base64") }));
      }
    });
  });

  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

main();
