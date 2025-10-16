import net from "net";
import crypto from "crypto";

const PORT = 4000;

function encryptRSA(publicKey: string, data: Buffer) {
  return crypto.publicEncrypt(publicKey, data);
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
  const client = net.connect(PORT, "127.0.0.1");
  const clientRandom = crypto.randomBytes(32);

  console.log("CLIENT_RANDOM:", clientRandom.toString("hex"));

  let sessionKey: Buffer;

  client.on("connect", () => {
    client.write(JSON.stringify({ type: "CLIENT_HELLO", random: clientRandom.toString("base64") }));
  });

  client.on("data", (d) => {
    const msg = JSON.parse(d.toString());

    if (msg.type === "SERVER_HELLO") {
      const serverRandom = Buffer.from(msg.random, "base64");

      console.log("SERVER_RANDOM:", serverRandom.toString("hex"));

      const publicKey = msg.publicKey as string;

      const premaster = crypto.randomBytes(48);

      console.log("PREMASTER (client generated):", premaster.toString("hex"));

      const encrypted = encryptRSA(publicKey, premaster);
      const keyBuffer = crypto.hkdfSync(
        "sha256",
        premaster,
        Buffer.concat([clientRandom, serverRandom]),
        Buffer.from("handshake"),
        32
      );
      sessionKey = Buffer.from(keyBuffer);

      console.log("SESSION_KEY (client):", sessionKey.toString("hex"));

      client.write(JSON.stringify({ type: "CLIENT_KEY_EXCHANGE", encrypted: encrypted.toString("base64") }));
    }

    else if (msg.type === "SERVER_READY") {
      const { enc, iv, tag } = msg;
      const text = aesDecrypt(sessionKey, Buffer.from(enc, "base64"), Buffer.from(iv, "base64"), Buffer.from(tag, "base64"));
      console.log("Handshake complete:", text);

      const { enc: e, iv: i, tag: t } = aesEncrypt(sessionKey, "Hello secure world!");
      client.write(JSON.stringify({ type: "APP_DATA", enc: e.toString("base64"), iv: i.toString("base64"), tag: t.toString("base64") }));
    }

    else if (msg.type === "APP_DATA") {
      const { enc, iv, tag } = msg;
      const text = aesDecrypt(sessionKey, Buffer.from(enc, "base64"), Buffer.from(iv, "base64"), Buffer.from(tag, "base64"));
      console.log("Received:", text);
      client.end();
    }
  });
}

main();
