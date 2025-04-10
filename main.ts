const IV = /* @__PURE__ */ Uint32Array.from(
  /* @__PURE__ */ "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f26a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
    .match(/.{8}/g)!,
  (Z) => parseInt(Z, 16),
);
/** SHA-256 block function. */
const mix = (use: Uint32Array, from: DataView, at: number, to: Uint32Array) => {
  let a = to[1], b = to[2], c = to[3], d = to[4], e = to[5], f, g, z = 0;
  do use[z] = from.getUint32(at), at += 4; while (++z < 16);
  do f = use[z - 2],
    g = use[z - 15],
    use[z] = ((g >>> 7 | g << 25) ^ (g >>> 18 | g << 14) ^ g >>> 3) +
      ((f >>> 17 | f << 15) ^ (f >>> 19 | f << 13) ^ f >>> 10) +
      use[z - 7] + use[z - 16]; while (++z < 64);
  let h = to[z = 0], i = to[6], j = to[7];
  do f = ((d >>> 6 | d << 26) ^ (d >>> 11 | d << 21) ^ (d >>> 25 | d << 7)) +
    (d & e ^ ~d & i) + j + IV[z] + use[z],
    g = ((h >>> 2 | h << 30) ^ (h >>> 13 | h << 19) ^ (h >>> 22 | h << 10)) +
      (a & b ^ h & a ^ h & b),
    j = i,
    i = e,
    e = d,
    d = c + f | 0,
    c = b,
    b = a,
    a = h,
    h = f + g | 0; while (++z < 64);
  to[0] += h, to[1] += a, to[2] += b, to[3] += c;
  to[4] += d, to[5] += e, to[6] += i, to[7] += j;
};
/** Hashes with {@link https://w.wiki/KgC | SHA-256}. */
export const sha256 = (message: Uint8Array) => {
  const a = new Uint32Array(IV.subarray(64)), b = new Uint32Array(80);
  const c = new Uint8Array(64), d = message.length;
  let e = new DataView(message.buffer, message.byteOffset), z = 0, y = 0;
  while (z < d) {
    const f = Math.min(64 - y, d - z);
    if (f !== 64) c.set(message.subarray(z, z += f)), y += f;
    else do mix(b, e, z, a), z += 64; while (d - z >= 64);
  }
  e = new DataView(c.buffer), c[y] = 128, 64 - ++y < 8 && mix(b, e, y = 0, a);
  c.fill(0, y), e.setBigUint64(56, BigInt(d) << 3n), mix(b, e, y = 0, a);
  do e.setUint32(y << 2, a[y]); while (++y < 8);
  return new Uint8Array(c.subarray(0, 32));
};

const enum Pad {
  IPAD = 0x36,
  OPAD = 0x5c,
}
/** Creates a hash-based message authentication code. */
export const hmac = (key: Uint8Array, data: Uint8Array) => {
  if (key.length > 64) key = sha256(key);
  const a = key.length + 63 & ~63;
  const b = new Uint8Array(a + data.length).fill(Pad.IPAD);
  const c = new Uint8Array(a + 32).fill(Pad.OPAD);
  let z = a;
  do b[--z] ^= key[z], c[z] ^= key[z]; while (z);
  return b.set(data, a), c.set(sha256(b), a), sha256(c);
};

/** Encodes text to binary. */
const s_b: (string: string) => Uint8Array = /* @__PURE__ */ TextEncoder
  .prototype.encode.bind(/* @__PURE__ */ new TextEncoder());
const HEX = Array<string>(256);
for (let z = 0; z < 256; ++z) HEX[z] = z.toString(16).padStart(2, "0");
/** Encodes binary to base16. */
const b_s16 = (binary: Uint8Array) => {
  const to = Array<string>(binary.length);
  for (let z = 0; z < binary.length; ++z) to[z] = HEX[binary[z]];
  return to.join("");
};

/** Converts a date to S3's timestamp format. */
const iso = (date: Date) => date.toISOString().replace(/[-:]|\..../g, "");
const ESCAPE = /[^.\w~-]/g, S3 = s_b("s3"), AWS4_REQUEST = s_b("aws4_request");
/**
 * Creates a presigned URL for the specified path and operation.
 *
 * @param env Environment variables to calculate the signature.
 * @param path Relative path to the object.
 * @param method Method to be used for HTTP requests.
 * @param headers Header names and values to require on requests.
 * @param time Seconds before expiration, max 1 week.
 * @param date Earliest date this URL will be valid, only used in testing.
 * @returns Presigned S3 URL.
 */
export const presign = (
  env: { S3_HOST: string; S3_ID: string; S3_KEY: string },
  path: string,
  method: "PUT" | "GET" | "HEAD" = "PUT",
  headers: { [header: string]: string } = {},
  time = 604800,
  region = "auto",
  date = new Date(),
) => {
  const a = new URL(env.S3_HOST).hostname, b = iso(date), c = b.slice(0, 8);
  const d = Object.keys(headers), e: { [header: string]: string } = { host: a };
  for (let z = 0; z < d.length; ++z) e[d[z].toLowerCase()] = headers[d[z]];
  const f = `${c}/${region}/s3/aws4_request`, g = Object.keys(e).sort();
  const h = `X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${env.S3_ID}%2F${
    f.replace(ESCAPE, (a) => "%" + HEX[a.charCodeAt(0)].toUpperCase())
  }&X-Amz-Date=${b}&X-Amz-Expires=${time}&X-Amz-SignedHeaders=${g.join("%3B")}`;
  let i = `${method}\n/${path}\n${h}\n`;
  for (let z = 0; z < g.length; ++z) i += `${g[z]}:${e[g[z]]}\n`;
  return `${a}/${path}?${h}&X-Amz-Signature=` + b_s16(
    hmac(
      hmac(
        hmac(hmac(hmac(s_b(`AWS4${env.S3_KEY}`), s_b(c)), s_b(region)), S3),
        AWS4_REQUEST,
      ),
      s_b(
        `AWS4-HMAC-SHA256\n${b}\n${f}\n${
          b_s16(sha256(s_b(`${i}\n${g.join(";")}\nUNSIGNED-PAYLOAD`)))
        }`,
      ),
    ),
  );
};
