import { assertEquals, assertMatch, assertNotEquals } from "@std/assert";
import { hmac, presign, sha256 } from "../main.ts";
import vectors from "./wycheproof_hmac.json" with { type: "json" };

const s16_b = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (Z) => parseInt(Z, 16));
Deno.test(async function nist_sha256() {
  const path = import.meta.url.slice(7, -8);
  const nist_short = await Deno.readTextFile(path + "/nist_short.txt");
  const nist_long = await Deno.readTextFile(path + "/nist_long.txt");
  const nist = nist_short + nist_long;
  for (const step of nist.matchAll(/Len = (\d+)\s+Msg = (\S+)\s+MD = (\S+)/g)) {
    const [step1, step2] = [step[2].slice(0, +step[1] << 1), step[3]].map((Z) =>
      Uint8Array.from(Z.match(/[\da-f]{2}/g) ?? [], (Z) => parseInt(Z, 16))
    );
    assertEquals(sha256(step1), step2);
  }
});
Deno.test(function hmac_vectors() {
  for (let z = 0; z < vectors.testGroups.length; ++z) {
    const a = vectors.testGroups[z];
    const b = new Uint8Array(a.keySize / 8);
    const c = new Uint8Array(a.tagSize / 8);
    const d = new Uint8Array(a.tagSize / 8);
    for (let y = 0; y < a.tests.length; ++y) {
      const e = a.tests[y];
      b.set(s16_b(e.key).subarray(0, b.length));
      c.set(s16_b(e.tag).subarray(0, c.length));
      d.set(hmac(b, s16_b(e.msg)).subarray(0, d.length));
      if (e.result === "valid") assertEquals(c, d, `${e.tcId}`);
      else assertNotEquals(c, d, `${e.tcId}`);
    }
  }
});

Deno.test(function presign_example() {
  const S3 = {
    S3_HOST: "https://examplebucket.s3.amazonaws.com",
    S3_ID: "AKIAIOSFODNN7EXAMPLE",
    S3_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  };
  assertEquals(
    presign(
      S3,
      "test.txt",
      "GET",
      {},
      86400,
      "us-east-1",
      new Date("Fri, 24 May 2013 00:00:00 GMT"),
    ),
    "examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
  );
  assertMatch(
    presign(S3, "", "PUT", { "content-type": "text/plain" }),
    /X-Amz-SignedHeaders=content-type%3Bhost/,
  );
});
