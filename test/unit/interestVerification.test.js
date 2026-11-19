"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizeTesterEmail, isDisposableDomain, createToken, tokenId,
  enforceInterestLimits, createPendingVerification,
  getVerificationState, claimVerification, finishVerification,
} = require("../../lib/server/interestVerification");

// Minimal Firestore transaction fake; the production code only uses document
// transactions, so no external Firebase credentials or Resend calls are needed.
class MemoryDb {
  constructor() { this.docs = new Map(); }
  collection(name) {
    return { doc: (id) => this.ref(name + "/" + id) };
  }
  ref(path) {
    return {
      path,
      get: async () => this.snapshot(path),
      create: async (data) => {
        assert.equal(this.docs.has(path), false, "unique document");
        this.docs.set(path, { ...data });
      },
    };
  }
  snapshot(path) {
    const data = this.docs.get(path);
    return { exists: data !== undefined, data: () => ({ ...data }) };
  }
  async runTransaction(fn) {
    const writes = [];
    const tx = {
      get: async (ref) => this.snapshot(ref.path),
      set: (ref, value) => writes.push({ ref, value, mode: "set" }),
      update: (ref, value) => writes.push({ ref, value, mode: "update" }),
    };
    const result = await fn(tx);
    for (const { ref, value, mode } of writes) {
      if (mode === "update") assert.ok(this.docs.has(ref.path));
      this.docs.set(ref.path, { ...(mode === "update" ? this.docs.get(ref.path) : {}), ...value });
    }
    return result;
  }
}

test("rejects known disposable inboxes and their subdomains", () => {
  for (const email of [
    "yener95415@anonmart.com", "test@mailinator.com", "person@sub.yopmail.com",
    "x@tempmail.com", "x@guerrillamail.org",
  ]) assert.equal(normalizeTesterEmail(email).error, "disposable", email);
  assert.equal(isDisposableDomain("private.fake.test", "fake.test"), true);
  assert.equal(normalizeTesterEmail("x@throwaway.example", "throwaway.example").error, "disposable");
});

test("accepts normal mail and rejects malformed addresses without blocking legitimate providers", () => {
  assert.deepEqual(normalizeTesterEmail("  Tester@Gmail.com  "), { email: "Tester@gmail.com" });
  assert.deepEqual(normalizeTesterEmail("foo@seznam.cz"), { email: "foo@seznam.cz" });
  for (const email of ["", "a@", "a@@gmail.com", "a@bad", "a@-invalid.cz", "a@example..com", "x".repeat(65) + "@gmail.com"]) {
    assert.equal(normalizeTesterEmail(email).error, "invalid");
  }
  assert.equal(isDisposableDomain("notmailinator.com"), false);
});

test("verification token is unpredictable, bounded and invalid strings cannot be used as Firestore IDs", () => {
  const a = createToken();
  const b = createToken();
  assert.equal(a.length, 43);
  assert.notEqual(a, b);
  assert.match(tokenId(a), /^[0-9a-f]{64}$/);
  assert.equal(tokenId("../../../users/123"), null);
  assert.equal(tokenId("<img>"), null);
  assert.equal(tokenId("a".repeat(200)), null);
});

test("distributed rate limiting enforces five per IP and three per email", async () => {
  const db = new MemoryDb();
  const t = 1795100000000;
  for (let i = 0; i < 5; i++) {
    assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.1", "member" + i + "@gmail.com", t), true);
  }
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.1", "another@gmail.com", t), false);
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.2", "another@gmail.com", t), true);
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.3", "another@gmail.com", t), true);
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.4", "another@gmail.com", t), true);
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.5", "another@gmail.com", t), false);
  assert.equal(await enforceInterestLimits(db, "secret", "192.0.2.1", "new@gmail.com", t + 24 * 60 * 60 * 1000), true);
  assert.ok([...db.docs.keys()].every((key) => !key.includes("192.0.2.") && !key.includes("@gmail.com")));
});

test("GET-style status never consumes a link; POST claims only once", async () => {
  const db = new MemoryDb();
  const token = createToken(), t = 1795100000000;
  await createPendingVerification(db, "tester@gmail.com", token, t);
  assert.equal(await getVerificationState(db, token, t + 100), "ready");
  assert.equal(await getVerificationState(db, token, t + 200), "ready");
  const claim = await claimVerification(db, token, t + 250);
  assert.equal(claim.state, "send");
  assert.equal(claim.email, "tester@gmail.com");
  assert.equal((await claimVerification(db, token, t + 300)).state, "sending");
  await finishVerification(db, claim.id, claim.claim, true);
  assert.equal(await getVerificationState(db, token, t + 400), "notified");
  assert.equal((await claimVerification(db, token, t + 500)).state, "notified");
});

test("expired links fail closed; temporary notification failure can be retried", async () => {
  const db = new MemoryDb(), t = 1795100000000;
  const expired = createToken();
  await createPendingVerification(db, "expired@example.org", expired, t);
  assert.equal((await claimVerification(db, expired, t + 24 * 60 * 60 * 1000 + 1)).state, "expired");

  const retry = createToken();
  await createPendingVerification(db, "retry@gmail.com", retry, t);
  const first = await claimVerification(db, retry, t + 100);
  await finishVerification(db, first.id, first.claim, false);
  assert.equal(await getVerificationState(db, retry, t + 200), "ready");
  assert.equal((await claimVerification(db, retry, t + 300)).state, "send");
  assert.equal((await claimVerification(db, "wrong", t + 300)).state, "invalid");
});
