"use strict";

/**
 * Minimal in-memory Firestore fake for unit tests. Supports the subset of the
 * Admin SDK API used by the backend: documents, subcollections, simple
 * where/limit queries, serialised transactions, batches and the two
 * sentinels (serverTimestamp, increment) via fsHelpers override.
 */
const { overrideFirestoreHelpers } = require("../../lib/server/bacha/fsHelpers");

class FakeTimestamp {
  constructor(ms) {
    this._ms = ms;
    this.seconds = Math.floor(ms / 1000);
    this.nanoseconds = (ms % 1000) * 1e6;
  }
  toMillis() {
    return this._ms;
  }
}

const SERVER_TS = { __op: "serverTimestamp" };

function installFakeHelpers(clock = () => Date.now()) {
  overrideFirestoreHelpers({
    serverTimestamp: () => SERVER_TS,
    increment: (n) => ({ __op: "inc", n }),
    now: () => new FakeTimestamp(clock()),
    fromMillis: (ms) => new FakeTimestamp(ms),
  });
}

function cmp(a, b) {
  const av = a && typeof a.toMillis === "function" ? a.toMillis() : a;
  const bv = b && typeof b.toMillis === "function" ? b.toMillis() : b;
  return av < bv ? -1 : av > bv ? 1 : 0;
}

let autoId = 0;

class FakeFirestore {
  constructor({ clock = () => Date.now() } = {}) {
    this.store = new Map();
    this.clock = clock;
    this._txQueue = Promise.resolve();
    this.failOn = null; // (op, path) => Error | null
  }

  _check(op, path) {
    if (this.failOn) {
      const err = this.failOn(op, path);
      if (err) throw err;
    }
  }

  _resolve(existing, data) {
    const out = { ...(existing || {}) };
    for (const [k, v] of Object.entries(data)) {
      if (v && v.__op === "serverTimestamp") out[k] = new FakeTimestamp(this.clock());
      else if (v && v.__op === "inc") out[k] = (typeof out[k] === "number" ? out[k] : 0) + v.n;
      else out[k] = v;
    }
    return out;
  }

  _write(path, data, { merge = false } = {}) {
    this._check("write", path);
    const existing = merge ? this.store.get(path) : undefined;
    this.store.set(path, this._resolve(existing, data));
  }

  _update(path, data) {
    this._check("write", path);
    if (!this.store.has(path)) {
      const e = new Error(`No document to update: ${path}`);
      e.code = 5;
      throw e;
    }
    this.store.set(path, this._resolve(this.store.get(path), data));
  }

  _delete(path) {
    this._check("delete", path);
    this.store.delete(path);
  }

  collection(name) {
    return new CollectionRef(this, name);
  }

  batch() {
    const ops = [];
    return {
      set: (ref, data, opts) => ops.push(() => this._write(ref.path, data, opts)),
      update: (ref, data) => ops.push(() => this._update(ref.path, data)),
      delete: (ref) => ops.push(() => this._delete(ref.path)),
      commit: async () => {
        for (const op of ops) op();
      },
    };
  }

  /** Transactions are serialised to emulate Firestore's isolation. */
  runTransaction(fn) {
    const run = async () => {
      const writes = [];
      const tx = {
        get: async (ref) => ref.get(),
        set: (ref, data, opts) => {
          writes.push(() => this._write(ref.path, data, opts));
          return tx;
        },
        update: (ref, data) => {
          writes.push(() => this._update(ref.path, data));
          return tx;
        },
        delete: (ref) => {
          writes.push(() => this._delete(ref.path));
          return tx;
        },
      };
      const result = await fn(tx);
      for (const w of writes) w();
      return result;
    };
    const p = this._txQueue.then(run, run);
    this._txQueue = p.catch(() => {});
    return p;
  }

  /** Test helper: raw document data or undefined. */
  raw(path) {
    return this.store.get(path);
  }

  docsIn(collectionPath) {
    const prefix = collectionPath + "/";
    return [...this.store.keys()].filter((k) => k.startsWith(prefix) && !k.slice(prefix.length).includes("/"));
  }
}

class DocRef {
  constructor(db, path) {
    this.db = db;
    this.path = path;
    this.id = path.split("/").pop();
  }
  collection(name) {
    return new CollectionRef(this.db, `${this.path}/${name}`);
  }
  async get() {
    this.db._check("read", this.path);
    const data = this.db.store.get(this.path);
    return new DocSnap(this, data);
  }
  async set(data, opts) {
    this.db._write(this.path, data, opts);
  }
  async update(data) {
    this.db._update(this.path, data);
  }
  async delete() {
    this.db._delete(this.path);
  }
}

class DocSnap {
  constructor(ref, data) {
    this.ref = ref;
    this.id = ref.id;
    this.exists = data !== undefined;
    this._data = data;
  }
  data() {
    return this._data === undefined ? undefined : { ...this._data };
  }
  get(field) {
    return this._data ? this._data[field] : undefined;
  }
}

class Query {
  constructor(db, path, filters = [], limitN = null) {
    this.db = db;
    this.path = path;
    this.filters = filters;
    this.limitN = limitN;
  }
  where(field, op, value) {
    return new Query(this.db, this.path, [...this.filters, { field, op, value }], this.limitN);
  }
  limit(n) {
    return new Query(this.db, this.path, this.filters, n);
  }
  async get() {
    this.db._check("read", this.path);
    let paths = this.db.docsIn(this.path);
    paths = paths.filter((p) => {
      const d = this.db.store.get(p);
      return this.filters.every(({ field, op, value }) => {
        const v = d[field];
        switch (op) {
          case "==":
            return v === value;
          case "<":
            return v != null && cmp(v, value) < 0;
          case ">":
            return v != null && cmp(v, value) > 0;
          default:
            throw new Error(`Unsupported op ${op}`);
        }
      });
    });
    if (this.limitN != null) paths = paths.slice(0, this.limitN);
    const docs = paths.map((p) => new DocSnap(new DocRef(this.db, p), this.db.store.get(p)));
    return { docs, size: docs.length, empty: docs.length === 0, forEach: (f) => docs.forEach(f) };
  }
}

class CollectionRef extends Query {
  constructor(db, path) {
    super(db, path);
  }
  doc(id) {
    return new DocRef(this.db, `${this.path}/${id || `auto_${++autoId}`}`);
  }
  async add(data) {
    const ref = this.doc();
    await ref.set(data);
    return ref;
  }
}

module.exports = { FakeFirestore, FakeTimestamp, installFakeHelpers };
