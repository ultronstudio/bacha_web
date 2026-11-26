"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const W = require("../../tools/link-inspector/worker");
const M = require("../../lib/server/bacha/urlMetadata");

test("reject internal, reserved, alternate scheme and credential URLs", async () => {
  for (const value of ["http://localhost/", "http://169.254.169.254/", "http://2130706433/", "http://x.local/", "file:///etc/passwd", "https://u:p@site.com/", "https://site.com:8443/"])
    assert.throws(() => W.safeUrl(value));
  for (const ip of ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "203.0.113.1", "::1", "168.63.129.16"])
    assert.equal(W.publicIpv4(ip), false);
  assert.equal(W.publicIpv4("8.8.8.8"), true);
  await assert.rejects(W.resolvePublic("site.com", async () => ["8.8.8.8", "10.0.0.1"]));
});
test("redirect targets are independently validated before request", async () => {
  let calls = 0;
  const r = await W.inspect("https://site.com/", {
    resolve4: async () => ["8.8.8.8"],
    request: async () => { calls++; return { status:302, location:"http://169.254.169.254/" }; },
  });
  assert.equal(r.checked, false);
  assert.equal(calls, 1);
});
test("bounded static inspection returns only metadata and strips query", async () => {
  const observed = [];
  const r = await W.inspect("https://site.com/path?token=secret", {
    resolve4: async () => ["8.8.8.8"],
    request: async (url, ip) => {
      observed.push([url.href, ip]);
      return observed.length === 1 ? {status:302, location:"https://other.com/login?private=1"} :
        {status:200, html:'<form action="https://third.com/"><input type="password"></form>'};
    },
  });
  assert.deepEqual(observed, [["https://site.com/path","8.8.8.8"],["https://other.com/login","8.8.8.8"]]);
  assert.equal(r.checked, true); assert.equal(r.changedHost, true); assert.equal(r.queryOmitted, true);
  assert.equal(r.passwordForm, true); assert.equal(r.externalForm, true);
  assert.ok(!JSON.stringify(r).includes("third.com"));
});
test("RDAP is opt-in, fixed endpoint, registration event only, no personal fields", async () => {
  let called = 0;
  const fetchImpl = async (url, options) => {
    called++; assert.equal(url,"https://rdap.nic.cz/domain/site.cz"); assert.equal(options.redirect,"error");
    return new Response(JSON.stringify({objectClassName:"domain",ldhName:"site.cz",
      events:[{eventAction:"registration",eventDate:"2026-11-01T00:00:00Z"}],entities:[{secret:"private"}]}));
  };
  assert.equal((await M.lookupDomainAge("www.site.cz", {fetchImpl})).checked,false);
  assert.equal(called,0);
  const r = await M.lookupDomainAge("www.site.cz",{enabled:true,fetchImpl,now:Date.parse("2026-11-26T00:00:00Z")});
  assert.deepEqual(r,{checked:true,ageDays:25});
  assert.equal(M.metadataSignals(r,{checked:false})[0].severity,"LOW");
});
test("worker adapter is disabled without config and never sends query", async () => {
  const r0 = await M.inspectThroughWorker("https://site.com/?token=private");
  assert.equal(r0.checked,false);
  const r = await M.inspectThroughWorker("https://site.com/?token=private", {
    endpoint:"https://worker.example/inspect",token:"x".repeat(32),
    fetchImpl:async (url, options) => {
      assert.equal(url.href,"https://worker.example/inspect");
      assert.deepEqual(JSON.parse(options.body),{url:"https://site.com/"});
      return new Response(JSON.stringify({checked:true,redirects:1,externalForm:true,passwordForm:true,changedHost:true}));
    },
  });
  assert.equal(r.checked,true);
  assert.equal(r.queryOmitted,true);
  assert.equal(M.metadataSignals({checked:false},r).some((s)=>s.id==="metadata_external_sensitive_form"),true);
});
