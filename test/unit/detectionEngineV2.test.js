"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { validateAiOutput, RESPONSE_SCHEMA } = require("../../lib/server/bacha/aiOutput");
const { combineServerVerdict } = require("../../lib/server/bacha/riskEngine");
const { checkExternalProviders } = require("../../lib/server/bacha/threatIntel");

test("structured context and evidence groups are sanitized", () => {
  const r = validateAiOutput({ riskLevel:"LOW", confidence:"HIGH", summary:"Ověřte zdroj.",
    scamType:"INVOICE", detectedActions:["CHANGE_BANK_ACCOUNT","BOGUS","CHANGE_BANK_ACCOUNT"],
    requiresFurtherVerification:true, signals:[] });
  assert.deepEqual(r.detectedActions, ["CHANGE_BANK_ACCOUNT"]);
  assert.equal(r.scamType, "INVOICE");
  assert.ok(RESPONSE_SCHEMA.required.includes("detectedActions"));
  assert.equal(combineServerVerdict({ai:r}).category,"INCONCLUSIVE");
});
test("correlated model signals cannot inflate verdict", () => {
  const s = {id:"same", severity:"CAUTION", evidenceGroup:"CREDENTIAL_REQUEST"};
  const ai = {riskLevel:"CAUTION",confidence:"HIGH",signals:[s,{...s,id:"same2"},{...s,id:"same3"}]};
  assert.equal(combineServerVerdict({ai}).category,"SUSPICIOUS");
});
test("unsupported HIGH model verdict is a warning, not confirmed high risk", () => {
  assert.equal(combineServerVerdict({ai:{riskLevel:"HIGH",confidence:"HIGH",signals:[]}}).category,"SUSPICIOUS");
});
test("unchecked provider cannot confirm maliciousness", async () => {
  const r = await checkExternalProviders("https://example.invalid", [{name:"WEB_RISK",checkUrl:async()=>({checked:false,isMalicious:true})}]);
  assert.equal(r.hit,null);
});
