"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { ordinaryPickupOnly, reconcilePickup } = require("../../lib/server/bacha/pickupContext");
const { combineServerVerdict } = require("../../lib/server/bacha/riskEngine");
const text = "Ahoj mami. Potřebuju vyzvednout balíček. Kód je 123 456. Dej mi vědět až ho vyzvedneš.";
const ai = {riskLevel:"HIGH",confidence:"HIGH",scamType:"DELIVERY",signals:[{id:"ai_otp",severity:"HIGH",evidenceGroup:"CREDENTIAL_REQUEST"}]};
const input = {text,analysisType:"TEXT_OR_URL",image:null};
test("ordinary pickup with family greeting and pickup code is inconclusive, not confirmed safe or high risk", () => {
  assert.equal(ordinaryPickupOnly(text),true);
  const r = reconcilePickup(ai,input,null,[]);
  assert.equal(r.riskLevel,"UNKNOWN");
  assert.equal(combineServerVerdict({ai:r}).category,"INCONCLUSIVE");
  assert.equal(r.signals.length,0);
});
test("mixed risk, images, links, credential requests and verified indicators are not suppressed", () => {
  for (const extra of [" Zaplaťte poplatek.", " Přihlas se do banky.", " Pošli SMS kód.", " https://example.invalid", " Nevolej mi.", " Předej heslo."]) {
    assert.equal(reconcilePickup(ai,{...input,text:text+extra},null,[]),ai);
  }
  assert.equal(reconcilePickup(ai,{...input,image:{}},null,[]),ai);
  assert.equal(reconcilePickup(ai,input,{verdict:"CONFIRMED_MALICIOUS"},[]),ai);
  assert.equal(reconcilePickup(ai,input,{verdict:"SUSPICIOUS"},[]),ai);
  assert.equal(reconcilePickup(ai,input,null,[{id:"metadata"}]),ai);
});
