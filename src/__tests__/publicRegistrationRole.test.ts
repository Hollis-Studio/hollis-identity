import assert from "node:assert/strict";
import test from "node:test";
import { publicRegisterBodySchema } from "../validation/publicRegistration.js";

const base = { email: "new-client@example.invalid", password: "sufficient-secret", displayName: "New Client" };

test("public Identity registration accepts only CLIENT role", () => {
  assert.equal(publicRegisterBodySchema.safeParse(base).success, true);
  assert.equal(publicRegisterBodySchema.safeParse({ ...base, role: "CLIENT" }).success, true);
  assert.equal(publicRegisterBodySchema.safeParse({ ...base, role: "ADMIN" }).success, false);
  assert.equal(publicRegisterBodySchema.safeParse({ ...base, role: "CLINICIAN" }).success, false);
  assert.equal(publicRegisterBodySchema.safeParse({ ...base, role: "TRAINER" }).success, false);
});
