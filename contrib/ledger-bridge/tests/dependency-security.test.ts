import { it } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const qs = require("qs");

it("serializes parsed constructor properties without invoking attacker data", () => {
  const parsed = qs.parse("x[constructor][isBuffer]=y", { plainObjects: true });
  assert.doesNotThrow(() => qs.stringify(parsed));
  assert.equal(qs.stringify({ query: "hello" }), "query=hello");
});

it("enforces comma array limits on bracket keys", () => {
  const options = { comma: true, arrayLimit: 3, throwOnLimitExceeded: true };
  assert.throws(() => qs.parse("a[]=1,2,3,4", options), RangeError);
  assert.doesNotThrow(() => qs.parse("a[]=1,2,3", options));
});
