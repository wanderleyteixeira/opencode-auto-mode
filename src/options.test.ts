import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_STAGES, parsePluginOptions } from "./options.js";
import type { Logger } from "./logger.js";

const silentLog: Logger = { log: () => {}, logJSON: () => {} };

describe("parsePluginOptions", () => {
  it("applies defaults for empty options", () => {
    const parsed = parsePluginOptions({}, silentLog);
    assert.equal(parsed.reviewScope, "all");
    assert.equal(parsed.allowInProjectEdits, true);
    assert.deepEqual(parsed.agents, []);
    assert.deepEqual(parsed.stages, DEFAULT_STAGES);
    assert.equal(parsed.reviewerModel, undefined);
  });

  it("parses model, review mode, and agents", () => {
    const parsed = parsePluginOptions(
      {
        review: "prompts",
        agents: ["auto"],
        model: { id: "cheap", providerID: "router" },
      },
      silentLog,
    );
    assert.equal(parsed.reviewScope, "prompts");
    assert.deepEqual(parsed.agents, ["auto"]);
    assert.deepEqual(parsed.reviewerModel, { id: "cheap", providerID: "router" });
  });

  it("falls back to default stages for a malformed classifier", () => {
    assert.deepEqual(parsePluginOptions({ classifier: {} }, silentLog).stages, DEFAULT_STAGES);
    assert.deepEqual(parsePluginOptions({ classifier: { stages: [] } }, silentLog).stages, DEFAULT_STAGES);
    assert.deepEqual(
      parsePluginOptions({ classifier: { stages: [{ type: "nope" }] } }, silentLog).stages,
      DEFAULT_STAGES,
    );
  });

  it("compiles valid rules and skips invalid ones", () => {
    const parsed = parsePluginOptions(
      {
        classifier: {
          stages: [
            { type: "static" },
            {
              type: "rules",
              rules: [
                { expression: "action == 'shell'", decision: "allow" },
                { expression: "unknown ident == 1", decision: "deny" },
                { expression: "action == 'webfetch'", decision: "not-a-decision" },
              ],
            },
            { type: "llm" },
          ],
        },
      },
      silentLog,
    );
    assert.equal(parsed.stages.length, 3);
    const rulesStage = parsed.stages[1];
    assert.equal(rulesStage.type, "rules");
    if (rulesStage.type === "rules") {
      assert.equal(rulesStage.rules.length, 1);
      assert.equal(rulesStage.rules[0].source, "action == 'shell'");
    }
  });

  it("ignores malformed agents and model", () => {
    const parsed = parsePluginOptions(
      { agents: "auto", model: { id: 1 } },
      silentLog,
    );
    assert.deepEqual(parsed.agents, []);
    assert.equal(parsed.reviewerModel, undefined);
  });
});
