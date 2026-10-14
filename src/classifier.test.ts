import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runDeterministicStage, type StageInput } from "./classifier.js";
import { compileExpression, type CompiledRule } from "./rules.js";
import type { Logger } from "./logger.js";

const silentLog: Logger = { log: () => {}, logJSON: () => {} };

function input(overrides: Partial<StageInput> = {}): StageInput {
  return {
    action: "shell",
    resources: ["git status"],
    agent: "auto",
    projectDir: "/repo",
    isDelegation: false,
    ...overrides,
  };
}

function rulesStage(expressions: Array<[string, "allow" | "deny" | "ask"]>) {
  const rules: CompiledRule[] = expressions.map(([source, decision]) => ({
    source,
    decision,
    ast: compileExpression(source),
  }));
  return { type: "rules" as const, rules };
}

describe("static stage", () => {
  it("maps tier results to decisions", () => {
    assert.deepEqual(runDeterministicStage({ type: "static" }, input(), silentLog), {
      decision: "allow",
      reason: "safe read-only command",
    });
    const denied = runDeterministicStage({ type: "static" }, input({ resources: ["rm -rf /"] }), silentLog);
    assert.equal(denied?.decision, "deny");
    assert.equal(
      runDeterministicStage({ type: "static" }, input({ resources: ["make deploy"] }), silentLog),
      null,
    );
  });
});

describe("rules stage", () => {
  const stage = rulesStage([
    ["action == 'shell' && command == 'git' && args[0] in ['status','diff']", "allow"],
  ]);

  it("returns the matching rule decision", () => {
    assert.deepEqual(runDeterministicStage(stage, input(), silentLog), {
      decision: "allow",
      reason: "rule matched: action == 'shell' && command == 'git' && args[0] in ['status','diff']",
    });
  });

  it("returns null when no rule matches", () => {
    assert.equal(runDeterministicStage(stage, input({ resources: ["git push"] }), silentLog), null);
  });

  it("never matches a rule against a chained command", () => {
    assert.equal(
      runDeterministicStage(stage, input({ resources: ["git status && rm -rf /tmp/x"] }), silentLog),
      null,
    );
    assert.equal(
      runDeterministicStage(stage, input({ resources: ["git status | head"] }), silentLog),
      null,
    );
  });

  it("evaluates non-shell rules with command/args undefined", () => {
    const readStage = rulesStage([["action in ['read','glob','grep']", "allow"]]);
    assert.deepEqual(
      runDeterministicStage(
        readStage,
        input({ action: "read", resources: ["src/index.ts"] }),
        silentLog,
      ),
      { decision: "allow", reason: "rule matched: action in ['read','glob','grep']" },
    );
  });

  it("exposes agent, projectDir, and isDelegation to rules", () => {
    const agentStage = rulesStage([["agent == 'auto' && projectDir == '/repo' && !isDelegation", "allow"]]);
    assert.equal(runDeterministicStage(agentStage, input(), silentLog)?.decision, "allow");
    assert.equal(
      runDeterministicStage(agentStage, input({ agent: "build" }), silentLog),
      null,
    );
    assert.equal(
      runDeterministicStage(
        agentStage,
        input({ action: "task", resources: ["research"], isDelegation: true }),
        silentLog,
      ),
      null,
    );
  });
});
