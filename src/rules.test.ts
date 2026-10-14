import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  compileExpression,
  evaluateExpression,
  parseCommand,
  runRulesStage,
  type CompiledRule,
  type RuleContext,
} from "./rules.js";
import type { Logger } from "./logger.js";

const silentLog: Logger = { log: () => {}, logJSON: () => {} };

function ctx(overrides: Partial<RuleContext> = {}): RuleContext {
  return {
    action: "shell",
    resource: "git status",
    resources: ["git status"],
    command: "git",
    args: ["status"],
    agent: "auto",
    projectDir: "/repo",
    isDelegation: false,
    ...overrides,
  };
}

function rule(expression: string, decision: "allow" | "deny" | "ask" = "allow"): CompiledRule {
  return { source: expression, decision, ast: compileExpression(expression) };
}

describe("parseCommand", () => {
  it("splits command and args on whitespace", () => {
    assert.deepEqual(parseCommand("git status --short"), {
      command: "git",
      args: ["status", "--short"],
    });
  });

  it("honors single and double quotes", () => {
    assert.deepEqual(parseCommand(`npm run "build:app" --flag='x y'`), {
      command: "npm",
      args: ["run", "build:app", "--flag=x y"],
    });
  });

  it("handles empty input and collapses whitespace", () => {
    assert.deepEqual(parseCommand(""), { command: undefined, args: [] });
    assert.deepEqual(parseCommand("   ls   -la  "), { command: "ls", args: ["-la"] });
  });
});

describe("compileExpression", () => {
  it("rejects empty, unknown identifiers, and malformed input", () => {
    assert.throws(() => compileExpression(""), /non-empty/);
    assert.throws(() => compileExpression("foo == 'bar'"), /unknown identifier/);
    assert.throws(() => compileExpression("action == 'shell"), /unterminated/);
    assert.throws(() => compileExpression("action == 'shell' extra"), /trailing token/);
    assert.throws(() => compileExpression("action[0] == 'shell'"), /only 'args' and 'resources'/);
    assert.throws(() => compileExpression("args[0] in [args]"), /only contain literals/);
  });
});

describe("evaluateExpression", () => {
  it("matches the git read-only rule", () => {
    const ast = compileExpression(
      "action == 'shell' && command == 'git' && args[0] in ['status','diff','log','show','branch']",
    );
    assert.equal(evaluateExpression(ast, ctx()), true);
    assert.equal(evaluateExpression(ast, ctx({ args: ["push"] })), false);
    assert.equal(evaluateExpression(ast, ctx({ command: "npm", args: ["status"] })), false);
  });

  it("matches the package-manager rule", () => {
    const ast = compileExpression(
      "action == 'shell' && command in ['npm','bun','pnpm','yarn'] && args[0] in ['install','test','run','build','typecheck','lint']",
    );
    assert.equal(evaluateExpression(ast, ctx({ command: "npm", args: ["test"] })), true);
    assert.equal(evaluateExpression(ast, ctx({ command: "bun", args: ["run", "build"] })), true);
    assert.equal(evaluateExpression(ast, ctx({ command: "npm", args: ["publish"] })), false);
  });

  it("matches the read-action rule", () => {
    const ast = compileExpression("action in ['read','glob','grep']");
    assert.equal(evaluateExpression(ast, ctx({ action: "read", command: undefined, args: [] })), true);
    assert.equal(evaluateExpression(ast, ctx({ action: "edit" })), false);
  });

  it("supports parentheses, negation, and booleans", () => {
    const ast = compileExpression("(action == 'edit' || action == 'write') && !isDelegation");
    assert.equal(evaluateExpression(ast, ctx({ action: "edit" })), true);
    assert.equal(evaluateExpression(ast, ctx({ action: "task", isDelegation: true })), false);
  });

  it("treats out-of-range indexes and missing values as no match", () => {
    const ast = compileExpression("args[0] == 'status'");
    assert.equal(evaluateExpression(ast, ctx({ args: [] })), false);
    assert.equal(evaluateExpression(ast, ctx({ command: undefined, args: [] })), false);
  });

  it("treats mismatched types as unequal", () => {
    assert.equal(evaluateExpression(compileExpression("action == 1"), ctx()), false);
    assert.equal(evaluateExpression(compileExpression("action != 1"), ctx()), true);
  });
});

describe("runRulesStage", () => {
  it("returns the first matching rule's decision", () => {
    const stage = [
      rule("action == 'shell' && command == 'git'", "deny"),
      rule("action == 'shell'", "allow"),
    ];
    assert.deepEqual(runRulesStage(stage, ctx(), silentLog), {
      decision: "deny",
      reason: "rule matched: action == 'shell' && command == 'git'",
    });
  });

  it("returns null when nothing matches", () => {
    const stage = [rule("action == 'webfetch'", "deny")];
    assert.equal(runRulesStage(stage, ctx(), silentLog), null);
  });

  it("skips rules that error at evaluation and continues", () => {
    const stage = [
      rule("args[0] in command", "allow"), // 'in' against a string -> RuleEvalError
      rule("command == 'git'", "allow"),
    ];
    assert.deepEqual(runRulesStage(stage, ctx(), silentLog), {
      decision: "allow",
      reason: "rule matched: command == 'git'",
    });
  });
});
