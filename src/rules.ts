import type { Logger } from "./logger.js";

export type RuleDecision = "allow" | "deny" | "ask";

export interface Rule {
  expression: string;
  decision: RuleDecision;
}

export interface RuleContext {
  action: string;
  resource?: string;
  resources: readonly string[];
  command?: string;
  args: readonly string[];
  agent?: string;
  projectDir?: string;
  isDelegation: boolean;
}

// ---------------------------------------------------------------------------
// Command tokenizer: split a shell command string into executable + args,
// honoring single/double quotes. No expansion, no substitution.
// ---------------------------------------------------------------------------

export interface CommandParts {
  command?: string;
  args: string[];
}

export function parseCommand(raw: string): CommandParts {
  const tokens: string[] = [];
  let cur = "";
  let started = false;
  let quote: string | null = null;
  for (const ch of raw) {
    if (quote !== null) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (started) {
        tokens.push(cur);
        cur = "";
        started = false;
      }
      continue;
    }
    started = true;
    cur += ch;
  }
  if (started) tokens.push(cur);
  const [command, ...args] = tokens;
  return { command, args };
}

// ---------------------------------------------------------------------------
// Expression evaluator. Grammar:
//   expr      := orExpr
//   orExpr    := andExpr ("||" andExpr)*
//   andExpr   := unary ("&&" unary)*
//   unary     := "!" unary | comparison
//   comparison:= primary (("==" | "!=" | "in") primary)?
//   primary   := literal | ident | ident "[" number "]" | "(" expr ")"
//   literal   := string | number | boolean | "[" (literal ("," literal)*)? "]"
// No eval / new Function — parsed to an AST once, evaluated against context.
// ---------------------------------------------------------------------------

type Primitive = string | number | boolean;
type Value = Primitive | readonly Primitive[] | undefined;

type Expr =
  | { kind: "literal"; value: Value }
  | { kind: "ident"; name: string }
  | { kind: "index"; name: string; index: number }
  | { kind: "not"; operand: Expr }
  | { kind: "binary"; op: "==" | "!=" | "in" | "&&" | "||"; left: Expr; right: Expr };

interface Token {
  type: "string" | "number" | "ident" | "op" | "lbracket" | "rbracket" | "lparen" | "rparen" | "comma";
  value: string;
}

const KNOWN_IDENTS = new Set([
  "action",
  "resource",
  "resources",
  "command",
  "args",
  "agent",
  "projectDir",
  "isDelegation",
  "true",
  "false",
]);

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      const quote = ch;
      let j = i + 1;
      let value = "";
      while (j < src.length && src[j] !== quote) {
        if (src[j] === "\\" && j + 1 < src.length) {
          value += src[j + 1];
          j += 2;
          continue;
        }
        value += src[j];
        j++;
      }
      if (j >= src.length) throw new Error(`unterminated string in expression: ${src}`);
      tokens.push({ type: "string", value });
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < src.length && /[0-9.]/.test(src[j])) j++;
      tokens.push({ type: "number", value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push({ type: "ident", value: src.slice(i, j) });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (two === "==" || two === "!=" || two === "&&" || two === "||") {
      tokens.push({ type: "op", value: two });
      i += 2;
      continue;
    }
    if (ch === "!") {
      tokens.push({ type: "op", value: "!" });
      i++;
      continue;
    }
    if (ch === "[") {
      tokens.push({ type: "lbracket", value: ch });
      i++;
      continue;
    }
    if (ch === "]") {
      tokens.push({ type: "rbracket", value: ch });
      i++;
      continue;
    }
    if (ch === "(") {
      tokens.push({ type: "lparen", value: ch });
      i++;
      continue;
    }
    if (ch === ")") {
      tokens.push({ type: "rparen", value: ch });
      i++;
      continue;
    }
    if (ch === ",") {
      tokens.push({ type: "comma", value: ch });
      i++;
      continue;
    }
    throw new Error(`unexpected character '${ch}' in expression: ${src}`);
  }
  return tokens;
}

class Parser {
  private pos = 0;
  constructor(private tokens: Token[], private src: string) {}

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }

  private next(): Token {
    const token = this.tokens[this.pos];
    if (!token) throw new Error(`unexpected end of expression: ${this.src}`);
    this.pos++;
    return token;
  }

  private expectOp(value: string): void {
    const token = this.next();
    if (token.type !== "op" || token.value !== value) {
      throw new Error(`expected '${value}' but found '${token.value}' in expression: ${this.src}`);
    }
  }

  parse(): Expr {
    const expr = this.parseOr();
    if (this.pos < this.tokens.length) {
      throw new Error(`unexpected trailing token '${this.tokens[this.pos].value}' in expression: ${this.src}`);
    }
    return expr;
  }

  private parseOr(): Expr {
    let left = this.parseAnd();
    while (this.peek()?.type === "op" && this.peek()?.value === "||") {
      this.next();
      left = { kind: "binary", op: "||", left, right: this.parseAnd() };
    }
    return left;
  }

  private parseAnd(): Expr {
    let left = this.parseUnary();
    while (this.peek()?.type === "op" && this.peek()?.value === "&&") {
      this.next();
      left = { kind: "binary", op: "&&", left, right: this.parseUnary() };
    }
    return left;
  }

  private parseUnary(): Expr {
    const token = this.peek();
    if (token?.type === "op" && token.value === "!") {
      this.next();
      return { kind: "not", operand: this.parseUnary() };
    }
    return this.parseComparison();
  }

  private parseComparison(): Expr {
    const left = this.parsePrimary();
    const token = this.peek();
    if (token?.type === "op" && (token.value === "==" || token.value === "!=")) {
      this.next();
      return { kind: "binary", op: token.value, left, right: this.parsePrimary() };
    }
    if (token?.type === "ident" && token.value === "in") {
      this.next();
      return { kind: "binary", op: "in", left, right: this.parsePrimary() };
    }
    return left;
  }

  private parsePrimary(): Expr {
    const token = this.next();
    if (token.type === "string") return { kind: "literal", value: token.value };
    if (token.type === "number") {
      const value = Number(token.value);
      if (Number.isNaN(value)) throw new Error(`invalid number '${token.value}' in expression: ${this.src}`);
      return { kind: "literal", value };
    }
    if (token.type === "ident") {
      if (token.value === "true") return { kind: "literal", value: true };
      if (token.value === "false") return { kind: "literal", value: false };
      if (!KNOWN_IDENTS.has(token.value)) {
        throw new Error(`unknown identifier '${token.value}' in expression: ${this.src}`);
      }
      if (this.peek()?.type === "lbracket") {
        this.next();
        const index = this.next();
        if (index.type !== "number" || !Number.isInteger(Number(index.value))) {
          throw new Error(`expected integer index in expression: ${this.src}`);
        }
        const close = this.next();
        if (close.type !== "rbracket") throw new Error(`expected ']' in expression: ${this.src}`);
        if (token.value !== "args" && token.value !== "resources") {
          throw new Error(`only 'args' and 'resources' support indexing in expression: ${this.src}`);
        }
        return { kind: "index", name: token.value, index: Number(index.value) };
      }
      return { kind: "ident", name: token.value };
    }
    if (token.type === "lparen") {
      const inner = this.parseOr();
      const close = this.next();
      if (close.type !== "rparen") throw new Error(`expected ')' in expression: ${this.src}`);
      return inner;
    }
    if (token.type === "lbracket") {
      const items: Primitive[] = [];
      if (this.peek()?.type === "rbracket") {
        this.next();
        return { kind: "literal", value: items };
      }
      for (;;) {
        const item = this.next();
        if (item.type === "string") items.push(item.value);
        else if (item.type === "number") {
          const value = Number(item.value);
          if (Number.isNaN(value)) throw new Error(`invalid number '${item.value}' in expression: ${this.src}`);
          items.push(value);
        } else if (item.type === "ident" && (item.value === "true" || item.value === "false")) {
          items.push(item.value === "true");
        } else {
          throw new Error(`arrays may only contain literals in expression: ${this.src}`);
        }
        const sep = this.next();
        if (sep.type === "rbracket") break;
        if (sep.type !== "comma") throw new Error(`expected ',' or ']' in expression: ${this.src}`);
      }
      return { kind: "literal", value: items };
    }
    throw new Error(`unexpected token '${token.value}' in expression: ${this.src}`);
  }
}

export type CompiledExpression = Expr;

export function compileExpression(src: string): CompiledExpression {
  if (typeof src !== "string" || src.trim() === "") {
    throw new Error("rule expression must be a non-empty string");
  }
  return new Parser(tokenize(src), src).parse();
}

function lookup(expr: Expr, ctx: RuleContext): Value {
  if (expr.kind === "literal") return expr.value;
  if (expr.kind === "ident") {
    switch (expr.name) {
      case "action":
        return ctx.action;
      case "resource":
        return ctx.resource;
      case "resources":
        return ctx.resources as readonly Primitive[];
      case "command":
        return ctx.command;
      case "args":
        return ctx.args;
      case "agent":
        return ctx.agent;
      case "projectDir":
        return ctx.projectDir;
      case "isDelegation":
        return ctx.isDelegation;
      default:
        return undefined;
    }
  }
  if (expr.kind === "index") {
    const list = expr.name === "args" ? ctx.args : ctx.resources;
    return list[expr.index];
  }
  return undefined;
}

function truthy(value: Value): boolean {
  if (value === undefined) return false;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") return value.length > 0;
  return value.length > 0;
}

export class RuleEvalError extends Error {}

function evalExpr(expr: Expr, ctx: RuleContext): Value {
  switch (expr.kind) {
    case "literal":
    case "ident":
    case "index":
      return lookup(expr, ctx);
    case "not":
      return !truthy(evalExpr(expr.operand, ctx));
    case "binary": {
      if (expr.op === "&&") {
        return truthy(evalExpr(expr.left, ctx)) ? evalExpr(expr.right, ctx) : false;
      }
      if (expr.op === "||") {
        const left = evalExpr(expr.left, ctx);
        return truthy(left) ? left : evalExpr(expr.right, ctx);
      }
      const left = evalExpr(expr.left, ctx);
      const right = evalExpr(expr.right, ctx);
      if (expr.op === "in") {
        if (!Array.isArray(right)) {
          throw new RuleEvalError(`right side of 'in' must be an array`);
        }
        if (left === undefined || typeof left === "object") return false;
        return (right as readonly Primitive[]).some((item) => item === left);
      }
      // == / != : mismatched types are simply unequal.
      const equal =
        left === right ||
        (typeof left === typeof right &&
          left !== undefined &&
          typeof left !== "object" &&
          left === right);
      return expr.op === "==" ? equal : !equal;
    }
  }
}

export function evaluateExpression(compiled: CompiledExpression, ctx: RuleContext): boolean {
  return truthy(evalExpr(compiled, ctx));
}

// ---------------------------------------------------------------------------
// Rules stage runner: first matching rule wins; no match falls through.
// Evaluation errors skip the rule (fail closed — never a silent allow).
// ---------------------------------------------------------------------------

export interface CompiledRule {
  source: string;
  decision: RuleDecision;
  ast: CompiledExpression;
}

export interface RuleMatch {
  decision: RuleDecision;
  reason: string;
}

export function runRulesStage(
  rules: readonly CompiledRule[],
  ctx: RuleContext,
  log: Logger,
): RuleMatch | null {
  for (const rule of rules) {
    let matched = false;
    try {
      matched = evaluateExpression(rule.ast, ctx);
    } catch (err) {
      log.logJSON("rule evaluation error, skipping rule", {
        expression: rule.source,
        error: err instanceof Error ? err.message : String(err),
      });
      continue;
    }
    if (matched) {
      return { decision: rule.decision, reason: `rule matched: ${rule.source}` };
    }
  }
  return null;
}
