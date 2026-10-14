import type { Logger } from "./logger.js";
import type { PolicyOptions } from "./policy.js";
import { compileExpression, type CompiledRule, type RuleDecision } from "./rules.js";

export interface ReviewerModel {
  id: string;
  providerID: string;
  variant?: string;
}

export type StageType = "static" | "rules" | "llm";

export type CompiledStage =
  | { type: "static" }
  | { type: "llm" }
  | { type: "rules"; rules: CompiledRule[] };

export interface ParsedOptions {
  reviewerModel: ReviewerModel | undefined;
  reviewScope: "all" | "prompts";
  policyOptions: PolicyOptions;
  allowInProjectEdits: boolean;
  agents: string[];
  stages: CompiledStage[];
}

export const DEFAULT_STAGES: CompiledStage[] = [{ type: "static" }, { type: "llm" }];

const STAGE_TYPES = new Set<StageType>(["static", "rules", "llm"]);
const RULE_DECISIONS = new Set<RuleDecision>(["allow", "deny", "ask"]);

interface RawRule {
  expression?: unknown;
  decision?: unknown;
}

interface RawStage {
  type?: unknown;
  rules?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseReviewerModel(raw: unknown, log: Logger): ReviewerModel | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!isRecord(raw) || typeof raw.id !== "string" || typeof raw.providerID !== "string") {
    log.log("options.model ignored: expected { id: string, providerID: string }");
    return undefined;
  }
  const variant = typeof raw.variant === "string" ? { variant: raw.variant } : {};
  return { id: raw.id, providerID: raw.providerID, ...variant };
}

function parseAgents(raw: unknown, log: Logger): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw) || raw.some((item) => typeof item !== "string")) {
    log.log("options.agents ignored: expected an array of agent id strings");
    return [];
  }
  return raw as string[];
}

function parseStage(raw: RawStage, index: number, log: Logger): CompiledStage | null {
  const type = raw.type;
  if (typeof type !== "string" || !STAGE_TYPES.has(type as StageType)) {
    log.log(`classifier stage ${index} ignored: unknown type '${String(type)}'`);
    return null;
  }
  const stageType = type as StageType;
  if (stageType !== "rules") return { type: stageType };

  if (!Array.isArray(raw.rules) || raw.rules.length === 0) {
    log.log(`classifier stage ${index} ignored: 'rules' stage requires a non-empty rules array`);
    return null;
  }
  const compiled: CompiledRule[] = [];
  for (const [ruleIndex, rawRule] of (raw.rules as RawRule[]).entries()) {
    const source = typeof rawRule?.expression === "string" ? rawRule.expression : "";
    const decision = rawRule?.decision;
    if (typeof decision !== "string" || !RULE_DECISIONS.has(decision as RuleDecision)) {
      log.log(
        `classifier stage ${index} rule ${ruleIndex} ignored: decision must be allow|deny|ask`,
      );
      continue;
    }
    try {
      compiled.push({
        source,
        decision: decision as RuleDecision,
        ast: compileExpression(source),
      });
    } catch (err) {
      log.log(
        `classifier stage ${index} rule ${ruleIndex} ignored: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }
  if (compiled.length === 0) {
    log.log(`classifier stage ${index} ignored: no valid rules`);
    return null;
  }
  return { type: "rules", rules: compiled };
}

function parseStages(raw: unknown, log: Logger): CompiledStage[] {
  if (raw === undefined) return DEFAULT_STAGES;
  if (!isRecord(raw) || !Array.isArray(raw.stages) || raw.stages.length === 0) {
    log.log("options.classifier ignored: expected { stages: [...] } with at least one stage");
    return DEFAULT_STAGES;
  }
  const stages = (raw.stages as RawStage[])
    .map((stage, index) => parseStage(stage, index, log))
    .filter((stage): stage is CompiledStage => stage !== null);
  if (stages.length === 0) {
    log.log("options.classifier ignored: no valid stages; falling back to [static, llm]");
    return DEFAULT_STAGES;
  }
  const llmIndex = stages.findIndex((stage) => stage.type === "llm");
  if (llmIndex !== -1 && llmIndex !== stages.length - 1) {
    log.log("classifier: 'llm' stage is terminal; stages after it will never run");
  }
  return stages;
}

export function parsePluginOptions(raw: unknown, log: Logger): ParsedOptions {
  const options = isRecord(raw) ? raw : {};
  return {
    reviewerModel: parseReviewerModel(options.model, log),
    reviewScope: options.review === "prompts" ? "prompts" : "all",
    policyOptions: {
      trusted: Array.isArray(options.trusted) ? (options.trusted as string[]) : undefined,
      blocks: Array.isArray(options.blocks) ? (options.blocks as string[]) : undefined,
      exceptions: Array.isArray(options.exceptions) ? (options.exceptions as string[]) : undefined,
    },
    allowInProjectEdits: options.allowInProjectEdits !== false,
    agents: parseAgents(options.agents, log),
    stages: parseStages(options.classifier, log),
  };
}
