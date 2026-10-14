import type { Logger } from "./logger.js";
import type { CompiledStage } from "./options.js";
import { parseCommand, runRulesStage, type RuleDecision, type RuleContext } from "./rules.js";
import { classify, hasShellMetacharacters } from "./tiers.js";

export interface StageInput {
  action: string;
  resources: readonly string[];
  agent?: string;
  projectDir?: string;
  isDelegation: boolean;
}

export interface StageOutcome {
  decision: RuleDecision;
  reason: string;
}

// Runs one deterministic stage ("static" or "rules"). Returns null when the
// stage has no opinion and the pipeline should continue to the next stage.
export function runDeterministicStage(
  stage: Exclude<CompiledStage, { type: "llm" }>,
  input: StageInput,
  log: Logger,
): StageOutcome | null {
  if (stage.type === "static") {
    const classification = classify(input.action, input.resources, {
      projectDir: input.projectDir,
    });
    log.logJSON("classification", classification);
    if (classification.tier === "auto-allow") {
      return { decision: "allow", reason: classification.reason };
    }
    if (classification.tier === "auto-deny") {
      return { decision: "deny", reason: classification.reason };
    }
    return null;
  }

  // rules stage: a permitted prefix never authorizes the rest of a chained
  // command ("pwd ; sudo rm -rf"), so chained/redirected shell commands skip
  // the rules stage and fall through to the LLM reviewer.
  let command: string | undefined;
  let args: readonly string[] = [];
  if (input.action === "shell") {
    const raw = input.resources[0] ?? "";
    if (hasShellMetacharacters(raw)) {
      log.log("rules stage skipped: chained or redirected command evaluated as one action");
      return null;
    }
    const parts = parseCommand(raw);
    command = parts.command;
    args = parts.args;
  }

  const ctx: RuleContext = {
    action: input.action,
    resource: input.resources[0],
    resources: input.resources,
    command,
    args,
    agent: input.agent,
    projectDir: input.projectDir,
    isDelegation: input.isDelegation,
  };
  return runRulesStage(stage.rules, ctx, log);
}
