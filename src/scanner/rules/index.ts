import { Rule } from "../../report/types.js";
import { networkRules } from "./network.js";
import { obfuscationRules } from "./obfuscation.js";
import { exfiltrationRules } from "./exfiltration.js";
import { executionRules } from "./execution.js";
import { cryptoRules } from "./crypto.js";
import { persistenceRules } from "./persistence.js";
import { installScriptRules } from "./install-scripts.js";

export const ALL_RULES: Rule[] = [
  ...networkRules,
  ...obfuscationRules,
  ...exfiltrationRules,
  ...executionRules,
  ...cryptoRules,
  ...persistenceRules,
  ...installScriptRules,
];
