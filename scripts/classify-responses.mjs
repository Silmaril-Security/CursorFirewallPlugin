export function classifyDecision(action, evidence = {}) {
  return {
    action,
    source: null,
    confidence: null,
    severity: null,
    outcome: null,
    governance: null,
    model_id: null,
    ...evidence,
  };
}

export const CLASSIFY_RESPONSES = new Map([
  ["/v2/classify", (decision) => ({ results: [decision] })],
  ["/classify", ({ source, outcome, governance, model_id: modelId }) => ({
    prediction: source === "model" ? "MALICIOUS" : "BENIGN",
    score: source === "model" ? 0.99 : 0.01,
    threshold: 0.5,
    primary_outcome: outcome ?? "benign",
    outcome_scores: outcome ? { [outcome]: 0.99 } : {},
    ...(governance ? { governance } : {}),
    ...(modelId ? { model_id: modelId } : {}),
  })],
]);
