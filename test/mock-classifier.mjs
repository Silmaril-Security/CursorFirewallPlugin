import assert from "node:assert/strict";
import http from "node:http";

import { CLASSIFY_RESPONSES, classifyDecision } from "../scripts/classify-responses.mjs";

export async function withMockClassifier(
  run,
  { decision = classifyDecision("allow"), responses = CLASSIFY_RESPONSES } = {},
) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push({ path: request.url, payload: JSON.parse(body) });
      const render = responses[request.url];
      response.writeHead(render ? 200 : 404, { "content-type": "application/json" });
      response.end(JSON.stringify(render ? render(decision) : { detail: "Not Found" }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await run(`http://127.0.0.1:${address.port}`, requests);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}
