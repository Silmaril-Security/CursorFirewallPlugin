# Contributing

Use a branch from current `origin/main`. Keep host-native behavior, fail-open defaults, exact `MALICIOUS` enforcement, and raw-content non-retention intact.

Before submitting a change, run:

```sh
npm ci
npm run lint
npm test
npm run pack:dry
```

Commit the rebuilt `dist/cursor-hook.js` whenever TypeScript runtime code changes. Do not add secrets, customer payloads, raw lifecycle fixtures, generated credentials, or production endpoints.
