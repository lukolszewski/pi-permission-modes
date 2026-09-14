# Stable system prompt (KV-cache-friendly banner delivery)

Branch: `stable-prompt`. Fixes the full-context re-prefill problem documented in
`~/dev/airun/pi-issue.md`: the plugin used to re-render a state-dependent
`<!-- permission-modes:context -->` block into the **system prompt** every turn.
Any byte change that early in the request invalidates the inference server's KV
cache for everything after it — with a ~180 k-token conversation, one banner flip
(mode switch, one-shot reminder appearing/disappearing, a compliance note after a
denial, plan-todo progress) forced a 60–100 k-token re-prefill taking 100–180 s.

## What changed

- `before_agent_start` no longer injects anything into the system prompt. The
  banner (mode block + injection warning) is still computed exactly as before,
  but stored in module state (`tailBannerText`). The system prompt is returned
  modified **only** when per-mode skill filtering actually rewrites it (a no-op
  unless the user configured mode-specific skills, and then it changes only on a
  real mode switch).
- A new `context` event handler appends the banner as the **last message** of
  every LLM call:

  ```
  { role: "custom", customType: "permission-modes-notice",
    content: "<permission-mode>\n…\n</permission-mode>", display: false }
  ```

  pi converts `role: "custom"` to a user-role message for the provider. The
  message is transient (never persisted to the session, never shown in the UI,
  never seen by the classifier transcript builder). At the tail it costs only its
  own ~60–150 tokens per call instead of invalidating the whole prefix.

## Why a trailing *system* message was not used

The Qwen chat templates on this stack (llama.cpp `--jinja`; Qwen3.5-4B,
Qwen3.8-27B, Qwen3.8-Flash-Next through litellm) hard-fail on any `system` or
`developer` message that is not the first message:
`raise_exception('System message must be at the beginning')` — verified
empirically on all three endpoints (2026-09-14). pi-ai's `Message` union has no
system role for history messages either. A trailing user-role message is what
pi itself uses for its own custom notices, and a live probe confirmed the model
reads and obeys the `<permission-mode>` block from that position.

## Behaviour notes

- Content is unchanged: ask/bypass one-shots, plan protocol + remaining todos,
  post-denial compliance note, auto/bypass injection warning — same text, new
  position. One-shots still appear for exactly one turn.
- In ask mode after the one-shot is consumed, **no trailing message is sent at
  all**; in auto the tail is the (stable) injection warning; plan mode carries
  the protocol block while the mode is active.
- Sessions where the user never enters a special state get a byte-identical
  system prompt for the whole session, so consecutive turns share their full
  prefix and the server prefills only the appended delta.

## Acceptance

`index.test.ts` › "stable system prompt across turns": the system prompt is
never rewritten across turns and mode switches; the notice is appended as the
last message with `display: false`; one-shots go quiet after one turn; the auto
tail is byte-stable turn-to-turn. Matches the acceptance check in
`pi-issue.md` (§Acceptance): `commonprefix(turn N, turn N+1) ≈ len(N)`.

## Revert

The change is isolated to this branch (system-prompt handling in `index.ts`,
tests, this file). Reverting = not merging `stable-prompt` / merging only
`gate-v3`; the two branches touch disjoint concerns.
