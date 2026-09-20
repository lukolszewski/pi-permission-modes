/**
 * Gate ↔ ledger integration: runGate's ledger step (pure code path, mocked or
 * absent endpoint) and gate-bridge syncLedger (mocked fetch).
 */
import { afterEach, describe, expect, it, vi } from "vitest"
import { applyEvent, createLedger } from "./auth-ledger.ts"
import { collectUserMessageRefs, syncLedger } from "./gate-bridge.ts"
import { runGate } from "./gate.ts"
import { createGrantStore } from "./session-grants.ts"
import type { MessageExtraction } from "./model-client.ts"

const POLICY = { cwd: "/home/u/proj", project: "/home/u/proj", home: "/home/u" }
const EP = { baseUrl: "http://mock", model: "mock" }

function ledgerWith(entries: Parameters<typeof applyEvent>[1][]) {
	const l = createLedger()
	for (const e of entries) applyEvent(l, e)
	return l
}

const rsyncGrant = {
	type: "grant" as const,
	category: "write_outside",
	value: "/x/x/",
	kind: "scope" as const,
	quote: "copy the file to /x/x/ with rsync",
	messageId: "m1",
	seq: 1,
}

/** OpenAI-style fetch mock: picks the extraction by which user message text
 *  appears in the request body; records call count. */
function mockExtractionFetch(map: Array<[string, MessageExtraction]>, opts?: { failFor?: string }) {
	const calls: string[] = []
	const fn = vi.fn(async (_url: unknown, init?: { body?: string }) => {
		// match on the user prompt only — the system prompt's few-shot examples
		// would otherwise satisfy any needle
		const parsed = JSON.parse(String(init?.body ?? "{}")) as { messages?: Array<{ content?: string }> }
		const body = String(parsed.messages?.[1]?.content ?? "")
		const hit = map.find(([needle]) => body.includes(needle))
		calls.push(hit?.[0] ?? body.split("\n")[1]?.slice(0, 30) ?? "?")
		if (opts?.failFor && body.includes(opts.failFor)) {
			return { ok: false, status: 500, text: async () => "boom" }
		}
		const payload: MessageExtraction = hit?.[1] ?? { grants: [], revocations: [] }
		return {
			ok: true,
			json: async () => ({ choices: [{ message: { content: JSON.stringify(payload) } }] }),
		}
	})
	vi.stubGlobal("fetch", fn)
	return { fn, calls }
}

afterEach(() => vi.unstubAllGlobals())

describe("runGate ledger step", () => {
	it("ledger grant covers mkdir at an rsync-granted location (kind-group widening), no model call", async () => {
		const grants = createGrantStore()
		const r = await runGate("bash", { command: "mkdir -p /x/x/sub" }, {
			policy: POLICY,
			grants,
			ledger: ledgerWith([rsyncGrant]),
			userMessages: ["copy the file to /x/x/ with rsync"],
			// no endpoint: if the ledger step did not grant, this would be "prompt"
		})
		expect(r.outcome).toBe("allow-granted")
		expect(r.grantedBy).toBe("ledger")
		expect(r.modelCalls).toHaveLength(0)
		// promoted to a session grant so repeats skip the ledger scan
		expect(grants.grants.some((g) => g.category === "write_outside" && g.value === "/x/x/sub")).toBe(true)
	})
	it("rsync grant does NOT cover a recursive delete there (verb gate)", async () => {
		const r = await runGate("bash", { command: "rm -rf /x/x/old" }, {
			policy: POLICY,
			ledger: ledgerWith([rsyncGrant]),
			userMessages: [],
		})
		expect(r.outcome).toBe("prompt")
	})
	it("ledger forbid goes straight to prompt — the recent-window fallback is NOT consulted", async () => {
		const { fn } = mockExtractionFetch([])
		const r = await runGate("bash", { command: "mkdir -p /x/x/sub" }, {
			policy: POLICY,
			endpoint: EP,
			ledger: ledgerWith([
				rsyncGrant,
				{ type: "forbid", category: "*", value: "/x/x/", kind: "scope", quote: "actually leave /x/x/ alone", messageId: "m9", seq: 9 },
			]),
			// a stale grant is still inside the window — must not overrule the revocation
			userMessages: ["copy the file to /x/x/ with rsync"],
		})
		expect(r.outcome).toBe("prompt")
		expect(r.reason).toContain("forbade")
		expect(fn).not.toHaveBeenCalled()
	})
})

describe("collectUserMessageRefs", () => {
	const branch = [
		{ type: "message", id: "a1", message: { role: "user", content: "hello" } },
		{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "hi" }] } },
		{ type: "message", message: { role: "user", content: [{ type: "text", text: "copy data to /x/x/" }] } },
		{ type: "custom" },
		{ type: "message", id: "a4", message: { role: "user", content: [{ type: "text", text: "<tool_result>skip me</tool_result>" }] } },
	]
	it("keeps ids, synthesizes stable ones, preserves branch seq, skips non-user/tool-result", () => {
		const refs = collectUserMessageRefs(branch as never)
		expect(refs).toEqual([
			{ id: "a1", seq: 0, text: "hello" },
			{ id: "#2", seq: 2, text: "copy data to /x/x/" },
		])
	})
})

describe("syncLedger", () => {
	const refs = [
		{ id: "m0", seq: 0, text: "hello there" },
		{ id: "m1", seq: 2, text: "copy the dataset to /x/x/ with rsync" },
		{ id: "m2", seq: 4, text: "thanks, looks good" },
	]
	const extractions: Array<[string, MessageExtraction]> = [
		["copy the dataset", {
			grants: [{ action: "copy files", targets: ["/x/x/"], quote: "copy the dataset to /x/x/ with rsync" }],
			revocations: [],
		}],
	]

	it("processes newest-first within maxCalls, folds verified grants", async () => {
		const { calls } = mockExtractionFetch(extractions)
		const ledger = createLedger()
		const res = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(calls).toEqual(["thanks, looks good", "copy the dataset"])
		// (needle "thanks, looks good" resolves via the fallback label — it is
		// not in the extraction map, so the mock returns an empty extraction)
		expect(res).toMatchObject({ processed: 2, pending: 1, changed: true })
		expect(ledger.grants).toEqual([expect.objectContaining({ value: "/x/x/", seq: 2, messageId: "m1" })])
		expect(ledger.seen.has("m0")).toBe(false)
	})
	it("second pass drains the rest; already-seen messages cost nothing", async () => {
		const { fn } = mockExtractionFetch(extractions)
		const ledger = createLedger()
		await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		const res2 = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(res2).toMatchObject({ processed: 1, pending: 0 })
		const res3 = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 2 })
		expect(res3).toMatchObject({ processed: 0, pending: 0, changed: false })
		expect(fn).toHaveBeenCalledTimes(3)
	})
	it("a failed extraction leaves the message unseen for retry", async () => {
		mockExtractionFetch(extractions, { failFor: "thanks, looks good" })
		const ledger = createLedger()
		const res = await syncLedger({ refs, ledger, endpoint: EP, maxCalls: 3 })
		expect(res.pending).toBe(1) // m2 failed, stays unseen
		expect(ledger.seen.has("m2")).toBe(false)
		expect(ledger.grants).toHaveLength(1) // m1 still folded
	})
	it("messages beyond backfillLimit are skipped permanently without calls", async () => {
		const { fn } = mockExtractionFetch(extractions)
		const many = Array.from({ length: 10 }, (_, i) => ({ id: `x${i}`, seq: i, text: `filler ${i}` }))
		const ledger = createLedger()
		const res = await syncLedger({ refs: many, ledger, endpoint: EP, maxCalls: 20, backfillLimit: 3 })
		expect(fn).toHaveBeenCalledTimes(3) // only the newest 3
		expect(res.pending).toBe(0)
		expect(ledger.seen.size).toBe(10)
	})
})
