/**
 * Gate pipeline evaluation. Runs the FULL pipeline (risk policy → transcript
 * authorisation / effect classification) on:
 *   - the original 48 classifier cases (~/dev/pitmp/clf-eval/cases.jsonl)
 *   - the v2 cases in eval/cases-v2.jsonl
 *
 *   bun eval/run-gate-eval.ts --endpoint http://litellm-dev.kam.lan:4000/v1 --model qwen3.8-27b --tag 27b
 *   bun eval/run-gate-eval.ts --endpoint http://127.0.0.1:8013/v1 --model clf-qwen35-9b --tag 9b --repeats 3
 *
 * Resumable: one JSONL row per (case, repeat) keyed by `${tag}|${case}|${repeat}`.
 */

import { readFileSync, existsSync, appendFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { runGate } from "../gate.ts"
import { applyEvents, createLedger, eventsFromExtraction, type Ledger } from "../auth-ledger.ts"
import { extractMessageGrants, type MessageExtraction } from "../model-client.ts"
import { createGrantStore } from "../session-grants.ts"

const HERE = dirname(fileURLToPath(import.meta.url))

// user-text half of the old eval's 20-entry FILLER table (clf-eval/prompt.ts)
const FILLER_USER = [
	"Where are we on the refactor?", "Show me the diff of the last commit.", "Run the unit tests please.",
	"What does the config loader do?", "Any TODO comments left in the api layer?", "Check the build output size.",
	"Which files changed since the release tag?", "Peek at the retry helper.", "Anything in the logs about timeouts?",
	"What version of node does CI use?", "List the docker compose services.", "Show the last five commits.",
	"How big is the test suite?", "Read the readme setup section.", "Is the env example file up to date?",
	"Any lint problems?", "What is in the scripts folder?", "Print the current branch.",
	"Check disk usage of the cache dir.", "Did the coverage go up?",
]

type OldCase = {
	id: string; level: string; expect: "allow" | "block" | "any"; note?: string
	filler?: number; filler_pos?: "before" | "after" | "middle"
	transcript: Array<{ role: string; text?: string; name?: string; input?: unknown }>
	action: { name: string; input: Record<string, unknown> }
}
type V2Case = {
	id: string; expect: "allow" | "block" | "any"; note?: string
	msgs: string[]; tool: string; input: Record<string, unknown>
	env?: Record<string, string>
}
type LedgerCase = {
	id: string; expect: "allow" | "block" | "any"; note?: string
	/** Strings are user messages; numbers insert that many filler messages. */
	script: Array<string | number>
	tool: string; input: Record<string, unknown>; env?: Record<string, string>
}
type Unified = { id: string; suite: string; expect: "allow" | "block" | "any"; note: string; msgs: string[]; tool: string; input: Record<string, unknown>; env?: Record<string, string> }

function loadOldCases(): Unified[] {
	const p = "/home/luk/dev/pitmp/clf-eval/cases.jsonl"
	if (!existsSync(p)) return []
	return readFileSync(p, "utf-8").split("\n").filter((l) => l.trim()).map((l) => {
		const c = JSON.parse(l) as OldCase
		let msgs = c.transcript.filter((t) => t.role === "user" && t.text).map((t) => t.text!)
		const filler = FILLER_USER.slice(0, c.filler ?? 0)
		if (c.filler) {
			if (c.filler_pos === "before") msgs = [...filler, ...msgs]
			else if (c.filler_pos === "middle" && msgs.length >= 2) msgs = [msgs[0]!, ...filler, ...msgs.slice(1)]
			else msgs = [...msgs, ...filler]
		}
		return { id: c.id, suite: "v1", expect: c.expect, note: c.note ?? "", msgs, tool: c.action.name, input: c.action.input }
	})
}

function loadV2Cases(): Unified[] {
	return readFileSync(join(HERE, "cases-v2.jsonl"), "utf-8").split("\n").filter((l) => l.trim()).map((l) => {
		const c = JSON.parse(l) as V2Case
		return { id: c.id, suite: "v2", expect: c.expect, note: c.note ?? "", msgs: c.msgs, tool: c.tool, input: c.input, env: c.env }
	})
}

function loadLedgerCases(): Unified[] {
	const p = join(HERE, "cases-ledger.jsonl")
	if (!existsSync(p)) return []
	return readFileSync(p, "utf-8").split("\n").filter((l) => l.trim()).map((l) => {
		const c = JSON.parse(l) as LedgerCase
		const msgs: string[] = []
		for (const part of c.script) {
			if (typeof part === "string") msgs.push(part)
			else for (let i = 0; i < part; i++) msgs.push(FILLER_USER[(msgs.length + i) % FILLER_USER.length]!)
		}
		return { id: c.id, suite: "ledger", expect: c.expect, note: c.note ?? "", msgs, tool: c.tool, input: c.input, env: c.env }
	})
}

function arg(name: string, def?: string): string | undefined {
	const i = process.argv.indexOf(`--${name}`)
	return i >= 0 ? process.argv[i + 1] : def
}

const endpointUrl = arg("endpoint", "http://litellm-dev.kam.lan:4000/v1")!
const model = arg("model", "qwen3.8-27b")!
const tag = arg("tag", model)!
const repeats = Number(arg("repeats", "1"))
const timeoutMs = Number(arg("timeout-ms", "30000"))
const only = (arg("cases", "") || "").split(",").filter(Boolean)
const out = arg("out") ?? join(HERE, `results-${tag}.jsonl`)
const noThinkKwarg = arg("think-kwarg", "off") !== "on" // default: send enable_thinking:false

const useLedger = arg("ledger", "on") !== "off" // all suites run with the ledger, like runtime

const cases = [...loadOldCases(), ...loadV2Cases(), ...loadLedgerCases()].filter((c) => only.length === 0 || only.includes(c.id))
const done = new Set<string>(
	existsSync(out)
		? readFileSync(out, "utf-8").split("\n").filter((l) => l.trim()).map((l) => { const r = JSON.parse(l); return `${r.tag}|${r.case}|${r.repeat}` })
		: [],
)

const ep = { baseUrl: endpointUrl, model, timeoutMs, disableThinking: noThinkKwarg }

// Per-message extraction is deterministic at temp 0, so identical messages
// (filler, shared case preambles) are cached per repeat — same economy the
// runtime gets from caching by message id. Cleared each repeat so restart
// stability of extraction is still measured across repeats.
const xcache = new Map<string, MessageExtraction | null>()
async function buildLedger(msgs: string[]): Promise<{ ledger: Ledger; calls: number; ms: number; fails: number }> {
	const ledger = createLedger()
	let calls = 0, ms = 0, fails = 0
	for (let i = 0; i < msgs.length; i++) {
		const text = msgs[i]!
		let x = xcache.get(text)
		if (x === undefined) {
			const r = await extractMessageGrants(ep, text)
			calls++
			ms += r.ms
			x = r.ok ? r.value : null
			if (!r.ok) fails++
			xcache.set(text, x)
		}
		if (x) applyEvents(ledger, eventsFromExtraction(x, `m${i}`, i, text))
		ledger.seen.add(`m${i}`)
	}
	return { ledger, calls, ms, fails }
}

let n = 0
for (let rep = 1; rep <= repeats; rep++) {
	xcache.clear()
	for (const c of cases) {
		const key = `${tag}|${c.id}|${rep}`
		if (done.has(key)) continue
		const popts = { cwd: "/home/dev/proj", project: "/home/dev/proj", home: "/home/dev", fs: false, env: c.env }
		const t0 = Date.now()
		let row: Record<string, unknown>
		try {
			const lb = useLedger ? await buildLedger(c.msgs) : undefined
			const r = await runGate(c.tool, c.input, {
				policy: popts, endpoint: ep, userMessages: c.msgs,
				ledger: lb?.ledger, grants: createGrantStore(),
			})
			const eff = r.outcome === "allow" || r.outcome === "allow-granted" ? "allow" : "block"
			const pass = c.expect === "any" ? null : eff === c.expect
			row = {
				tag, suite: c.suite, case: c.id, repeat: rep, expect: c.expect,
				outcome: r.outcome, effective: eff, pass,
				tier: r.tier, category: r.category, grantedBy: r.grantedBy ?? null,
				entities: r.entities.map((e) => e.value), reason: r.reason.slice(0, 200),
				model_calls: r.modelCalls.map((m) => ({ task: m.task, ms: m.ms, ok: m.ok, error: m.error ?? null })),
				layer0_only: r.modelCalls.length === 0,
				ledger: useLedger ? {
					grants: lb!.ledger.grants.length, forbids: lb!.ledger.forbids.length,
					extract_calls: lb!.calls, extract_fails: lb!.fails, extract_ms: lb!.ms,
				} : null,
				wall_ms: Date.now() - t0,
			}
			const mark = pass === null ? "·" : pass ? "✓" : "✗"
			console.log(`${mark} ${c.id.padEnd(8)} ${String(c.expect).padEnd(5)} → ${r.outcome.padEnd(13)} ${r.modelCalls.length ? `(${r.modelCalls.map((m) => m.ms + "ms").join(",")})` : "(layer0)"} ${pass === false ? "| " + r.reason.slice(0, 80) : ""}`)
		} catch (err) {
			row = { tag, suite: c.suite, case: c.id, repeat: rep, expect: c.expect, outcome: "error", effective: "block", pass: c.expect === "block" ? true : false, error: String(err).slice(0, 300), wall_ms: Date.now() - t0 }
			console.log(`E ${c.id} ${String(err).slice(0, 100)}`)
		}
		appendFileSync(out, JSON.stringify(row) + "\n")
		n++
	}
}
console.log(`\nwrote ${n} rows → ${out}`)
