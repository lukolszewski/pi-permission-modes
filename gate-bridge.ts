/**
 * Bridge between pi (index.ts) and the v3 gate pipeline (gate.ts).
 * Pure helpers: endpoint resolution, user-message extraction, prompt labels.
 */

import { redactForClassifier } from "./classifier-redact.ts"
import { parseModelRef, type ClassifierRegistry } from "./classifier-client.ts"
import type { ClassifierConfig } from "./config.ts"
import { extractMessageGrants, type ModelEndpoint } from "./model-client.ts"
import type { GateResult } from "./gate.ts"
import { applyEvents, eventsFromExtraction, type Ledger } from "./auth-ledger.ts"

/** Extract user text messages (oldest first) from a pi session branch. */
export function collectUserMessagesFromBranch(
	branch: Array<{ type?: string; message?: { role?: string; content?: unknown } }>,
): string[] {
	const out: string[] = []
	for (const entry of branch) {
		if (entry?.type !== "message") continue
		const msg = entry.message
		if (msg?.role !== "user") continue
		const content = msg.content
		if (typeof content === "string") {
			if (content.trim()) out.push(redactForClassifier(content.trim(), 4000))
			continue
		}
		if (!Array.isArray(content)) continue
		for (const block of content) {
			if ((block as { type?: string })?.type === "text") {
				const t = String((block as { text?: string }).text ?? "").trim()
				// Skip tool-result-shaped payloads that some flows store as user text.
				if (t && !t.startsWith("<tool_result")) out.push(redactForClassifier(t, 4000))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- ledger sync

export type UserMessageRef = {
	/** Branch entry id, or a synthetic stable "#<index>" when pi gives none. */
	id: string
	/** Branch ordinal — the ledger's `seq` (revocation precedence). */
	seq: number
	text: string
}

/** User messages WITH identity and branch position, for ledger extraction.
 *  Same filtering as collectUserMessagesFromBranch (redaction, tool-result skip). */
export function collectUserMessageRefs(
	branch: Array<{ type?: string; id?: string; message?: { role?: string; content?: unknown } }>,
): UserMessageRef[] {
	const out: UserMessageRef[] = []
	for (let i = 0; i < branch.length; i++) {
		const entry = branch[i]!
		if (entry?.type !== "message" || entry.message?.role !== "user") continue
		const content = entry.message.content
		const parts: string[] = []
		if (typeof content === "string") {
			if (content.trim()) parts.push(content.trim())
		} else if (Array.isArray(content)) {
			for (const block of content) {
				if ((block as { type?: string })?.type === "text") {
					const t = String((block as { text?: string }).text ?? "").trim()
					if (t && !t.startsWith("<tool_result")) parts.push(t)
				}
			}
		}
		if (!parts.length) continue
		out.push({
			id: typeof entry.id === "string" && entry.id ? entry.id : `#${i}`,
			seq: i,
			text: redactForClassifier(parts.join("\n"), 4000),
		})
	}
	return out
}

export type SyncLedgerResult = {
	/** Extraction calls made this invocation. */
	processed: number
	/** Unseen messages still waiting (drain via background backfill). */
	pending: number
	/** Whether the ledger changed (caller persists a snapshot). */
	changed: boolean
}

/**
 * Fold unseen user messages into the ledger, newest-first
 * (proper-permission-ledger.md §2.2/§2.6). `maxCalls` bounds this invocation
 * (≤2 inline before a tool call; larger for a background drain step). Messages
 * beyond `backfillLimit` (counted from the newest) are marked seen without
 * extraction — they fall back to the targeted call / prompt path. A failed
 * extraction leaves the message unseen so the next invocation retries;
 * worst case is a prompt, never a false allow.
 */
export async function syncLedger(opts: {
	refs: UserMessageRef[]
	ledger: Ledger
	endpoint: ModelEndpoint
	maxCalls: number
	backfillLimit?: number
	signal?: AbortSignal
	debug?: (line: string) => void
}): Promise<SyncLedgerResult> {
	const { refs, ledger, endpoint } = opts
	const dbg = opts.debug ?? (() => {})
	const limit = opts.backfillLimit ?? 400
	let changed = false

	const unseen = refs.filter((r) => !ledger.seen.has(r.id))
	// beyond-cap messages (older than the newest `limit`): skip permanently
	if (unseen.length > limit) {
		const skipped = unseen.slice(0, unseen.length - limit)
		for (const r of skipped) ledger.seen.add(r.id)
		changed = true
		dbg(`[gate] ledger: skipped ${skipped.length} messages beyond backfill limit ${limit}`)
	}
	const queue = unseen.slice(-limit).reverse() // newest first
	let processed = 0
	for (const r of queue) {
		if (processed >= opts.maxCalls) break
		if (opts.signal?.aborted) break
		const res = await extractMessageGrants(endpoint, r.text, opts.signal)
		processed++
		if (!res.ok) {
			dbg(`[gate] ledger: extraction failed for ${r.id}: ${res.error}`)
			continue // stays unseen → retried next invocation
		}
		const events = eventsFromExtraction(res.value, r.id, r.seq, r.text)
		applyEvents(ledger, events)
		ledger.seen.add(r.id)
		changed = true
		if (events.length) {
			dbg(`[gate] ledger: ${r.id} → ${events.map((e) => `${e.type}:${e.category}:${e.value}`).join(", ")}`)
		}
	}
	const pending = refs.filter((r) => !ledger.seen.has(r.id)).length
	return { processed, pending, changed }
}

/**
 * Resolve the HTTP endpoint for the gate's model calls.
 * Priority: explicit classifier.baseUrl override → pi model registry entry.
 */
export async function resolveGateEndpoint(
	config: ClassifierConfig & { baseUrl?: string; modelId?: string },
	registry: ClassifierRegistry | undefined,
): Promise<ModelEndpoint | undefined> {
	if (!config.enabled) return undefined
	if (config.baseUrl) {
		return {
			baseUrl: config.baseUrl,
			model: config.modelId ?? config.model.split("/").pop() ?? config.model,
			timeoutMs: config.timeoutMs,
		}
	}
	if (!registry) return undefined
	const parsed = parseModelRef(config.model)
	if (!parsed) return undefined
	const model = registry.find(parsed.provider, parsed.modelId) as
		| { baseUrl?: string; id?: string }
		| undefined
	if (!model?.baseUrl) return undefined
	try {
		const auth = await registry.getApiKeyAndHeaders(model as never)
		if (!auth.ok) return undefined
		return {
			baseUrl: model.baseUrl,
			model: model.id ?? parsed.modelId,
			apiKey: auth.apiKey,
			headers: auth.headers,
			timeoutMs: config.timeoutMs,
		}
	} catch {
		return undefined
	}
}

/** One-line label for the approval prompt. */
export function gatePromptLabel(r: GateResult): string {
	const ents = r.entities
		.filter((e) => e.kind === "target")
		.map((e) => e.value)
		.slice(0, 4)
	const entStr = ents.length ? ` [${ents.join(", ")}]` : ""
	if (r.tier === "never") {
		return `⛔ HIGH RISK — ${r.description}${entStr}. This action is never auto-approved.`
	}
	return `${r.description}${entStr} — ${r.reason}`
}

/** Denial message sent back to the agent when there is no UI or the user blocks. */
export function gateDenialMessage(r: GateResult): string {
	const ents = r.entities.filter((e) => e.kind === "target").map((e) => e.value).slice(0, 6)
	const head = r.tier === "never"
		? `Blocked (high-risk, never auto-approved): ${r.description}.`
		: `Not auto-approved: ${r.description}.`
	const why = r.reason && r.reason !== r.description ? ` Reason: ${r.reason}.` : ""
	const what = ents.length ? ` Affected: ${ents.join(", ")}.` : ""
	const hint = r.tier === "never"
		? " Ask the user to run this themselves or to approve it explicitly in the UI."
		: " Ask the user for approval, naming the exact target(s), or proceed differently."
	return `${head}${why}${what}${hint}`
}
