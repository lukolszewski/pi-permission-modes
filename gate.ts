/**
 * The auto-mode gate pipeline (docs/CLASSIFIER-SPEC.md §1–§4):
 *
 *   layer 0  evaluateToolCall (deterministic policy)
 *   layer 1a session grants (prompt-once memory)
 *   layer 1b transcript authorisation (model extract + code verify)   [ASK only]
 *   layer 1c effect classification (model)                            [UNKNOWN only]
 *
 * Returns a GateResult; the caller (index.ts) renders prompts/denials.
 * No UI, no pi imports — testable end to end against a live endpoint.
 */

import { evaluateToolCall, type Entity, type PolicyDecision, type PolicyOptions } from "./risk-policy.ts"
import { verifyGrant, type GrantExtraction } from "./grant-verify.ts"
import {
	classifyEffect,
	effectToTier,
	extractGrant,
	type EffectClassification,
	type ModelCallResult,
	type ModelEndpoint,
} from "./model-client.ts"
import { addGrant, grantsCover, type GrantStore } from "./session-grants.ts"
import { ledgerCovers, type Ledger } from "./auth-ledger.ts"

export type GateOutcome =
	| "allow"            // run it, no user involvement
	| "allow-granted"    // run it, authorised by transcript or session grant
	| "prompt"           // needs the user (ASK, not authorised)
	| "prompt-never"     // needs the user, loud warning, not pre-authorisable
export type GateResult = {
	outcome: GateOutcome
	tier: "allow" | "ask" | "never"
	category: string
	entities: Entity[]
	description: string
	/** Why (for the prompt / denial message / log). */
	reason: string
	/** Grant source when outcome is allow-granted. */
	grantedBy?: "session-grant" | "ledger" | "transcript"
	policy: PolicyDecision
	modelCalls: Array<{ task: "grant" | "effect"; ms: number; ok: boolean; error?: string; raw?: string }>
}

export type GateOptions = {
	policy: PolicyOptions
	endpoint?: ModelEndpoint
	grants?: GrantStore
	/** Authorisation ledger (kept in sync by the caller via syncLedger). */
	ledger?: Ledger
	/** Recent user messages, oldest first (already redacted/limited by caller). */
	userMessages?: string[]
	signal?: AbortSignal
	debug?: (line: string) => void
}

// Recent-window fallback only — long-range authorisation lives in the ledger,
// so the window no longer has to carry the whole session (it can't anyway).
const MAX_USER_MSGS = 60
const MAX_USER_CHARS = 15000

export function limitUserMessages(msgs: string[]): string[] {
	let out = msgs.slice(-MAX_USER_MSGS)
	let total = out.reduce((n, m) => n + m.length, 0)
	while (out.length > 1 && total > MAX_USER_CHARS) {
		total -= out[0]!.length
		out = out.slice(1)
	}
	return out.map((m) => (m.length > 2000 ? m.slice(0, 2000) + "…" : m))
}

export async function runGate(tool: string, input: Record<string, unknown>, opts: GateOptions): Promise<GateResult> {
	const modelCalls: GateResult["modelCalls"] = []
	const dbg = opts.debug ?? (() => {})
	let policy = evaluateToolCall(tool, input, opts.policy)
	dbg(`[gate] layer0: ${policy.tier} ${policy.category} — ${policy.description}`)

	// ---- resolve UNKNOWN segments via effect classification
	if (policy.tier === "unknown") {
		if (!opts.endpoint) {
			return finish("prompt", "ask", policy, `cannot classify locally and no classifier endpoint configured`, modelCalls)
		}
		// classify each unknown segment; the worst result wins
		let worst: { tier: "allow" | "ask" | "never"; category: string } = { tier: "allow", category: "read_only" }
		const targets: Entity[] = [...policy.entities]
		for (const u of policy.unknown) {
			const res: ModelCallResult<EffectClassification> = await classifyEffect(
				opts.endpoint,
				{ command: u.command, inlineCode: u.inlineCode, cwd: opts.policy.cwd, project: opts.policy.project ?? opts.policy.cwd },
				opts.signal,
			)
			modelCalls.push({ task: "effect", ms: res.ms, ok: res.ok, error: res.ok ? undefined : res.error, raw: res.ok ? res.raw : res.raw })
			if (!res.ok) {
				dbg(`[gate] effect call failed: ${res.error}`)
				return finish("prompt", "ask", policy, `classifier unavailable (${res.error}); confirmation required`, modelCalls)
			}
			const mapped = effectToTier(res.value)
			dbg(`[gate] effect: ${u.command.slice(0, 60)} → ${res.value.effect}/${res.value.confidence} → ${mapped.tier}`)
			for (const t of res.value.targets) targets.push({ kind: "target", value: t })
			if (rank(mapped.tier) > rank(worst.tier)) worst = mapped
		}
		// merge with the non-unknown part of the policy decision
		const residualTier = policy.segments.filter((s) => s.tier !== "unknown").reduce<"allow" | "ask" | "never">((acc, s) => (rank(s.tier as never) > rank(acc) ? (s.tier as never) : acc), "allow")
		const finalTier = rank(worst.tier) > rank(residualTier) ? worst.tier : residualTier
		policy = {
			...policy,
			tier: finalTier,
			category: finalTier === worst.tier ? worst.category : policy.category,
			entities: dedupe(targets),
		}
		if (finalTier === "allow") return finish("allow", "allow", policy, "classified as project-scoped/read-only", modelCalls)
	}

	if (policy.tier === "allow") return finish("allow", "allow", policy, policy.reason, modelCalls)
	if (policy.tier === "never") {
		return finish("prompt-never", "never", policy, policy.description, modelCalls)
	}

	// ---- ASK: session grants first
	if (opts.grants) {
		const cover = grantsCover(opts.grants, policy.category, policy.entities)
		if (cover.covered) {
			dbg(`[gate] session grant covers: ${cover.by.join(", ")}`)
			return finish("allow-granted", "ask", policy, `covered by earlier approval (${cover.by.join(", ")})`, modelCalls, "session-grant")
		}
	}

	// ---- ASK: authorisation ledger (whole-session memory, pure code)
	if (opts.ledger) {
		const lv = ledgerCovers(opts.ledger, policy.category, policy.entities)
		if (lv.covered) {
			dbg(`[gate] ledger covers: ${lv.reason}`)
			// promote to a session grant so repeats skip even the ledger scan
			if (opts.grants) {
				for (const m of lv.by) addGrant(opts.grants, policy.category, m.entity, "entity")
			}
			return finish("allow-granted", "ask", policy, lv.reason, modelCalls, "ledger")
		}
		if (lv.forbidden) {
			// an explicit revocation outrules the recent-window fallback: a stale
			// grant still inside the window must not overrule "stop doing X"
			dbg(`[gate] ledger forbids: ${lv.reason}`)
			return finish("prompt", "ask", policy, lv.reason, modelCalls)
		}
	}

	// ---- ASK: transcript authorisation
	const userMessages = limitUserMessages(opts.userMessages ?? [])
	if (opts.endpoint && userMessages.length > 0) {
		const res: ModelCallResult<GrantExtraction> = await extractGrant(
			opts.endpoint,
			{
				userMessages,
				description: policy.description,
				category: policy.category,
				entities: policy.entities,
				command: policy.segments.map((s) => s.command).filter(Boolean)[0] ?? "",
			},
			opts.signal,
		)
		modelCalls.push({ task: "grant", ms: res.ms, ok: res.ok, error: res.ok ? undefined : res.error, raw: res.ok ? res.raw : res.raw })
		if (res.ok) {
			const verdict = verifyGrant({ extraction: res.value, category: policy.category, entities: policy.entities, userMessages })
			dbg(`[gate] grant: model=${res.value.authorized} verified=${verdict.granted} — ${verdict.reason}`)
			if (verdict.granted) {
				// persist so the identical action does not re-pay the model call
				if (opts.grants) {
					for (const m of verdict.matches) addGrant(opts.grants, policy.category, m.entity, "entity")
				}
				return finish("allow-granted", "ask", policy, verdict.reason, modelCalls, "transcript")
			}
			return finish("prompt", "ask", policy, verdict.reason, modelCalls)
		}
		dbg(`[gate] grant call failed: ${res.error}`)
		return finish("prompt", "ask", policy, `needs confirmation (classifier unavailable: ${res.error})`, modelCalls)
	}

	return finish("prompt", "ask", policy, policy.description, modelCalls)
}

function rank(t: "allow" | "ask" | "never" | "unknown"): number {
	return t === "allow" ? 0 : t === "unknown" ? 1 : t === "ask" ? 2 : 3
}

function dedupe(list: Entity[]): Entity[] {
	const seen = new Set<string>()
	return list.filter((e) => {
		const k = `${e.kind}:${e.value}`
		if (seen.has(k) || !e.value) return false
		seen.add(k)
		return true
	})
}

function finish(
	outcome: GateOutcome,
	tier: "allow" | "ask" | "never",
	policy: PolicyDecision,
	reason: string,
	modelCalls: GateResult["modelCalls"],
	grantedBy?: "session-grant" | "transcript",
): GateResult {
	return {
		outcome,
		tier,
		category: policy.category,
		entities: policy.entities,
		description: policy.description,
		reason,
		grantedBy,
		policy,
		modelCalls,
	}
}
