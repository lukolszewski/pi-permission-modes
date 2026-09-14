/**
 * Bridge between pi (index.ts) and the v3 gate pipeline (gate.ts).
 * Pure helpers: endpoint resolution, user-message extraction, prompt labels.
 */

import { redactForClassifier } from "./classifier-redact.ts"
import { parseModelRef, type ClassifierRegistry } from "./classifier-client.ts"
import type { ClassifierConfig } from "./config.ts"
import type { ModelEndpoint } from "./model-client.ts"
import type { GateResult } from "./gate.ts"

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
