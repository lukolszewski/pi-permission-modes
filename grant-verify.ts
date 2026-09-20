/**
 * Code-side verification of transcript authorisation (docs/CLASSIFIER-SPEC.md §3.3, §4.2).
 *
 * The model only *extracts* what the user allowed/forbade; nothing it says can
 * widen an approval past these checks. All matching is deterministic.
 */

import type { Entity } from "./risk-policy.ts"

export type GrantExtraction = {
	authorized: "yes" | "no"
	allowed_targets: string[]
	forbidden_targets: string[]
	quote: string
}

export type GrantVerdict = {
	granted: boolean
	reason: string
	/** Which pending entities matched which allowed target (for the log/UI). */
	matches: Array<{ entity: string; target: string }>
}

/** Categories where a bare verb ("push it", "clean the build dir") is a complete
 *  instruction, so an empty allowed_targets list with a verb-bearing quote may grant. */
export const BARE_VERB_CATEGORIES: Record<string, RegExp> = {
	vcs_remote: /\b(push|publish|pr|pull request|release)\b/i,
	vcs_discard: /\b(reset|discard|clean|throw away|revert|undo)\b/i,
	delete_recursive: /\b(delete|remove|clean|clear|wipe|rm)\b/i,
	delete_data: /\b(delete|remove|clean|clear|rm)\b/i,
	package_system: /\b(install|apt|brew|dnf|yum|pacman|upgrade|update)\b/i,
	privilege: /\b(sudo|root|elevated|admin|privileg)\b/i,
	process_control: /\b(kill|stop|restart|terminate)\b/i,
	network_listen: /\b(serve|server|listen|host|port|start)\b/i,
	system_config: /\b(restart|enable|disable|start|stop|service|daemon|systemctl|firewall|mount)\b/i,
	interactive_editor: /\b(open|edit|editor|vim|nano)\b/i,
	remote_exec: /\b(curl|wget|installer|install script|bash|\bsh\b|download|pipe)\b/i,
}

/** Categories where naming the entity is NOT the same as approving the method:
 *  the quote must also carry the action verb ("ripgrep is missing" names ripgrep
 *  but does not approve a system-wide install). */
export const METHOD_VERB_REQUIRED = new Set([
	"package_system", "privilege", "remote_exec", "network_listen",
])

/** Normalise whitespace + case + strip surrounding punctuation/quotes. */
function norm(s: string): string {
	return s.trim().toLowerCase().replace(/^["'`([{]+|["'`)\]}.,;:!?]+$/g, "")
}

/** Split an entity/target into path-ish components: a/b@c:d → [a,b,c,d]. */
function components(s: string): string[] {
	return norm(s)
		.replace(/^s3:\/\//, "")
		.replace(/^[a-z]+:\/\//, "")
		.split(/[\/@:,\s]+/)
		.map((x) => x.replace(/^\.+|\.+$/g, "").trim())
		.filter(Boolean)
}

/** Variants of a target we search for in the user's own words. */
function targetVariants(t: string): string[] {
	const n = norm(t)
	const out = new Set<string>([n])
	out.add(n.replace(/^\.\//, "").replace(/\/$/, ""))
	out.add(n.replace(/^~\//, ""))
	const parts = n.split("/").filter(Boolean)
	if (parts.length > 1) out.add(parts[parts.length - 1]!)
	return [...out].filter((v) => v.length >= 2)
}

const PHRASE_STOPWORDS = new Set([
	"the", "a", "an", "in", "on", "of", "to", "my", "our", "this", "that", "and", "or",
	"dir", "directory", "folder", "file", "files", "prefix", "bucket", "image", "images",
	"branch", "table", "tables", "namespace", "pod", "pods", "container", "release",
	"repo", "repository", "package", "service", "db", "database", "whole", "entire", "only",
])

const WORD_CHAR = /[a-z0-9_-]/i

/** Does `needle` occur in `hay` as a whole token (no identifier char hugging either end)? */
function occursWholeToken(hay: string, needle: string): boolean {
	let idx = 0
	for (;;) {
		const i = hay.indexOf(needle, idx)
		if (i === -1) return false
		const before = i === 0 ? "" : hay[i - 1]!
		const after = i + needle.length >= hay.length ? "" : hay[i + needle.length]!
		const beforeOk = !before || !WORD_CHAR.test(before)
		const afterOk = !after || !(WORD_CHAR.test(after) && WORD_CHAR.test(needle[needle.length - 1]!))
		if (beforeOk && afterOk) return true
		idx = i + 1
	}
}

/** The model must not invent targets: an allowed target counts only if the user
 *  actually wrote it (whole-token, case-insensitive) in some message. */
export function targetNamedByUser(targetName: string, userMessages: string[]): boolean {
	const hays = userMessages.map((m) => m.replace(/\s+/g, " ").toLowerCase())
	return targetVariants(targetName).some((v) => hays.some((hay) => occursWholeToken(hay, v)))
}

/** Whole-token match between a pending entity and one user-named target.
 *  `db-backup` ≠ `db-backup-test`, `feature/x` ≠ `feature/x-prod`, `dev` ≠ `dev-logs`. */
export function entityMatchesTarget(entity: string, targetName: string): boolean {
	const e = norm(entity)
	const t = norm(targetName)
	if (!e || !t) return false
	if (e === t) return true
	const ec = components(entity)
	const tc = components(targetName)
	if (tc.length === 0 || ec.length === 0) return false
	// multi-component target must appear as a consecutive component run of the entity
	if (tc.length > 1) {
		for (let i = 0; i + tc.length <= ec.length; i++) {
			if (tc.every((c, j) => ec[i + j] === c)) return true
		}
		// noun-phrase target ("build dir", "dev/ prefix in the acme-data bucket"):
		// only for targets with whitespace (a phrase, not a path), and EVERY
		// content word must name a component of the entity — so "feature/x"
		// still cannot match "feature/x-prod".
		if (/\s/.test(norm(targetName))) {
			const content = tc.filter((c) => !PHRASE_STOPWORDS.has(c))
			if (content.length > 0 && content.every((c) => ec.includes(c))) return true
		}
		return false
	}
	// single-component target: match any single component of the entity
	// (namespace, image tag, table name, basename …)
	return ec.includes(tc[0]!)
}

export function verifyGrant(opts: {
	extraction: GrantExtraction
	category: string
	entities: Entity[]
	/** User messages exactly as sent to the model (for the verbatim-quote check). */
	userMessages: string[]
}): GrantVerdict {
	const { extraction, category, entities, userMessages } = opts
	const no = (reason: string): GrantVerdict => ({ granted: false, reason, matches: [] })

	if (extraction.authorized !== "yes") return no("model: not authorised by the user")

	// 1. Verbatim quote check (whitespace-normalised substring of a user message).
	const q = (extraction.quote ?? "").replace(/\s+/g, " ").trim().toLowerCase()
	if (q.length < 3) return no("no supporting quote from a user message")
	const haystacks = userMessages.map((m) => m.replace(/\s+/g, " ").trim().toLowerCase())
	if (!haystacks.some((m) => m.includes(q))) return no("quote not found verbatim in any user message")

	// 2. Forbidden targets veto everything they match.
	const pending = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const checked = pending.length ? pending : entities.map((e) => e.value)
	for (const ent of checked) {
		for (const f of extraction.forbidden_targets ?? []) {
			if (entityMatchesTarget(ent, f)) {
				return no(`target "${ent}" matches user-forbidden "${f}"`)
			}
		}
	}

	// 3. Every pending entity must be covered by an allowed target.
	const primaryCategory = category.split("+")[0] ?? category
	const allowed = (extraction.allowed_targets ?? []).filter((t) => norm(t))
	if (checked.length > 0 && allowed.length > 0) {
		const matches: Array<{ entity: string; target: string }> = []
		for (const ent of checked) {
			const hit = allowed.find((t) => entityMatchesTarget(ent, t))
			if (!hit) return no(`target "${ent}" not named by the user (allowed: ${allowed.join(", ") || "none"})`)
			matches.push({ entity: ent, target: hit })
		}
		if (METHOD_VERB_REQUIRED.has(primaryCategory)) {
			const verbRe = BARE_VERB_CATEGORIES[primaryCategory]
			if (verbRe && !verbRe.test(q)) {
				return no(`user named the target but not the method (${primaryCategory}); quote lacks the action verb`)
			}
		}
		return { granted: true, reason: `user authorised: ${matches.map((m) => `${m.entity}←"${m.target}"`).join(", ")}`, matches }
	}

	// 4. No named targets — bare-verb categories only, and the quote itself must carry the verb.
	if (allowed.length === 0) {
		const verbRe = BARE_VERB_CATEGORIES[primaryCategory]
		if (!verbRe) return no(`category ${category} requires the user to name the target`)
		if (!verbRe.test(q)) return no("quote does not contain the action verb for this category")
		return { granted: true, reason: `user instruction covers the action ("${extraction.quote.slice(0, 60)}")`, matches: [] }
	}

	// allowed non-empty but the action has no entities: accept only with the verb in the quote.
	const verbReTail = BARE_VERB_CATEGORIES[primaryCategory]
	if (verbReTail && verbReTail.test(q)) {
		return { granted: true, reason: `user instruction covers the action`, matches: [] }
	}
	return no("action has no matchable targets and quote lacks the action verb")
}
