/**
 * Authorisation ledger (proper-permission-ledger.md §2): compact per-session
 * state of what the user granted or withdrew, folded from per-message
 * extraction (model-client task C). Fixes window amnesia — authorisation is
 * no longer a function of scroll position.
 *
 * Fold semantics: grants and forbids are deduped per (category, value, kind);
 * cross-type precedence is decided by `seq` AT MATCH TIME (a grant covers a
 * target only if no matching forbid has a higher seq). Insertion never
 * removes a broader entry because of a narrower later one (a "revoke all"
 * must keep blocking targets a later grant did not re-grant), so the folded
 * state is independent of processing order — which is what makes newest-first
 * background backfill safe to use while incomplete (§2.6).
 */

import type { Entity } from "./risk-policy.ts"
import {
	BARE_VERB_CATEGORIES,
	METHOD_VERB_REQUIRED,
	entityMatchesTarget,
	targetNamedByUser,
} from "./grant-verify.ts"

export type LedgerEntry = {
	/** Gate category the grant/forbid maps to; "*" = all categories (revocations);
	 *  "*<free text>*" = unmappable action, never matches (targeted fallback only). */
	category: string
	/** Normalized target, scope prefix ending in "/", or "*" for bare-verb/all. */
	value: string
	kind: "entity" | "scope"
	/** Verbatim user sentence (verified against the source message). */
	quote: string
	messageId: string
	/** Ordinal of the source message on the branch — decides precedence. */
	seq: number
	lastMatchedAt?: number
}

export type Ledger = {
	grants: LedgerEntry[]
	forbids: LedgerEntry[]
	/** Message ids already extracted (or deliberately skipped: beyond backfill cap). */
	seen: Set<string>
	/** Read-only posture from a blanket "don't change anything" (§ readonly-posture-plan).
	 *  When active, ask/unknown *mutations* are refused (allow-tier project/temp work
	 *  still proceeds). Tracked as two max-seq scalars so the fold is order-independent
	 *  and a later "you can make changes now" (higher seq) re-enables. */
	readOnlyOn?: { seq: number; quote: string }
	readOnlyOffSeq?: number
}

export type ExtractedEvent = {
	/** grant/forbid carry category+value+kind; readonly-on/off use them as "*". */
	type: "grant" | "forbid" | "readonly-on" | "readonly-off"
	category: string
	value: string
	kind: "entity" | "scope"
	quote: string
	messageId: string
	seq: number
}

/** Is the read-only posture in force right now? (latest on beats latest off.) */
export function readOnlyActive(ledger: Ledger): { quote: string; seq: number } | null {
	const on = ledger.readOnlyOn
	if (!on) return null
	if ((ledger.readOnlyOffSeq ?? -1) >= on.seq) return null
	return on
}

/** Under read-only, does a ledger grant made AFTER the posture (seq > roSeq) cover
 *  ALL pending targets? Such a later grant re-permits that specific target
 *  ("don't change anything" … later … "you can write to /x/"). A targetless
 *  mutation cannot be lifted this way — only a blanket re-enable clears it. */
export function readOnlyLiftedByGrant(ledger: Ledger, category: string, entities: Entity[], roSeq: number): boolean {
	const primary = category.split("+")[0] ?? category
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	if (targets.length === 0) return false
	return targets.every((t) =>
		ledger.grants.some((g) => g.seq > roSeq && compatible(g.category, primary) && valueCovers(g, t)),
	)
}

export const MAX_GRANTS = 200
export const MAX_FORBIDS = 100

export function createLedger(): Ledger {
	return { grants: [], forbids: [], seen: new Set() }
}

// ---------------------------------------------------------------- kind groups

/** Category → matching group (§2.4). Ledger matching compares groups, not exact
 *  categories, so "copy to /x/" also covers mkdir/mv/chmod at /x/ (deletes stay
 *  verb-gated, see ledgerCovers). */
const KIND_GROUPS: Record<string, string> = {
	write_outside: "fs-write",
	delete_outside: "fs-write",
	delete_recursive: "fs-write",
	delete_data: "fs-write",
	perm_change: "fs-write",
	package_system: "pkg",
	privilege: "priv",
	network_send: "net-send",
	vcs_remote: "vcs-remote",
	vcs_discard: "vcs-discard",
	cluster_mutation: "cluster",
	container_mutation: "cluster",
	db_mutation: "db",
	// write_project only reaches ledger matching via the named-forbid downgrade
	// (an allow-tier action the user explicitly forbade); grouping it with
	// fs-write lets a later "ok, you can delete X now" lift the forbid.
	write_project: "fs-write",
	remote_exec: "exec",
	agent_spawn: "exec",
	network_listen: "listen",
	read_secret: "secret",
	write_sensitive: "secret",
	process_control: "proc",
	system_config: "sysconf",
	interactive_editor: "editor",
}

export function kindGroup(category: string): string {
	const primary = category.split("+")[0] ?? category
	return KIND_GROUPS[primary] ?? primary
}

function compatible(entryCategory: string, pendingCategory: string): boolean {
	if (entryCategory === "*") return true
	return kindGroup(entryCategory) === kindGroup(pendingCategory)
}

const DELETE_CATEGORIES = new Set(["delete_recursive", "delete_outside", "delete_data"])
const DELETE_VERB_RE = /\b(delete|remove|rm|clean|clear|wipe|prune|drop|erase|purge)\b/i

// ---------------------------------------------------------------- action mapping

/** Free-text `action` from extraction → gate category. Ordered: domain nouns
 *  before generic verbs ("delete the pod" is cluster, not fs). Unmappable →
 *  undefined; caller stores "*text*" which never matches (fallback-only). */
const ACTION_MAP: Array<[RegExp, string]> = [
	[/\b(kubectl|k8s|kubernetes|namespace|pod|deployment|statefulset|helm|cluster)\b/i, "cluster_mutation"],
	[/\b(docker|container|image)s?\b/i, "container_mutation"],
	[/\b(table|database|db|sql|schema|collection|redis)\b/i, "db_mutation"],
	[/\b(push|force-push|publish|release|pull request|\bpr\b)\b/i, "vcs_remote"],
	[/\b(discard|reset --hard|stash drop|revert)\b/i, "vcs_discard"],
	[/\b(install|uninstall|apt|apt-get|brew|dnf|yum|pacman|pip|npm|package)\b/i, "package_system"],
	[/\b(sudo|root|privilege|elevated)\b/i, "privilege"],
	[/\b(installer|curl.*\|.*(bash|sh)|download.*(run|execute)|remote script)\b/i, "remote_exec"],
	[/\b(serve|server|listen|listener|tunnel|expose|port)\b/i, "network_listen"],
	[/\b(upload|send|post|transfer|exfil)\b/i, "network_send"],
	[/\b(kill|restart|stop|terminate)\b/i, "process_control"],
	[/\b(systemctl|firewall|mount|sysctl|cron|service)\b/i, "system_config"],
	[/\b(ssh|remote host|connect)\b/i, "remote_exec"],
	[/\b(secret|credential|token|\.env|key)\b/i, "read_secret"],
	[/\b(chmod|chown|permission)\b/i, "perm_change"],
	[/\b(delete|remove|rm\b|erase|wipe|clean|clear|purge)\b/i, "delete_outside"],
	[/\b(write|create|mkdir|copy|cp\b|move|mv\b|rsync|save|put|store|work in|extract)\b/i, "write_outside"],
]

export function mapActionToCategory(action: string): string | undefined {
	for (const [re, cat] of ACTION_MAP) if (re.test(action)) return cat
	return undefined
}

// ---------------------------------------------------------------- fold / insert

function normValue(v: string): string {
	return v.trim().toLowerCase().replace(/^["'`]+|["'`.,;:!?]+$/g, "")
}

function sameKey(a: LedgerEntry, b: ExtractedEvent | LedgerEntry): boolean {
	return a.category === b.category && normValue(a.value) === normValue(b.value) && a.kind === b.kind
}

/** Apply one extracted event under the seq-aware dedup rule. Same-key entries
 *  (in either list) keep only the highest seq; broader/partial overlaps are
 *  BOTH kept and resolved by seq at match time. */
export function applyEvent(ledger: Ledger, ev: ExtractedEvent): void {
	if (ev.type === "readonly-on") {
		if (!ledger.readOnlyOn || ev.seq > ledger.readOnlyOn.seq) {
			ledger.readOnlyOn = { seq: ev.seq, quote: ev.quote }
		}
		return
	}
	if (ev.type === "readonly-off") {
		ledger.readOnlyOffSeq = Math.max(ledger.readOnlyOffSeq ?? -1, ev.seq)
		return
	}
	if (!ev.value || !ev.category) return
	const mine = ev.type === "grant" ? ledger.grants : ledger.forbids
	const other = ev.type === "grant" ? ledger.forbids : ledger.grants

	// exact-key flip-flop against the opposite list: higher seq wins, O(1) per key
	const twinIdx = other.findIndex((e) => sameKey(e, ev))
	if (twinIdx >= 0) {
		if (other[twinIdx]!.seq >= ev.seq) return // newer contradiction already present
		other.splice(twinIdx, 1)
	}

	const dupIdx = mine.findIndex((e) => sameKey(e, ev))
	if (dupIdx >= 0) {
		if (mine[dupIdx]!.seq < ev.seq) {
			mine[dupIdx] = { ...mine[dupIdx]!, quote: ev.quote, messageId: ev.messageId, seq: ev.seq }
		}
		return
	}
	mine.push({ category: ev.category, value: ev.value, kind: ev.kind, quote: ev.quote, messageId: ev.messageId, seq: ev.seq })
	enforceCaps(ledger)
}

export function applyEvents(ledger: Ledger, events: ExtractedEvent[]): void {
	for (const ev of events) applyEvent(ledger, ev)
}

/** Eviction is fail-safe by construction: dropping a grant costs one extra
 *  prompt; forbids are evicted only from their own overflow, never for grants. */
function enforceCaps(ledger: Ledger): void {
	while (ledger.grants.length > MAX_GRANTS) {
		let worst = 0
		for (let i = 1; i < ledger.grants.length; i++) {
			const a = ledger.grants[i]!, b = ledger.grants[worst]!
			if ((a.lastMatchedAt ?? 0) < (b.lastMatchedAt ?? 0) ||
				((a.lastMatchedAt ?? 0) === (b.lastMatchedAt ?? 0) && a.seq < b.seq)) worst = i
		}
		ledger.grants.splice(worst, 1)
	}
	while (ledger.forbids.length > MAX_FORBIDS) {
		let worst = 0
		for (let i = 1; i < ledger.forbids.length; i++) {
			if (ledger.forbids[i]!.seq < ledger.forbids[worst]!.seq) worst = i
		}
		ledger.forbids.splice(worst, 1)
	}
}

// ---------------------------------------------------------------- matching

function valueCovers(entry: LedgerEntry, target: string): boolean {
	if (entry.value === "*") return true
	if (entry.kind === "scope") {
		// normalise "./x" vs "x/" before the prefix check; on miss still fall
		// through to component matching ("results/" must cover "./results")
		const s = entry.value.toLowerCase().replace(/^\.\//, "")
		const t = target.toLowerCase().replace(/^\.\//, "")
		if (s.endsWith("/") && (t.startsWith(s) || t + "/" === s)) return true
	}
	return entityMatchesTarget(target, entry.value)
}

/**
 * Named-forbid scan for ALLOW-tier actions ("do not delete X" must bind even
 * where the risk tables say allow). Considers "target" AND "path" entities
 * (allow segments mark touched files as kind "path"). Blanket forbids
 * (value "*", i.e. "stop doing risky things") are ignored here — they revoke
 * grants, they do not turn default-allowed project work into prompts. A grant
 * for the same value with a higher seq ("ok, you can delete it now") lifts
 * the forbid, category-agnostically: lifting only restores the default allow.
 */
export function namedForbidCovers(
	ledger: Ledger,
	entities: Entity[],
): { entity: string; entry: LedgerEntry } | null {
	const values = entities.filter((e) => e.kind === "target" || e.kind === "path").map((e) => e.value)
	for (const v of values) {
		let best: LedgerEntry | null = null
		for (const f of ledger.forbids) {
			if (f.value === "*") continue
			if (!valueCovers(f, v)) continue
			if (!best || f.seq > best.seq) best = f
		}
		if (!best) continue
		const lifted = ledger.grants.some((g) => g.seq > best!.seq && valueCovers(g, v))
		if (!lifted) return { entity: v, entry: best }
	}
	return null
}

export type LedgerVerdict = {
	covered: boolean
	/** A matching forbid outrules every matching grant — go straight to prompt,
	 *  do NOT let the recent-window fallback overrule an explicit revocation. */
	forbidden: boolean
	by: Array<{ entity: string; entry: LedgerEntry }>
	reason: string
}

/**
 * All target entities of the pending action must be covered by grant entries of
 * a compatible kind group, each with seq above any matching forbid. Verb gates:
 * METHOD_VERB_REQUIRED categories and (via kind-group widening) deletes require
 * the grant quote to carry the action verb.
 */
export function ledgerCovers(ledger: Ledger, category: string, entities: Entity[]): LedgerVerdict {
	const primary = category.split("+")[0] ?? category
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	const no: LedgerVerdict = { covered: false, forbidden: false, by: [], reason: "no matching ledger entry" }
	if (targets.length === 0) return no

	const needVerb = METHOD_VERB_REQUIRED.has(primary) ? BARE_VERB_CATEGORIES[primary] : undefined
	const needDeleteVerb = DELETE_CATEGORIES.has(primary)

	const by: LedgerVerdict["by"] = []
	for (const t of targets) {
		const forbidSeq = ledger.forbids
			.filter((f) => compatible(f.category, primary) && valueCovers(f, t))
			.reduce((m, f) => Math.max(m, f.seq), -1)
		const grant = ledger.grants.find((g) =>
			compatible(g.category, primary) &&
			valueCovers(g, t) &&
			g.seq > forbidSeq &&
			(!needVerb || needVerb.test(g.quote)) &&
			(!needDeleteVerb || DELETE_VERB_RE.test(g.quote)),
		)
		if (!grant) {
			if (forbidSeq >= 0) {
				const f = ledger.forbids.find((x) => x.seq === forbidSeq && compatible(x.category, primary) && valueCovers(x, t))
				return { covered: false, forbidden: true, by: [], reason: `user forbade "${t}" ("${(f?.quote ?? "").slice(0, 80)}")` }
			}
			return no
		}
		by.push({ entity: t, entry: grant })
	}
	const now = Date.now()
	for (const m of by) m.entry.lastMatchedAt = now
	return { covered: true, forbidden: false, by, reason: `ledger: ${by.map((m) => `${m.entity}←"${m.entry.value}"`).join(", ")}` }
}

// ---------------------------------------------------------------- extraction → events

export type MessageGrantExtraction = {
	grants: Array<{ action: string; targets: string[]; quote: string }>
	revocations: Array<{ action?: string; targets: string[]; all: boolean; quote: string }>
}

function quoteInMessage(quote: string, message: string): boolean {
	const q = quote.replace(/\s+/g, " ").trim().toLowerCase()
	if (q.length < 3) return false
	return message.replace(/\s+/g, " ").trim().toLowerCase().includes(q)
}

function targetKind(value: string): "entity" | "scope" {
	return value.endsWith("/") ? "scope" : "entity"
}

/** Pronouns/deixis the model sometimes emits as "targets" ("force-push it").
 *  They are not names; dropping them routes the grant into the bare-verb path. */
const PRONOUN_TARGETS = new Set([
	"it", "that", "this", "them", "these", "those", "everything", "anything",
	"all", "stuff", "things", "one",
])

/** Generic kind-words the model sometimes emits as revocation "targets"
 *  ("do not delete any images" → targets ["images"]). They are not names and
 *  can never match a concrete entity, which would silently drop the revocation
 *  — escalate to a category-wide forbid instead (fail-safe direction). */
const GENERIC_KIND_TARGETS = new Set([
	"image", "images", "container", "containers", "file", "files", "folder",
	"folders", "directory", "directories", "dir", "dirs", "table", "tables",
	"database", "databases", "db", "dbs", "branch", "branches", "package",
	"packages", "service", "services", "pod", "pods", "namespace", "namespaces",
	"repo", "repos", "repository", "repositories", "volume", "volumes", "data",
	"backup", "backups", "dump", "dumps", "server", "servers", "process",
	"processes",
])

/** Clear phrases that globally re-enable changes, lifting the read-only posture. */
const RE_ENABLE_CHANGES =
	/(?:(?:you (?:can|may)|go ahead(?: and)?|feel free to|ok(?:ay)? to|it'?s (?:ok|okay|fine) to|resume|re-?enable|allow)\b[^.]*\b(?:make changes?|changes?|modif\w*|writ\w*|edit\w*)\b)|(?:\bchanges? (?:are (?:ok|okay|fine|allowed|permitted)|enabled|allowed)\b)|(?:\b(?:no longer|not) read[- ]?only\b)/i

/**
 * Convert one message's extraction into ledger events, dropping anything the
 * code cannot verify against the message text (fail-safe: a dropped event
 * costs at most one prompt later). The extraction context is the single
 * message, so requiring targets to appear in it verbatim is sound here —
 * unlike task A, there is no pending action for the model to echo from.
 */
export function eventsFromExtraction(
	x: MessageGrantExtraction,
	messageId: string,
	seq: number,
	messageText: string,
): ExtractedEvent[] {
	const out: ExtractedEvent[] = []
	for (const g of x.grants ?? []) {
		const quote = String(g.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		const mapped = mapActionToCategory(String(g.action ?? ""))
		const category = mapped ?? `*${String(g.action ?? "").slice(0, 60)}*`
		const targets = (g.targets ?? [])
			.map(String)
			.filter((t) => t.trim().length >= 2 && !PRONOUN_TARGETS.has(t.trim().toLowerCase()))
		if (targets.length === 0) {
			// bare-verb grant ("force-push it"): only for bare-verb categories,
			// and the quote itself must carry the verb.
			if (!mapped) continue
			const verbRe = BARE_VERB_CATEGORIES[mapped]
			if (!verbRe || !verbRe.test(quote)) continue
			out.push({ type: "grant", category, value: "*", kind: "scope", quote, messageId, seq })
			continue
		}
		for (const t of targets) {
			if (!targetNamedByUser(t, [messageText])) continue
			out.push({ type: "grant", category, value: t, kind: targetKind(t), quote, messageId, seq })
		}
	}
	for (const r of x.revocations ?? []) {
		const quote = String(r.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		// a mapped action scopes an all-forbid to its kind group; unmappable → all groups
		const cat = mapActionToCategory(String(r.action ?? "")) ?? "*"
		const targets = (r.targets ?? []).map(String).filter((t) => t.trim().length >= 2)
		const named = targets.filter((t) => {
			const low = t.trim().toLowerCase()
			return !PRONOUN_TARGETS.has(low) && !GENERIC_KIND_TARGETS.has(low)
		})
		const isBlanket = r.all === true || named.length === 0
		if (isBlanket) {
			if (cat === "*") {
				// truly global "don't change anything / read-only" → session posture,
				// not a wildcard forbid row (which would match hallucinated targets and
				// report a fabricated "user forbade X").
				out.push({ type: "readonly-on", category: "*", value: "*", kind: "scope", quote, messageId, seq })
			} else {
				// mapped category with no specific target: forbid that whole category
				out.push({ type: "forbid", category: cat, value: "*", kind: "scope", quote, messageId, seq })
			}
			continue
		}
		for (const t of named) {
			if (!targetNamedByUser(t, [messageText])) continue
			// named revocations apply across all categories: "don't touch
			// ~/backups" forbids deletes AND writes AND chmod there.
			out.push({ type: "forbid", category: "*", value: t, kind: targetKind(t), quote, messageId, seq })
		}
	}
	// Blanket re-enable ("ok, you can make changes now") lifts the read-only posture.
	// Conservative phrase match, and only when no specific grant target is involved
	// (a specific grant already overrides per-target via seq). Not classification —
	// a clear re-enable phrase.
	for (const g of x.grants ?? []) {
		const quote = String(g.quote ?? "")
		if (!quoteInMessage(quote, messageText)) continue
		const hasTarget = (g.targets ?? []).some((t) => {
			const low = String(t).trim().toLowerCase()
			return low.length >= 2 && !PRONOUN_TARGETS.has(low) && !GENERIC_KIND_TARGETS.has(low)
		})
		if (!hasTarget && RE_ENABLE_CHANGES.test(quote)) {
			out.push({ type: "readonly-off", category: "*", value: "*", kind: "scope", quote, messageId, seq })
		}
	}
	return out
}

// ---------------------------------------------------------------- (de)serialize

export type SerializedLedger = {
	v: 1
	grants: LedgerEntry[]
	forbids: LedgerEntry[]
	seen: string[]
	readOnlyOn?: { seq: number; quote: string }
	readOnlyOffSeq?: number
}

export function serializeLedger(ledger: Ledger): SerializedLedger {
	return {
		v: 1,
		grants: ledger.grants,
		forbids: ledger.forbids,
		seen: [...ledger.seen],
		readOnlyOn: ledger.readOnlyOn,
		readOnlyOffSeq: ledger.readOnlyOffSeq,
	}
}

/**
 * Restore a snapshot. `validMessageIds` (current-branch membership) drops
 * entries from messages the user rewound away — a grant from an abandoned
 * branch must not survive. Unknown versions return an empty ledger (backfill
 * rebuilds deterministically).
 */
export function deserializeLedger(data: unknown, validMessageIds?: Set<string>): Ledger {
	const ledger = createLedger()
	const s = data as Partial<SerializedLedger> | undefined
	if (!s || s.v !== 1) return ledger
	const keep = (e: LedgerEntry): boolean =>
		!!e && typeof e.value === "string" && typeof e.category === "string" &&
		typeof e.seq === "number" && typeof e.quote === "string" &&
		(!validMessageIds || !e.messageId || validMessageIds.has(e.messageId))
	ledger.grants = Array.isArray(s.grants) ? s.grants.filter(keep).slice(0, MAX_GRANTS) : []
	ledger.forbids = Array.isArray(s.forbids) ? s.forbids.filter(keep).slice(0, MAX_FORBIDS) : []
	for (const id of Array.isArray(s.seen) ? s.seen : []) {
		if (typeof id === "string" && (!validMessageIds || validMessageIds.has(id))) ledger.seen.add(id)
	}
	if (s.readOnlyOn && typeof s.readOnlyOn.seq === "number" && typeof s.readOnlyOn.quote === "string") {
		ledger.readOnlyOn = { seq: s.readOnlyOn.seq, quote: s.readOnlyOn.quote }
	}
	if (typeof s.readOnlyOffSeq === "number") ledger.readOnlyOffSeq = s.readOnlyOffSeq
	return ledger
}
