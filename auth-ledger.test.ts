import { describe, expect, it } from "vitest"
import {
	applyEvent,
	applyEvents,
	createLedger,
	deserializeLedger,
	eventsFromExtraction,
	kindGroup,
	ledgerCovers,
	mapActionToCategory,
	MAX_FORBIDS,
	MAX_GRANTS,
	readOnlyActive,
	readOnlyLiftedByGrant,
	serializeLedger,
	type ExtractedEvent,
	type Ledger,
} from "./auth-ledger.ts"
import type { Entity } from "./risk-policy.ts"

const T = (v: string): Entity => ({ kind: "target", value: v }) as Entity

function grant(category: string, value: string, seq: number, quote = `you can do it to ${value}`, kind?: "entity" | "scope"): ExtractedEvent {
	return { type: "grant", category, value, kind: kind ?? (value.endsWith("/") ? "scope" : "entity"), quote, messageId: `m${seq}`, seq }
}
function forbid(value: string, seq: number, quote = `do not touch ${value}`, category = "*"): ExtractedEvent {
	return { type: "forbid", category, value, kind: value.endsWith("/") ? "scope" : "entity", quote, messageId: `m${seq}`, seq }
}

describe("kind groups / action mapping", () => {
	it("groups fs mutations together, keeps domains apart", () => {
		expect(kindGroup("write_outside")).toBe("fs-write")
		expect(kindGroup("delete_recursive")).toBe(kindGroup("perm_change"))
		expect(kindGroup("write_outside")).not.toBe(kindGroup("package_system"))
		expect(kindGroup("cluster_mutation")).toBe(kindGroup("container_mutation"))
		expect(kindGroup("vcs_remote")).not.toBe(kindGroup("vcs_discard"))
	})
	it("maps domain nouns before generic verbs", () => {
		expect(mapActionToCategory("delete the pod")).toBe("cluster_mutation")
		expect(mapActionToCategory("drop the sessions table")).toBe("db_mutation")
		expect(mapActionToCategory("delete old logs")).toBe("delete_outside")
		expect(mapActionToCategory("copy files with rsync")).toBe("write_outside")
		expect(mapActionToCategory("install ripgrep")).toBe("package_system")
		expect(mapActionToCategory("interpretive dance")).toBeUndefined()
	})
})

describe("fold: dedup + seq precedence", () => {
	it("dedups same key, keeps highest seq", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 5))
		applyEvent(l, grant("write_outside", "/data/", 9, "again /data/ please"))
		applyEvent(l, grant("write_outside", "/data/", 3, "old /data/"))
		expect(l.grants).toHaveLength(1)
		expect(l.grants[0]!.seq).toBe(9)
		expect(l.grants[0]!.quote).toContain("again")
	})
	it("exact-key flip-flop keeps only the newest side", () => {
		const l = createLedger()
		applyEvents(l, [grant("write_outside", "/data/", 2), forbid("/data/", 5), grant("write_outside", "/data/", 8)])
		// forbid category "*" vs grant category write_outside — different keys, so
		// both survive; precedence is decided at match time by seq.
		const v = ledgerCovers(l, "write_outside", [T("/data/x.txt")])
		expect(v.covered).toBe(true)
	})
	it("revocation between grants blocks, re-grant unblocks", () => {
		const probe = () => ledgerCovers(l, "write_outside", [T("/data/x")])
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 2))
		expect(probe().covered).toBe(true)
		applyEvent(l, forbid("/data/", 5))
		expect(probe().covered).toBe(false)
		expect(probe().forbidden).toBe(true)
		applyEvent(l, grant("write_outside", "/data/", 8))
		expect(probe().covered).toBe(true)
	})
	it("'revoke all' keeps blocking targets a later grant did not re-grant", () => {
		const l = createLedger()
		applyEvents(l, [
			grant("write_outside", "/a/", 2),
			grant("write_outside", "/b/", 3),
			forbid("*", 10, "stop, do not write anywhere"),
			grant("write_outside", "/a/", 15),
		])
		expect(ledgerCovers(l, "write_outside", [T("/a/f")]).covered).toBe(true)
		const b = ledgerCovers(l, "write_outside", [T("/b/f")])
		expect(b.covered).toBe(false)
		expect(b.forbidden).toBe(true)
	})
	it("folded state is independent of processing order", () => {
		const events = [
			grant("write_outside", "/data/", 2),
			forbid("/data/", 5),
			grant("write_outside", "/data/", 8),
			grant("db_mutation", "sessions", 4, "you can drop the sessions table"),
			forbid("*", 6, "actually stop everything"),
			grant("package_system", "ripgrep", 9, "just apt-get install ripgrep"),
			forbid("payments", 7),
		]
		const probes: Array<[string, Entity[]]> = [
			["write_outside", [T("/data/x")]],
			["db_mutation", [T("sessions")]],
			["package_system", [T("ripgrep")]],
			["db_mutation", [T("payments")]],
		]
		const orders = [
			events,
			[...events].reverse(),
			[events[3]!, events[6]!, events[0]!, events[5]!, events[2]!, events[1]!, events[4]!],
			[events[4]!, events[2]!, events[0]!, events[1]!, events[6]!, events[5]!, events[3]!],
		]
		const results = orders.map((order) => {
			const l = createLedger()
			applyEvents(l, order)
			return probes.map(([c, e]) => `${ledgerCovers(l, c, e).covered}/${ledgerCovers(l, c, e).forbidden}`).join(" ")
		})
		expect(new Set(results).size).toBe(1)
		// sanity on the shared verdicts: sessions revoked by "stop everything" (seq 6 > 4),
		// ripgrep re-granted after it (9 > 6), payments forbidden
		expect(results[0]).toBe("true/false false/true true/false false/true")
	})
	it("newest-first partial fold never allows a later-revoked grant", () => {
		// grant at 10, revocation at 40 — processed newest-first
		const l = createLedger()
		applyEvent(l, forbid("/data/", 40))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(false)
		applyEvent(l, grant("write_outside", "/data/", 10)) // older grant arrives later
		const v = ledgerCovers(l, "write_outside", [T("/data/x")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
	})
})

describe("matching", () => {
	it("kind-group widening: rsync grant covers mkdir and chmod at the location", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "write_outside", [T("/x/x/sub")]).covered).toBe(true)
		expect(ledgerCovers(l, "perm_change", [T("/x/x/sub/f")]).covered).toBe(true)
	})
	it("deletes require a delete verb in the grant quote", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/x/x/", 3, "copy the file to /x/x/ with rsync"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(false)
		applyEvent(l, grant("delete_outside", "/x/x/old", 5, "and delete /x/x/old when done"))
		expect(ledgerCovers(l, "delete_recursive", [T("/x/x/old")]).covered).toBe(true)
	})
	it("METHOD_VERB_REQUIRED: naming the package is not approving the install", () => {
		const l = createLedger()
		applyEvent(l, grant("package_system", "ripgrep", 3, "ripgrep is missing on this box"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(false)
		applyEvent(l, grant("package_system", "ripgrep", 4, "go ahead and install ripgrep"))
		expect(ledgerCovers(l, "package_system", [T("ripgrep")]).covered).toBe(true)
	})
	it("near-names never match across the ledger", () => {
		const l = createLedger()
		applyEvent(l, grant("delete_data", "db-backup", 3, "you can delete db-backup"))
		expect(ledgerCovers(l, "delete_data", [T("db-backup-test")]).covered).toBe(false)
		expect(ledgerCovers(l, "delete_data", [T("db-backup")]).covered).toBe(true)
	})
	it("cross-group grants never match; unmappable actions never match", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 3, "write to /data/ freely"))
		expect(ledgerCovers(l, "package_system", [T("/data/")]).covered).toBe(false)
		applyEvent(l, { type: "grant", category: "*frobnicate the widget*", value: "widget", kind: "entity", quote: "frobnicate the widget", messageId: "m9", seq: 9 })
		expect(ledgerCovers(l, "write_outside", [T("widget")]).covered).toBe(false)
	})
	it("all targets must be covered", () => {
		const l = createLedger()
		applyEvent(l, grant("db_mutation", "sessions", 3, "drop the sessions table"))
		expect(ledgerCovers(l, "db_mutation", [T("sessions"), T("users")]).covered).toBe(false)
	})
	it("bare-verb '*' grant covers unlisted targets of the category", () => {
		const l = createLedger()
		applyEvent(l, grant("vcs_remote", "*", 3, "force-push it", "scope"))
		expect(ledgerCovers(l, "vcs_remote", [T("origin/main")]).covered).toBe(true)
		expect(ledgerCovers(l, "package_system", [T("origin/main")]).covered).toBe(false)
	})
})

describe("caps / eviction", () => {
	it("evicts least-recently-matched grants first, never forbids for grants", () => {
		const l = createLedger()
		for (let i = 0; i < MAX_GRANTS + 10; i++) applyEvent(l, grant("write_outside", `/p${i}/`, i))
		expect(l.grants.length).toBe(MAX_GRANTS)
		// the oldest unmatched ones are gone; matching bumps recency
		expect(ledgerCovers(l, "write_outside", [T(`/p${MAX_GRANTS + 9}/x`)]).covered).toBe(true)
		for (let i = 0; i < MAX_FORBIDS + 5; i++) applyEvent(l, forbid(`/q${i}/`, 1000 + i))
		expect(l.forbids.length).toBe(MAX_FORBIDS)
		expect(l.grants.length).toBe(MAX_GRANTS)
	})
})

describe("eventsFromExtraction verification", () => {
	const msg = "please copy the dataset to /mnt/scratch/exp1/ and then you can delete ./old-dumps, but do not touch ~/backups"
	it("keeps verified grants/revocations, drops unverifiable quotes and targets", () => {
		const ev = eventsFromExtraction(
			{
				grants: [
					{ action: "copy files", targets: ["/mnt/scratch/exp1/"], quote: "copy the dataset to /mnt/scratch/exp1/" },
					{ action: "delete files", targets: ["./old-dumps"], quote: "you can delete ./old-dumps" },
					{ action: "delete files", targets: ["/etc/passwd"], quote: "you can delete ./old-dumps" }, // target not in message
					{ action: "install tools", targets: ["ripgrep"], quote: "install ripgrep now" }, // quote not in message
				],
				revocations: [{ action: "delete files", targets: ["~/backups"], all: false, quote: "do not touch ~/backups" }],
			},
			"mid1", 7, msg,
		)
		expect(ev.map((e) => `${e.type}:${e.value}`)).toEqual([
			"grant:/mnt/scratch/exp1/",
			"grant:./old-dumps",
			"forbid:~/backups",
		])
		expect(ev[0]!.kind).toBe("scope")
		expect(ev[0]!.category).toBe("write_outside")
		expect(ev.every((e) => e.messageId === "mid1" && e.seq === 7)).toBe(true)
	})
	it("bare-verb grant only for bare-verb categories with the verb in the quote", () => {
		const ev = eventsFromExtraction(
			{ grants: [{ action: "push to remote", targets: [], quote: "force-push it" }], revocations: [] },
			"m1", 2, "ok now force-push it",
		)
		expect(ev).toEqual([expect.objectContaining({ type: "grant", category: "vcs_remote", value: "*", kind: "scope" })])
		const none = eventsFromExtraction(
			{ grants: [{ action: "write files", targets: [], quote: "sounds good" }], revocations: [] },
			"m1", 2, "sounds good",
		)
		expect(none).toEqual([])
	})
	it("'all' revocation with unmappable action sets the read-only posture (enforced by the gate, not ledgerCovers)", () => {
		const ev = eventsFromExtraction(
			{ grants: [], revocations: [{ action: "risky work", targets: [], all: true, quote: "stop, don't run anything risky anymore" }] },
			"m1", 50, "stop, don't run anything risky anymore",
		)
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/data/", 10))
		applyEvents(l, ev)
		// posture is set; the older grant (seq 10 < 50) does not lift it
		expect(readOnlyActive(l)?.seq).toBe(50)
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/data/x")], 50)).toBe(false)
		expect(l.forbids).toHaveLength(0)
	})
	it("blanket 'don't change anything' sets the read-only posture, not a wildcard forbid", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "change anything", targets: [], all: true, quote: "you are not allowed to change anything" }] },
			"m0", 0, "you are not allowed to change anything",
		))
		expect(readOnlyActive(l)?.quote).toContain("change anything")
		expect(l.forbids).toHaveLength(0) // no more */* forbid row
	})
	it("read-only: later per-target grant lifts that target, blanket re-enable clears it", () => {
		const l = createLedger()
		applyEvent(l, { type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "do not change anything", messageId: "m0", seq: 0 })
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(false)
		applyEvent(l, grant("write_outside", "/x/", 5, "you can write to /x/"))
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/x/f")], 0)).toBe(true) // seq 5 > 0
		expect(readOnlyLiftedByGrant(l, "write_outside", [T("/y/f")], 0)).toBe(false) // different target
		expect(readOnlyLiftedByGrant(l, "write_outside", [], 0)).toBe(false) // targetless can't be lifted
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "make changes", targets: [], quote: "ok you can make changes now" }], revocations: [] },
			"m9", 9, "ok you can make changes now",
		))
		expect(readOnlyActive(l)).toBeNull()
	})
	it("read-only posture is order-independent and re-armable (on/off/on by seq)", () => {
		const evs: ExtractedEvent[] = [
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "read only please", messageId: "a", seq: 2 },
			{ type: "readonly-off", category: "*", value: "*", kind: "scope", quote: "changes are fine", messageId: "b", seq: 5 },
			{ type: "readonly-on", category: "*", value: "*", kind: "scope", quote: "actually stop changing things", messageId: "c", seq: 8 },
		]
		const results = [evs, [...evs].reverse(), [evs[1]!, evs[2]!, evs[0]!]].map((order) => {
			const l = createLedger(); applyEvents(l, order); return readOnlyActive(l)?.seq ?? null
		})
		expect(new Set(results.map(String)).size).toBe(1)
		expect(results[0]).toBe(8) // newest on (seq 8) wins
	})
	it("generic-kind revocation targets escalate to a category-wide forbid (G9 regression)", () => {
		const l = createLedger()
		applyEvents(l, eventsFromExtraction(
			{ grants: [{ action: "delete image", targets: ["payments:staging"], quote: "you can delete the payments:staging image" }], revocations: [] },
			"m0", 0, "you can delete the payments:staging image",
		))
		expect(ledgerCovers(l, "container_mutation", [T("payments:staging")]).covered).toBe(true)
		// model emits the generic kind as a "target" — must not be treated as a name
		applyEvents(l, eventsFromExtraction(
			{ grants: [], revocations: [{ action: "delete image", targets: ["images"], all: false, quote: "do not delete any images" }] },
			"m1", 1, "actually never mind, do not delete any images",
		))
		const v = ledgerCovers(l, "container_mutation", [T("payments:staging")])
		expect(v.covered).toBe(false)
		expect(v.forbidden).toBe(true)
		// scoped to the kind group: unrelated fs writes are untouched
		applyEvent(l, grant("write_outside", "/data/", 0))
		expect(ledgerCovers(l, "write_outside", [T("/data/x")]).covered).toBe(true)
	})
})

describe("serialize / restore", () => {
	it("round-trips and filters entries from rewound-away messages", () => {
		const l = createLedger()
		applyEvent(l, grant("write_outside", "/a/", 2))
		applyEvent(l, grant("write_outside", "/b/", 3))
		applyEvent(l, forbid("/c/", 4))
		l.seen.add("m2"); l.seen.add("m3"); l.seen.add("m4")
		const snap = JSON.parse(JSON.stringify(serializeLedger(l)))
		const full = deserializeLedger(snap)
		expect(full.grants).toHaveLength(2)
		expect(full.forbids).toHaveLength(1)
		expect(full.seen.size).toBe(3)
		const filtered = deserializeLedger(snap, new Set(["m2", "m4"]))
		expect(filtered.grants.map((g) => g.value)).toEqual(["/a/"])
		expect(filtered.forbids).toHaveLength(1)
		expect([...filtered.seen].sort()).toEqual(["m2", "m4"])
	})
	it("unknown version → empty ledger (backfill rebuilds)", () => {
		expect(deserializeLedger({ v: 2, grants: [] }).grants).toEqual([])
		expect(deserializeLedger("garbage").grants).toEqual([])
		expect(deserializeLedger(undefined).grants).toEqual([])
	})
})
