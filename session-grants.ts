/**
 * Prompt-once session grants (docs/CLASSIFIER-SPEC.md §3.2).
 * A grant is {category, entity} or {category, scope-prefix}; grants never widen
 * automatically. Pure in-memory store with (de)serialisation for session persist.
 */

import type { Entity } from "./risk-policy.ts"
import { entityMatchesTarget } from "./grant-verify.ts"

export type SessionGrant = {
	category: string
	/** Exact entity value, or a prefix ending in "/" for scope grants. */
	value: string
	kind: "entity" | "scope"
	at: number
}

export type GrantStore = { grants: SessionGrant[] }

export function createGrantStore(): GrantStore {
	return { grants: [] }
}

export function addGrant(store: GrantStore, category: string, value: string, kind: "entity" | "scope"): void {
	const primary = category.split("+")[0] ?? category
	if (!value) return
	if (store.grants.some((g) => g.category === primary && g.value === value && g.kind === kind)) return
	store.grants.push({ category: primary, value, kind, at: Date.now() })
}

function scopeCovers(scopeValue: string, entity: string): boolean {
	const s = scopeValue.toLowerCase()
	const e = entity.toLowerCase()
	if (s.endsWith("/")) return e.startsWith(s) || (e + "/") === s
	return entityMatchesTarget(entity, scopeValue)
}

/** All target-entities of the pending action must be covered by grants of its category. */
export function grantsCover(store: GrantStore, category: string, entities: Entity[]): { covered: boolean; by: string[] } {
	const primary = category.split("+")[0] ?? category
	const targets = entities.filter((e) => e.kind === "target").map((e) => e.value)
	if (targets.length === 0) return { covered: false, by: [] }
	const relevant = store.grants.filter((g) => g.category === primary)
	if (relevant.length === 0) return { covered: false, by: [] }
	const by: string[] = []
	for (const t of targets) {
		const hit = relevant.find((g) =>
			g.kind === "entity" ? entityMatchesTarget(t, g.value) || g.value === t : scopeCovers(g.value, t),
		)
		if (!hit) return { covered: false, by: [] }
		by.push(hit.value)
	}
	return { covered: true, by }
}

export function serializeGrants(store: GrantStore): string {
	return JSON.stringify(store.grants)
}

export function deserializeGrants(json: string | undefined | null): GrantStore {
	if (!json) return createGrantStore()
	try {
		const arr = JSON.parse(json) as SessionGrant[]
		if (!Array.isArray(arr)) return createGrantStore()
		return { grants: arr.filter((g) => g && typeof g.value === "string" && typeof g.category === "string") }
	} catch {
		return createGrantStore()
	}
}
