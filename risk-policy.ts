/**
 * Deterministic auto-mode risk policy (docs/CLASSIFIER-SPEC.md §2).
 *
 * evaluateToolCall(tool, input, ctx) → PolicyDecision
 *
 * Bash commands are lexed (shell-lexer.ts), each simple command is classified by a
 * verb handler (risk-handlers.ts), `cd` updates the effective cwd, `sudo`/wrappers
 * are peeled, substitutions and `bash -c` strings are classified recursively, and
 * the compound result is the most restrictive segment. Anything the table does not
 * understand is `unknown` and is handed to the model with the exact segment text.
 */

import path from "node:path"
import { existsSync, readFileSync } from "node:fs"
import { lexShell, lexShellChecked, type SimpleCommand, type Word } from "./shell-lexer.ts"
import { classifyPath, displayPath, expandTilde, type PathClass, type PathContext } from "./risk-paths.ts"
import { classifyVerb, type HandlerContext } from "./risk-handlers.ts"

export type Tier = "allow" | "ask" | "never" | "unknown"

/** "target"/"scope" drive prompts, grant options and grant matching. "path"
 *  marks files an ALLOW-tier segment touches — consulted ONLY by the ledger's
 *  named-forbid scan ("do not delete X" must bind even where the tables say
 *  allow); every other consumer filters on target/scope and ignores it. */
export type Entity = { kind: "target" | "scope" | "path"; value: string }

export type SegmentDecision = {
	tier: Tier
	/** Category from the spec tables (e.g. delete_recursive, read_only, unknown_command). */
	category: string
	entities: Entity[]
	/** One line, plain words, for prompts and for the model ("recursively delete ./build"). */
	description: string
	/** Segment text (for the model on unknown, for the prompt otherwise). */
	command: string
	/** Inline code (heredoc / -c) for unknown interpreter segments. */
	inlineCode?: string
}

export type PolicyDecision = {
	tier: Tier
	category: string
	entities: Entity[]
	description: string
	reason: string
	segments: SegmentDecision[]
	/** Segments that need the model (tier === "unknown"). */
	unknown: SegmentDecision[]
	/** The command could not be tokenised cleanly (unterminated quote/heredoc/
	 *  substitution). The segment list is unreliable — the gate should refuse and
	 *  ask the model to fix/simplify, not trust the fabricated segments. */
	unparseable?: boolean
}

export type PolicyOptions = {
	cwd: string
	project?: string
	home?: string
	env?: Record<string, string | undefined>
	/** Filesystem probes (package.json scripts, node_modules/.bin) — disable in tests. */
	fs?: boolean
	/** Recursion guard. */
	depth?: number
}

const TIER_RANK: Record<Tier, number> = { allow: 0, ask: 1, unknown: 2, never: 3 }

export function mergeDecisions(segs: SegmentDecision[], commandText: string): PolicyDecision {
	if (segs.length === 0) {
		const d: SegmentDecision = { tier: "unknown", category: "unknown_command", entities: [], description: `run \`${commandText}\``, command: commandText }
		return { tier: "unknown", category: d.category, entities: [], description: d.description, reason: "could not parse command", segments: [d], unknown: [d] }
	}
	let top = segs[0]!
	for (const s of segs) if (TIER_RANK[s.tier] > TIER_RANK[top.tier]) top = s
	const same = segs.filter((s) => s.tier === top.tier)
	const entities = dedupeEntities(same.flatMap((s) => s.entities))
	const categories = [...new Set(same.map((s) => s.category))]
	const description = same.length === 1 ? top.description : same.map((s) => s.description).join("; ")
	return {
		tier: top.tier,
		category: categories.join("+"),
		entities,
		description,
		reason: `${top.tier}: ${description}`,
		segments: segs,
		unknown: segs.filter((s) => s.tier === "unknown"),
	}
}

export function dedupeEntities(list: Entity[]): Entity[] {
	const seen = new Set<string>()
	const out: Entity[] = []
	for (const e of list) {
		const k = `${e.kind}:${e.value}`
		if (!seen.has(k) && e.value) { seen.add(k); out.push(e) }
	}
	return out
}

export function seg(tier: Tier, category: string, description: string, command: string, entities: Entity[] = [], extra?: Partial<SegmentDecision>): SegmentDecision {
	return { tier, category, description, command, entities: dedupeEntities(entities), ...extra }
}

export const target = (v: string): Entity => ({ kind: "target", value: v })
export const scope = (v: string): Entity => ({ kind: "scope", value: v })
export const pathTouched = (v: string): Entity => ({ kind: "path", value: v })

// ------------------------------------------------------------------ tool-level

const READ_TOOLS = new Set(["read", "grep", "find", "ls", "glob", "web_search", "web_read", "fetch", "web_fetch", "plan_ready", "todo", "todo_read", "todo_write", "list_skills", "memory_search", "think"])

export function evaluateToolCall(tool: string, input: Record<string, unknown>, opts: PolicyOptions): PolicyDecision {
	try {
		return evaluateToolCallInner(tool, input, opts)
	} catch (err) {
		const text = `${tool} ${safeJson(input)}`
		return mergeDecisions([seg("unknown", "unknown_tool", `call tool ${tool} (policy error: ${String(err).slice(0, 80)})`, text)], text)
	}
}

function safeJson(v: unknown): string {
	try { return JSON.stringify(v)?.slice(0, 800) ?? "" } catch { return "" }
}

function evaluateToolCallInner(tool: string, input: Record<string, unknown>, opts: PolicyOptions): PolicyDecision {
	const ctx = makeCtx(opts)
	if (tool === "bash") {
		return evaluateBash(String(input.command ?? ""), opts)
	}
	if (tool === "edit" || tool === "write") {
		const p = String(input.path ?? "")
		const content = typeof input.content === "string" ? input.content : typeof input.new_string === "string" ? input.new_string : ""
		const pc = classifyPath(p, ctx)
		const d = decideWrite(pc, ctx, tool, content)
		return mergeDecisions([d], `${tool} ${p}`)
	}
	if (tool === "read" || tool === "grep" || tool === "find" || tool === "ls" || tool === "glob") {
		const p = String(input.path ?? input.file ?? "")
		if (p) {
			const pc = classifyPath(p, ctx)
			if (pc.isSecret) return mergeDecisions([seg("ask", "read_secret", `read secret-bearing path ${displayPath(pc, ctx)}`, `${tool} ${p}`, [target(displayPath(pc, ctx))])], `${tool} ${p}`)
		}
		return mergeDecisions([seg("allow", "read_only", `${tool} ${p || "(project)"}`, `${tool} ${p}`)], `${tool} ${p}`)
	}
	if (READ_TOOLS.has(tool)) {
		return mergeDecisions([seg("allow", "read_only", `${tool}`, tool)], tool)
	}
	// Unknown tool → the model sees the JSON input.
	const text = `${tool} ${JSON.stringify(input).slice(0, 1500)}`
	return mergeDecisions([seg("unknown", "unknown_tool", `call tool ${tool}`, text)], text)
}

function makeCtx(opts: PolicyOptions): PathContext {
	const home = opts.home ?? process.env.HOME ?? "/nonexistent"
	const project = path.resolve(opts.project ?? opts.cwd)
	return { cwd: path.resolve(opts.cwd), project, home }
}

export function decideWrite(pc: PathClass, ctx: PathContext, verb: string, content?: string): SegmentDecision {
	const disp = displayPath(pc, ctx)
	const cmd = `${verb} ${pc.raw}`
	if (pc.unresolvedRoot) return seg("ask", "write_outside", `${verb} to unresolved path ${pc.raw}`, cmd, [target(pc.raw)])
	if (pc.isDevice) return seg("never", "device_write", `write to device ${pc.abs}`, cmd, [target(pc.abs!)])
	if (pc.abs === "/dev/null" || pc.abs === "/dev/stdout" || pc.abs === "/dev/stderr") return seg("allow", "write_project", `${verb} ${disp}`, cmd)
	if (pc.abs && /\/\.ssh\/authorized_keys$/.test(pc.abs)) return seg("never", "persistent_access", `modify SSH authorized_keys (${disp})`, cmd, [target(disp)])
	if (pc.abs && /^\/etc\/(sudoers|passwd|shadow|fstab|gshadow)/.test(pc.abs)) {
		if (content && /NOPASSWD\s*:\s*ALL/i.test(content)) return seg("never", "privilege_persist", `grant passwordless sudo via ${disp}`, cmd, [target(disp)])
		return seg("ask", "write_sensitive", `${verb} system file ${disp}`, cmd, [target(disp)])
	}
	if (pc.isSecret) return seg("ask", "write_sensitive", `${verb} secret-bearing file ${disp}`, cmd, [target(disp)])
	if (pc.isGitInternal) return seg("ask", "write_sensitive", `${verb} inside .git (${disp})`, cmd, [target(disp)])
	if (pc.isSensitiveConfig) return seg("ask", "write_sensitive", `${verb} sensitive config ${disp}`, cmd, [target(disp)])
	if (pc.insideProject) return seg("allow", "write_project", `${verb} ${disp}`, cmd, [pathTouched(disp)])
	if (pc.isTemp) return seg("allow", "write_project", `${verb} ${disp} (temp location)`, cmd, [pathTouched(disp)])
	return seg("ask", "write_outside", `${verb} outside the project: ${disp}`, cmd, [target(disp), scope(path.posix.dirname(pc.abs!) + "/")])
}

// ------------------------------------------------------------------ bash

const MAX_DEPTH = 4

export function evaluateBash(command: string, opts: PolicyOptions): PolicyDecision {
	const text = command.trim()
	if (!text) return mergeDecisions([seg("allow", "read_only", "empty command", "")], "")
	// Fork bomb: a function that pipes into itself and backgrounds ( :(){ :|:& };: and variants)
	const fb = /(\S+)\s*\(\)\s*\{[^}]*\1[^}]*\|[^}]*\1[^}]*&[^}]*\}/
	if (fb.test(text)) {
		return mergeDecisions([seg("never", "process_massacre", "fork bomb (self-replicating function)", text)], text)
	}
	const depth = opts.depth ?? 0
	if (depth > MAX_DEPTH) {
		// too deeply nested to analyse reliably — treat like an unparseable command
		const d = mergeDecisions([seg("ask", "unparseable_command", "command is too deeply nested to analyse", text)], text)
		return { ...d, unparseable: true, reason: "nesting too deep to classify safely" }
	}
	// Fail closed on genuinely malformed input (unterminated quote/heredoc/
	// substitution): the lexer would otherwise emit confident phantom segments
	// from the unparsed remainder. Refuse and let the caller ask the model to fix.
	let cmds: SimpleCommand[]
	try {
		const lexed = lexShellChecked(text)
		if (!lexed.ok) {
			const d = mergeDecisions([seg("ask", "unparseable_command", `command does not parse: ${lexed.reason}`, text)], text)
			return { ...d, unparseable: true, reason: lexed.reason ?? "command does not parse cleanly" }
		}
		cmds = lexed.commands
	} catch {
		const d = mergeDecisions([seg("ask", "unparseable_command", "command could not be parsed", text)], text)
		return { ...d, unparseable: true, reason: "command could not be parsed" }
	}
	const base = makeCtx(opts)
	const state: WalkState = { cwd: base.cwd, vars: {}, prevArgv: null }
	const segs: SegmentDecision[] = []
	for (let i = 0; i < cmds.length; i++) {
		const c = cmds[i]!
		const next = cmds[i + 1]
		const ctx: PathContext = { ...base, cwd: state.cwd }
		for (const a of c.assignments) {
			if (!a.hasExpansion) state.vars[a.name] = a.value
			else state.vars[a.name] = substituteVars(a.value, state.vars)
		}
		// substitutions run first (their output feeds the command)
		for (const sub of c.substitutions) {
			const inner = evaluateBash(sub, { ...opts, cwd: state.cwd, depth: depth + 1 })
			segs.push(...inner.segments.map((s) => ({ ...s, description: `${s.description} (in command substitution)` })))
		}
		if (c.argv.length === 0) {
			// pure assignment or redirect-only
			for (const r of c.redirects) segs.push(...redirectDecisions(c, ctx, opts))
			continue
		}
		const hctx: HandlerContext = {
			ctx, opts: { ...opts, cwd: state.cwd, depth: depth + 1 }, vars: state.vars, cmd: c,
			pipedFrom: c.connector === "|" || c.connector === "|&" ? state.prevArgv : null,
			pipesTo: next && (next.connector === "|" || next.connector === "|&") ? wordsOf(next) : null,
			evaluateBash: (s, o) => evaluateBash(s, { ...opts, ...o, depth: depth + 1 }),
			decideWrite: (pc, verb) => decideWrite(pc, ctx, verb),
			classify: (p) => classifyPath(substituteVars(p, state.vars), ctx),
			display: (pc) => displayPath(pc, ctx),
		}
		const argv = c.argv.map((w) => substituteVars(w.value, state.vars))
		// `cd` updates cwd for later segments
		if (argv[0] === "cd" || argv[0] === "pushd") {
			const dest = argv.slice(1).find((a) => !a.startsWith("-"))
			if (dest === undefined) state.cwd = base.home
			else if (dest === "-") { /* unknown previous dir; keep */ }
			else if (/^\$|`/.test(dest)) { /* unresolved; keep, but later relative paths may be wrong → handled by unresolved flag */ }
			else state.cwd = path.resolve(state.cwd, expandTilde(dest, base.home))
			segs.push(seg("allow", "read_only", `cd ${dest ?? "~"}`, c.raw))
		} else {
			segs.push(...classifyVerb(argv, hctx))
		}
		segs.push(...redirectDecisions(c, ctx, opts))
		state.prevArgv = argv
	}
	return mergeDecisions(segs, text)
}

type WalkState = { cwd: string; vars: Record<string, string>; prevArgv: string[] | null }

function wordsOf(c: SimpleCommand): string[] {
	return c.argv.map((w: Word) => w.value)
}

export function substituteVars(s: string, vars: Record<string, string>): string {
	if (!s.includes("$")) return s
	return s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a, b) => {
		const name = a ?? b
		if (name === "PWD") return "."
		if (name === "HOME") return "~"
		if (name in vars) return vars[name]!
		return m
	})
}

function redirectDecisions(c: SimpleCommand, ctx: PathContext, opts: PolicyOptions): SegmentDecision[] {
	const out: SegmentDecision[] = []
	for (const r of c.redirects) {
		const t = r.target.value
		if (r.op === "<" || r.op === "<<<") {
			const pc = classifyPath(t, ctx)
			if (pc.isSecret) out.push(seg("ask", "read_secret", `read secret-bearing file ${displayPath(pc, ctx)}`, c.raw, [target(displayPath(pc, ctx))]))
			continue
		}
		if (r.op === "<>" ) continue
		const pc = classifyPath(t, ctx)
		out.push(decideWrite(pc, ctx, r.op === ">>" || r.op === "&>>" ? "append to" : "write", undefined))
	}
	return out
}

// ------------------------------------------------------------------ fs probes (optional)

export function readPackageScript(project: string, name: string, enabled: boolean | undefined): string | null {
	if (enabled === false) return null
	try {
		const pj = path.join(project, "package.json")
		if (!existsSync(pj)) return null
		const json = JSON.parse(readFileSync(pj, "utf-8")) as { scripts?: Record<string, string> }
		const s = json.scripts?.[name]
		return typeof s === "string" ? s : null
	} catch {
		return null
	}
}

export function hasLocalBin(project: string, name: string, enabled: boolean | undefined): boolean {
	if (enabled === false) return false
	try {
		return existsSync(path.join(project, "node_modules", ".bin", name))
	} catch {
		return false
	}
}
