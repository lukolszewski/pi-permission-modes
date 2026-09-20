/**
 * Permission-modes extension config (`~/.pi/agent/permission-modes.json`).
 * Pure fs helpers — no pi dependency.
 */

import { existsSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

import type { AutoModeRules } from "./classifier-prompt.ts"

export type ClassifierStage = "tool" | "single" | "fast" | "both" | "thinking"

export const CLASSIFIER_STAGE_SUFFIXES: readonly ClassifierStage[] = [
	"tool",
	"single",
	"fast",
	"both",
	"thinking",
] as const

export type ClassifierEngine = "gate" | "legacy"

export interface ClassifierConfig {
	enabled: boolean
	model: string
	timeoutMs: number
	/** v3 deterministic-policy + narrow-model gate ("gate", default) or the CC-style single-shot classifier ("legacy"). */
	engine?: ClassifierEngine
	/** Direct OpenAI-compatible endpoint override (bypasses pi's model registry). */
	baseUrl?: string
	/** Model id sent to baseUrl (defaults to the id part of `model`). */
	modelId?: string
	/** CC-style JSONL transcript lines instead of "User:" / "bash cmd" format. */
	jsonlTranscript?: boolean
	/** When true (default), classifier errors deny the action instead of local fallback. */
	failClosed?: boolean
	/** Classifier pipeline — see docs/prompts/auto-mode-prompts.md. Default `tool`. */
	stage?: ClassifierStage
	/** Inject AGENTS.md / CLAUDE.md into classifier context. */
	includeAgentsMd?: boolean
	/** Authorisation ledger (whole-session grant memory, gate engine only). Default true. */
	ledger?: boolean
	/** Backfill cap: only the newest N user messages are ever extracted (default 400). */
	ledgerBackfillLimit?: number
}

export interface PermissionModesConfig {
	classifier?: Partial<ClassifierConfig>
	/** CC auto-mode classifier allow / soft_deny / environment bullets. */
	autoMode?: AutoModeRules
	permissions?: {
		allow?: string[]
		deny?: string[]
		ask?: string[]
	}
}

let _configPath = join(homedir(), ".pi", "agent", "permission-modes.json")

export function getConfigPath(): string {
	return _configPath
}

export function setConfigPath(p: string): void {
	_configPath = p
}

const DEFAULT_CLASSIFIER: ClassifierConfig = {
	enabled: true,
	model: "anthropic/claude-haiku-4-5",
	timeoutMs: 15000,
	failClosed: true,
	stage: "tool",
	includeAgentsMd: true,
	engine: "gate",
}

export function resolveClassifierConfig(
	config: PermissionModesConfig,
): ClassifierConfig {
	const c = config.classifier ?? {}
	return {
		enabled: c.enabled ?? DEFAULT_CLASSIFIER.enabled,
		model: c.model ?? DEFAULT_CLASSIFIER.model,
		timeoutMs: c.timeoutMs ?? DEFAULT_CLASSIFIER.timeoutMs,
		engine: c.engine ?? DEFAULT_CLASSIFIER.engine,
		baseUrl: c.baseUrl,
		modelId: c.modelId,
		jsonlTranscript: c.jsonlTranscript ?? false,
		failClosed: c.failClosed ?? DEFAULT_CLASSIFIER.failClosed,
		stage: c.stage ?? DEFAULT_CLASSIFIER.stage,
		includeAgentsMd: c.includeAgentsMd ?? DEFAULT_CLASSIFIER.includeAgentsMd,
		ledger: c.ledger ?? true,
		ledgerBackfillLimit: c.ledgerBackfillLimit ?? 400,
	}
}

export function resolveAutoModeConfig(
	config: PermissionModesConfig,
): AutoModeRules | undefined {
	const rules = config.autoMode
	if (!rules) return undefined
	if (
		!rules.allow?.length &&
		!rules.soft_deny?.length &&
		!rules.environment?.length
	) {
		return undefined
	}
	return rules
}

export function loadPermissionModesConfig(): PermissionModesConfig {
	try {
		if (!existsSync(_configPath)) return {}
		const raw = readFileSync(_configPath, "utf-8")
		if (!raw.trim()) return {}
		return JSON.parse(raw) as PermissionModesConfig
	} catch (err) {
		console.warn(
			`[permission-modes] Failed to load ${_configPath}:`,
			err,
		)
		return {}
	}
}
