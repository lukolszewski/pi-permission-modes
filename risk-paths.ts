/**
 * Path classification for the auto-mode risk policy (docs/CLASSIFIER-SPEC.md §2.3, §2.5).
 * Pure functions; `home` and `project` are injected so tests are hermetic.
 */

import path from "node:path"

export type PathContext = {
	/** Effective working directory for relative paths. */
	cwd: string
	/** Project root (the pi session cwd). Writes inside are ALLOW. */
	project: string
	home: string
}

export type PathClass = {
	/** Absolute, normalised path; `null` when it cannot be resolved (unexpanded variable). */
	abs: string | null
	/** Raw token as written. */
	raw: string
	insideProject: boolean
	/** Equals the project root itself (or `.`, `./`, `*`). */
	isProjectRoot: boolean
	/** Wiping this path is NEVER-tier (root, home, system dirs, project parents…). */
	isNeverWipe: boolean
	/** Secret-bearing file (§2.5). */
	isSecret: boolean
	/** Sensitive config (shell profiles, ssh, cron, systemd, /etc…) — writes are ASK write_sensitive. */
	isSensitiveConfig: boolean
	/** Inside a temp location (/tmp, /var/tmp, /dev/shm, $TMPDIR) — writes are routine. */
	isTemp: boolean
	/** Inside the project's .git directory. */
	isGitInternal: boolean
	/** Block device or special device. */
	isDevice: boolean
	/** Starts with an unexpanded variable or contains a glob at the root position. */
	unresolvedRoot: boolean
	/** Path contains an unexpanded `$var` somewhere after a known prefix. */
	hasExpansion: boolean
}

const SYSTEM_ROOTS = [
	"/", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc", "/var",
	"/boot", "/opt", "/srv", "/dev", "/proc", "/sys", "/root", "/home", "/mnt", "/media",
	"/run", "/snap", "/nix", "/System", "/Library", "/Applications", "/Users", "/private", "/tmp", "/var/tmp", "/dev/shm",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/share", "/var/lib", "/var/log",
	"/etc/ssh", "/etc/systemd", "/var/lib/docker",
]

const HOME_NEVER_SUBDIRS = [
	".ssh", ".gnupg", ".config", ".local", ".cache", "Documents", "Desktop", "Pictures",
	"Videos", "Music", "Downloads", "Library", "Dropbox", "OneDrive", ".aws", ".kube",
	".docker", ".password-store", ".mozilla", ".thunderbird", "dev", "src", "projects",
	"work", "repos", "code",
]

const SECRET_FILE_RE =
	/^(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|.*\.(pem|key|p12|pfx|jks|keystore)|credentials(\..*)?|\.env(\..*)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\.my\.cnf|auth\.json|secrets?(\..*)?\.(json|ya?ml|toml|env)|token(s)?(\..*)?|.*\.secret|\.htpasswd|shadow|sudoers(\..*)?|kubeconfig|config\.json|hosts\.yml|service-account.*\.json)$/i

const SECRET_EXAMPLE_RE = /\.(example|sample|template|dist|schema)$/i

const SECRET_DIRS_UNDER_HOME = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh", ".config/gcloud", ".azure", ".password-store", ".pi/agent", ".claude", ".config/pi", ".vault-token"]

const SENSITIVE_HOME_FILES = new Set([
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin",
	".config/fish/config.fish", ".cshrc", ".tcshrc", ".kshrc", ".xinitrc", ".xprofile", ".Xresources", ".xsession",
	".gitconfig", ".gitignore_global", ".ssh/config", ".ssh/authorized_keys", ".ssh/known_hosts", ".inputrc",
	".tmux.conf", ".vimrc", ".config/nvim/init.lua", ".config/nvim/init.vim", ".npmrc", ".yarnrc", ".cargo/config.toml",
	".docker/config.json", ".kube/config", ".aws/config", ".config/systemd", ".config/autostart", ".bash_history",
	".zsh_history", ".python_history", ".node_repl_history", ".lesshst",
])

const SENSITIVE_SYSTEM_PREFIXES = [
	"/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/var/lib", "/var/spool/cron", "/var/log",
	"/Library", "/System", "/private/etc", "/root", "/snap",
]

const DEVICE_RE = /^\/dev\/(sd[a-z]+\d*|nvme\d+n\d+(p\d+)?|mmcblk\d+(p\d+)?|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|loop\d+|dm-\d+|md\d+|mapper\/.+|disk\d+.*|rdisk\d+.*|mem|kmem|port|zero|random|urandom|tty\S*|fd\d+)$/

export function expandTilde(p: string, home: string): string {
	if (p === "~") return home
	if (p.startsWith("~/")) return path.join(home, p.slice(2))
	if (p === "$HOME" || p === "${HOME}") return home
	if (p.startsWith("$HOME/")) return path.join(home, p.slice(6))
	if (p.startsWith("${HOME}/")) return path.join(home, p.slice(8))
	return p
}

function normalize(abs: string): string {
	const n = path.posix.normalize(abs)
	return n.length > 1 ? n.replace(/\/+$/, "") : n
}

/** Does `abs` equal `root` or live under it? */
export function isUnder(abs: string, root: string): boolean {
	const a = normalize(abs)
	const r = normalize(root)
	return a === r || a.startsWith(r === "/" ? "/" : r + "/")
}

function homeRelative(abs: string, home: string): string | null {
	const h = normalize(home)
	const a = normalize(abs)
	if (a === h) return ""
	if (a.startsWith(h + "/")) return a.slice(h.length + 1)
	return null
}

export function classifyPath(rawIn: string, ctx: PathContext): PathClass {
	const raw = rawIn
	let p = raw.trim()
	// strip surrounding quotes left by tools that pass strings through
	p = p.replace(/^["']|["']$/g, "")
	const base: PathClass = {
		abs: null, raw, insideProject: false, isProjectRoot: false, isNeverWipe: false, isSecret: false, isTemp: false,
		isSensitiveConfig: false, isGitInternal: false, isDevice: false, unresolvedRoot: false, hasExpansion: false,
	}
	if (!p) return base

	// Unexpanded variable/command substitution at the root of the path.
	const expansionAtRoot = /^\$(?!HOME\b|\{HOME\})|^`/.test(p)
	const globAtRoot = /^[*?]/.test(p) || p === "./*" || p === "*" || p === ".*"
	if (expansionAtRoot) {
		base.unresolvedRoot = true
		base.hasExpansion = true
		// `$X/...` — could be anything, including `/`. Callers treat as unresolved.
		return base
	}
	if (/\$[A-Za-z_{(]|`/.test(p)) base.hasExpansion = true

	p = expandTilde(p, ctx.home)
	if (globAtRoot) {
		// `*` / `./*` — the current directory's contents.
		base.abs = normalize(ctx.cwd)
	} else {
		// Drop a trailing glob component for classification ("./build/*" → ./build)
		const globIdx = p.search(/[*?[]/)
		let head = globIdx === -1 ? p : p.slice(0, globIdx)
		if (globIdx !== -1) {
			const lastSlash = head.lastIndexOf("/")
			head = lastSlash === -1 ? "." : head.slice(0, lastSlash) || "/"
		}
		base.abs = normalize(path.isAbsolute(head) ? head : path.resolve(ctx.cwd, head))
	}
	const abs = base.abs
	const project = normalize(ctx.project)
	const home = normalize(ctx.home)

	base.insideProject = isUnder(abs, project)
	base.isTemp = ["/tmp", "/var/tmp", "/dev/shm"].some((t) => abs !== t && isUnder(abs, t))
	base.isProjectRoot = abs === project || (globAtRoot && normalize(ctx.cwd) === project)
	base.isGitInternal = base.insideProject && (abs === path.posix.join(project, ".git") || abs.startsWith(path.posix.join(project, ".git") + "/"))
	base.isDevice = DEVICE_RE.test(abs) && abs !== "/dev/null"

	const basename = path.posix.basename(abs)
	const hrel = homeRelative(abs, home)

	// Secret-bearing?
	if (SECRET_FILE_RE.test(basename) && !SECRET_EXAMPLE_RE.test(basename)) base.isSecret = true
	if (hrel !== null) {
		for (const d of SECRET_DIRS_UNDER_HOME) {
			if (hrel === d || hrel.startsWith(d + "/")) {
				// known_hosts / config under ~/.ssh are sensitive config, not secrets
				if (d === ".ssh" && (basename === "known_hosts" || basename === "config")) break
				base.isSecret = true
			}
		}
	}
	if (abs === "/etc/shadow" || abs === "/etc/gshadow" || abs.startsWith("/etc/sudoers")) base.isSecret = true

	// Sensitive config?
	if (hrel !== null) {
		if (SENSITIVE_HOME_FILES.has(hrel)) base.isSensitiveConfig = true
		for (const d of [".ssh", ".config/systemd", ".config/autostart", ".config/fish", ".gnupg", ".aws", ".kube", ".docker", ".pi", ".claude", ".config/gh", "Library/LaunchAgents"]) {
			if (hrel === d || hrel.startsWith(d + "/")) base.isSensitiveConfig = true
		}
	}
	if (!base.insideProject && SENSITIVE_SYSTEM_PREFIXES.some((pre) => isUnder(abs, pre))) base.isSensitiveConfig = true
	if (/\/(crontab|cron\.d|cron\.daily|cron\.hourly|systemd|init\.d|rc\.d|profile\.d|ld\.so\.conf\.d|sudoers\.d)\b/.test(abs)) base.isSensitiveConfig = true

	// NEVER-wipe?
	const never = new Set(SYSTEM_ROOTS.map(normalize))
	if (never.has(abs)) base.isNeverWipe = true
	if (abs === home) base.isNeverWipe = true
	if (hrel !== null && hrel !== "") {
		const first = hrel.split("/")[0]!
		if (HOME_NEVER_SUBDIRS.includes(first) && !hrel.includes("/")) base.isNeverWipe = true
	}
	// Any ancestor of the project (including the project root itself) is never wiped.
	if (isUnder(project, abs)) base.isNeverWipe = true
	// Top-level home entries that are directories holding other projects are covered above;
	// wiping the parent of a project is always the project's parent chain → covered by isUnder.
	return base
}

/** Human-readable short form for prompts/entities. */
export function displayPath(pc: PathClass, ctx: PathContext): string {
	if (!pc.abs) return pc.raw
	if (pc.raw === "." || pc.raw === "./" || pc.raw === "*" || pc.raw === "./*") return pc.raw
	const rel = path.posix.relative(normalize(ctx.project), pc.abs)
	if (pc.insideProject) return rel === "" ? "." : `./${rel}`
	const hrel = homeRelative(pc.abs, ctx.home)
	if (hrel !== null) return hrel === "" ? "~" : `~/${hrel}`
	return pc.abs
}
