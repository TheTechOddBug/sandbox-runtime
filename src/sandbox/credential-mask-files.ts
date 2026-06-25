/**
 * Whole-file credential masking (Linux).
 *
 * For a `credentials.files` entry with `mode: "mask"`, srt reads the real
 * file content on the host, registers a sentinel for it in the
 * {@link SentinelRegistry}, and writes the sentinel to a fake file in a
 * manager-owned temp directory. The Linux sandbox then `--ro-bind`s the
 * fake over the real path, so the sandboxed process reads the sentinel.
 * The proxy substitution from env-var masking already scans every header
 * for any registered sentinel, so a tool that does
 * `Authorization: Bearer $(cat <maskedFile>)` reaches the upstream with
 * the real bytes — no proxy changes required.
 *
 * On macOS, SBPL cannot redirect reads, so masked files degrade to
 * `mode: "deny"` (see macos-sandbox-utils.ts).
 *
 * LIMITATION: this is whole-file masking. It works when the file content
 * *is* the credential (a token file). It does not work for structured
 * files a tool parses (JSON/YAML/.netrc) — the tool will fail to parse
 * the sentinel. See {@link CredentialFileConfigSchema}.
 */

import * as fs from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { logForDebugging } from '../utils/debug.js'
import { normalizePathForSandbox } from './sandbox-utils.js'
import type { CredentialFileConfig } from './sandbox-config.js'
import type { SentinelRegistry } from './credential-sentinel.js'

/**
 * Sentinel-registry key prefix for masked files. Keeps file keys disjoint
 * from env-var names so a credential file at path `GH_TOKEN` cannot collide
 * with the env var `GH_TOKEN`.
 */
const FILE_KEY_PREFIX = 'file:'

/** One masked file's bind mapping for the platform builder. */
export interface MaskedFileBind {
  /** Resolved (tilde-expanded, realpath'd) host path of the real file. */
  realPath: string
  /** Path to the fake file containing the sentinel. */
  fakePath: string
}

/**
 * Manager-owned temp dir holding the fake files.
 *
 * INVARIANT: this directory must never be writable from inside the sandbox.
 * The Linux layer enforces this by emitting `--ro-bind <dirPath> <dirPath>`
 * after every other filesystem mount (see generateFilesystemArgs), so the
 * store stays read-only even if a caller's allowWrite covers os.tmpdir() or
 * the host's $TMPDIR points under a default-writable path. If the sandbox
 * could write here it could replace a fake's content (the bind exposes the
 * source file) or plant a symlink for a later host-side write() to follow.
 */
export class MaskedFileStore {
  private dir: string | undefined
  private readonly byKey = new Map<string, string>()

  /**
   * Write `sentinel` to a fake file for `key` and return its path.
   * Idempotent on `key`: a repeat call rewrites the same fake (so a
   * changed sentinel after re-register propagates) instead of leaking a
   * new file per wrapWithSandbox() call.
   */
  write(key: string, sentinel: string): string {
    if (this.dir === undefined) {
      this.dir = fs.mkdtempSync(join(tmpdir(), 'srt-credmask-'))
    }
    let fakePath = this.byKey.get(key)
    if (fakePath === undefined) {
      fakePath = join(this.dir, `${this.byKey.size}.fake`)
      this.byKey.set(key, fakePath)
    }
    // Never follow a symlink at fakePath: a prior sandbox invocation may
    // have planted one (the store dir is ro-bound now, but defence in
    // depth). Unlink first so writeFileSync creates a fresh regular file.
    fs.rmSync(fakePath, { force: true })
    // 0600: owner rw so the idempotent rewrite above succeeds; the bind
    // into the sandbox is --ro-bind so the sandboxed process sees it
    // read-only regardless of the host mode. No group/other.
    fs.writeFileSync(fakePath, sentinel, { mode: 0o600 })
    return fakePath
  }

  /** Remove the temp dir and every fake file in it. Idempotent. */
  dispose(): void {
    if (this.dir !== undefined) {
      try {
        fs.rmSync(this.dir, { recursive: true, force: true })
      } catch (err) {
        logForDebugging(`MaskedFileStore cleanup failed: ${err}`, {
          level: 'error',
        })
      }
    }
    this.dir = undefined
    this.byKey.clear()
  }

  /** Temp dir path, or undefined if no fake has been written yet. */
  get dirPath(): string | undefined {
    return this.dir
  }
}

/**
 * For each `mode: "mask"` file entry: resolve the path, read the real
 * content, register `(file:<path>, content, injectHosts)` in `registry`,
 * write the sentinel to a fake file via `store`, and return the bind list.
 *
 * Entries whose path does not exist, is unreadable, or resolves to a
 * directory are skipped with a debug log — same posture as a masked env
 * var that's unset on the host: nothing to protect, and surfacing a hard
 * error would make a portable config brittle across machines.
 *
 * The directory check is the authoritative one (the schema only catches a
 * trailing slash); whole-file masking has no meaning for a directory.
 */
export function buildMaskedFileBinds(
  files: readonly CredentialFileConfig[],
  allowedDomains: readonly string[],
  registry: SentinelRegistry,
  store: MaskedFileStore,
): MaskedFileBind[] {
  const binds: MaskedFileBind[] = []
  for (const f of files) {
    if (f.mode !== 'mask') continue
    const realPath = normalizePathForSandbox(f.path)

    let content: string
    try {
      const stat = fs.statSync(realPath)
      if (stat.isDirectory()) {
        logForDebugging(
          `[credential-mask] Skipping masked file entry that resolves to ` +
            `a directory: ${f.path} — use mode "deny" for directories.`,
          { level: 'warn' },
        )
        continue
      }
      // Read as bytes first: a utf8 read silently maps invalid sequences
      // to U+FFFD, so the sentinel would round-trip to corrupted bytes at
      // the proxy. Whole-file masking is for token files; reject binary.
      const raw = fs.readFileSync(realPath)
      content = raw.toString('utf8')
      if (Buffer.byteLength(content, 'utf8') !== raw.length) {
        logForDebugging(
          `[credential-mask] Skipping masked file with non-UTF-8 content ` +
            `(binary credential files are not supported in whole-file ` +
            `mask mode): ${f.path}`,
          { level: 'warn' },
        )
        continue
      }
    } catch (err) {
      logForDebugging(
        `[credential-mask] Skipping masked file (unreadable on host): ` +
          `${f.path} — ${(err as Error).message}`,
      )
      continue
    }

    const injectHosts = f.injectHosts ?? allowedDomains
    const key = FILE_KEY_PREFIX + realPath
    const sentinel = registry.register(key, content, injectHosts)
    const fakePath = store.write(key, sentinel)
    binds.push({ realPath, fakePath })
  }
  return binds
}

export const MASKED_FILE_STORE_PREFIX = 'srt-credmask-'
