import { describe, test, expect, afterAll } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createMitmCA } from '../../src/sandbox/mitm-ca.js'

// Committed test-only CA — see test/fixtures/tls-terminate/README.md.
const FIXTURE_DIR = join(import.meta.dir, '..', 'fixtures', 'tls-terminate')
const certPath = join(FIXTURE_DIR, 'ca.crt')
const keyPath = join(FIXTURE_DIR, 'ca.key')
const certPem = readFileSync(certPath, 'utf8')
const keyPem = readFileSync(keyPath, 'utf8')

describe('mitm-ca: createMitmCA', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'srt-mitm-ca-'))
  const junkPath = join(scratch, 'junk.txt')
  writeFileSync(junkPath, 'not pem\n')

  afterAll(() => {
    rmSync(scratch, { recursive: true, force: true })
  })

  test('returns parsed cert+key from a real CA', () => {
    const ca = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(ca.certPath).toBe(certPath)
    expect(ca.keyPath).toBe(keyPath)
    expect(ca.certPem).toBe(certPem)
    expect(ca.keyPem).toBe(keyPem)
    expect(ca.certPem).toContain('-----BEGIN CERTIFICATE-----')
    // openssl req -nodes emits PKCS8 ("PRIVATE KEY"); the loader's regex also
    // accepts PKCS1 "RSA PRIVATE KEY" / "EC PRIVATE KEY".
    expect(ca.keyPem).toMatch(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/)
    expect(ca.cert.subject.getField('CN').value).toContain('srt-test-ca')
    expect(ca.key.n).toBeDefined() // RSA modulus present
  })

  test('is a pure factory: each call returns a new instance', () => {
    const a = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    const b = createMitmCA({ caCertPath: certPath, caKeyPath: keyPath })
    expect(b).not.toBe(a)
    expect(b.certPem).toBe(a.certPem)
  })

  test('throws with field+path+code when cert path is missing', () => {
    const missing = join(scratch, 'nope.crt')
    expect(() =>
      createMitmCA({ caCertPath: missing, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: cannot read .*nope\.crt \(ENOENT\)/)
  })

  test('throws with field+path+code when key path is missing', () => {
    const missing = join(scratch, 'nope.key')
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: missing }),
    ).toThrow(/tlsTerminate\.caKeyPath: cannot read .*nope\.key \(ENOENT\)/)
  })

  test('throws when cert file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: junkPath, caKeyPath: keyPath }),
    ).toThrow(/tlsTerminate\.caCertPath: .* is not a PEM CERTIFICATE/)
  })

  test('throws when key file is not PEM', () => {
    expect(() =>
      createMitmCA({ caCertPath: certPath, caKeyPath: junkPath }),
    ).toThrow(/tlsTerminate\.caKeyPath: .* is not a PEM PRIVATE KEY/)
  })

  test('throws when cert and key are swapped', () => {
    expect(() =>
      createMitmCA({ caCertPath: keyPath, caKeyPath: certPath }),
    ).toThrow(/is not a PEM CERTIFICATE/)
  })
})
