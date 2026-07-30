/**
 * Unit tests for the cross-signing bootstrap helper.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import fs from "fs"
import os from "os"
import path from "path"
import { ensureCrossSigningBootstrapped } from "../../connectors/matrix-cross-signing"

const USER_ID = "@opencode:example.org"
const DEVICE_ID = "TESTDEVICE"

function fakeDeviceKeyObject() {
  return {
    user_id: USER_ID,
    device_id: DEVICE_ID,
    algorithms: ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
    keys: {
      [`curve25519:${DEVICE_ID}`]: "curve25519pubkeyplaceholder",
      [`ed25519:${DEVICE_ID}`]: "ed25519pubkeyplaceholder",
    },
    signatures: {
      [USER_ID]: { [`ed25519:${DEVICE_ID}`]: "deviceselfsignatureplaceholder" },
    },
  }
}

describe("ensureCrossSigningBootstrapped", () => {
  let storagePath: string
  let logs: string[]
  let errors: Array<{ msg: string; err: any }>

  beforeEach(() => {
    storagePath = fs.mkdtempSync(path.join(os.tmpdir(), "xsign-test-"))
    logs = []
    errors = []
  })

  afterEach(() => {
    fs.rmSync(storagePath, { recursive: true, force: true })
  })

  function log(msg: string) {
    logs.push(msg)
  }
  function logError(msg: string, err?: any) {
    errors.push({ msg, err })
  }

  test("skips entirely when master key already exists", async () => {
    let calls = 0
    const matrix = {
      doRequest: async () => {
        calls++
        return { master_keys: { [USER_ID]: { user_id: USER_ID } } }
      },
    } as any

    await ensureCrossSigningBootstrapped({
      matrix,
      userId: USER_ID,
      password: "irrelevant",
      deviceId: DEVICE_ID,
      storagePath,
      log,
      logError,
    })

    expect(calls).toBe(1)
    expect(logs.some(l => l.includes("already bootstrapped"))).toBe(true)
    expect(fs.existsSync(path.join(storagePath, "cross-signing-keys.json"))).toBe(false)
  })

  test("skips and warns when no password is configured", async () => {
    const matrix = {
      doRequest: async () => ({ master_keys: {} }),
    } as any

    await ensureCrossSigningBootstrapped({
      matrix,
      userId: USER_ID,
      password: undefined,
      deviceId: DEVICE_ID,
      storagePath,
      log,
      logError,
    })

    expect(logs.some(l => l.includes("MATRIX_PASSWORD is not set"))).toBe(true)
    expect(errors.length).toBe(0)
  })

  test("bootstraps, self-signs the device, and persists private keys", async () => {
    const calls: Array<{ endpoint: string; body: any }> = []
    const matrix = {
      doRequest: async (_method: string, endpoint: string, _qs: any, body: any) => {
        calls.push({ endpoint, body })
        if (endpoint === "/_matrix/client/v3/keys/query") {
          if (body.device_keys[USER_ID].length === 0) {
            // First call: checking whether cross-signing already exists
            return { master_keys: {} }
          }
          // Second call: fetching this device's own key data to sign
          return { device_keys: { [USER_ID]: { [DEVICE_ID]: fakeDeviceKeyObject() } } }
        }
        if (endpoint === "/_matrix/client/v3/keys/device_signing/upload") {
          expect(body.auth?.type).toBe("m.login.password")
          expect(body.master_key.usage).toEqual(["master"])
          return {}
        }
        if (endpoint === "/_matrix/client/v3/keys/signatures/upload") {
          const signedDevice = body[USER_ID][DEVICE_ID]
          // Original self-signature must be preserved alongside the new one
          expect(signedDevice.signatures[USER_ID][`ed25519:${DEVICE_ID}`]).toBe("deviceselfsignatureplaceholder")
          const sigKeys = Object.keys(signedDevice.signatures[USER_ID])
          expect(sigKeys.length).toBe(2)
          return {}
        }
        throw new Error("unexpected endpoint: " + endpoint)
      },
    } as any

    await ensureCrossSigningBootstrapped({
      matrix,
      userId: USER_ID,
      password: "hunter2",
      deviceId: DEVICE_ID,
      storagePath,
      log,
      logError,
    })

    expect(errors.length).toBe(0)
    expect(logs.some(l => l.includes("Cross-signing bootstrapped"))).toBe(true)

    const keysFile = path.join(storagePath, "cross-signing-keys.json")
    expect(fs.existsSync(keysFile)).toBe(true)
    const saved = JSON.parse(fs.readFileSync(keysFile, "utf-8"))
    expect(saved.master_priv_jwk.crv).toBe("Ed25519")
    expect(saved.self_signing_priv_jwk.crv).toBe("Ed25519")
    expect(saved.user_signing_priv_jwk.crv).toBe("Ed25519")

    const endpoints = calls.map(c => c.endpoint)
    expect(endpoints).toEqual([
      "/_matrix/client/v3/keys/query",
      "/_matrix/client/v3/keys/device_signing/upload",
      "/_matrix/client/v3/keys/query",
      "/_matrix/client/v3/keys/signatures/upload",
    ])
  })

  test("retries a UIA-protected request once with a session id if the server demands one", async () => {
    let uploadAttempts = 0
    const matrix = {
      doRequest: async (_method: string, endpoint: string, _qs: any, body: any) => {
        if (endpoint === "/_matrix/client/v3/keys/query") {
          if (body.device_keys[USER_ID].length === 0) return { master_keys: {} }
          return { device_keys: { [USER_ID]: { [DEVICE_ID]: fakeDeviceKeyObject() } } }
        }
        if (endpoint === "/_matrix/client/v3/keys/device_signing/upload") {
          uploadAttempts++
          if (uploadAttempts === 1) {
            const err: any = new Error("M_UNKNOWN: unauthorized")
            err.body = { flows: [{ stages: ["m.login.password"] }], session: "abc123" }
            throw err
          }
          expect(body.auth.session).toBe("abc123")
          return {}
        }
        if (endpoint === "/_matrix/client/v3/keys/signatures/upload") return {}
        throw new Error("unexpected endpoint: " + endpoint)
      },
    } as any

    await ensureCrossSigningBootstrapped({
      matrix,
      userId: USER_ID,
      password: "hunter2",
      deviceId: DEVICE_ID,
      storagePath,
      log,
      logError,
    })

    expect(uploadAttempts).toBe(2)
    expect(errors.length).toBe(0)
  })

  test("logs an error but does not throw when the homeserver rejects the bootstrap", async () => {
    const matrix = {
      doRequest: async (_method: string, endpoint: string) => {
        if (endpoint === "/_matrix/client/v3/keys/query") return { master_keys: {} }
        throw new Error("boom")
      },
    } as any

    await expect(
      ensureCrossSigningBootstrapped({
        matrix,
        userId: USER_ID,
        password: "hunter2",
        deviceId: DEVICE_ID,
        storagePath,
        log,
        logError,
      }),
    ).resolves.toBeUndefined()

    expect(errors.length).toBe(1)
    expect(errors[0].msg).toContain("bootstrap failed")
  })
})
