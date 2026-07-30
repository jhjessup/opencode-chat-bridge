/**
 * One-time, idempotent cross-signing bootstrap for the bot's own Matrix account.
 *
 * Without cross-signing keys, clients like Element show the account as
 * "User verification is unavailable" and every message the bot sends is
 * flagged as sent by "a device not verified by its owner" -- there's no
 * verify button to clear it, because there's nothing to verify against.
 * A real client bootstraps this automatically the first time you log into
 * a fresh account; a headless bot has no GUI to do that, so we do the
 * equivalent over the raw API here.
 *
 * IMPORTANT: this must only ever run when the account has no existing
 * master key. Re-bootstrapping replaces the account's cross-signing
 * identity, which invalidates any trust a user already extended and
 * triggers Matrix's "the security of this conversation may be
 * compromised" warning for anyone who had verified the previous identity.
 * The existing-master-key check below is what makes it safe to call this
 * on every startup.
 */
import * as crypto from "crypto"
import * as fs from "fs"
import * as path from "path"
import type { MatrixClient } from "matrix-bot-sdk"

export interface CrossSigningBootstrapOptions {
  matrix: MatrixClient
  userId: string
  password: string | undefined
  deviceId: string
  storagePath: string
  log: (msg: string) => void
  logError: (msg: string, err?: any) => void
}

function canonicalize(value: any): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]"
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort()
    return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}"
  }
  return JSON.stringify(value)
}

function toUnpaddedBase64(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/, "")
}

function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519")
  const jwk = publicKey.export({ format: "jwk" }) as { x: string }
  const pubB64 = toUnpaddedBase64(Buffer.from(jwk.x, "base64url"))
  return { privateKey, pubB64 }
}

/** Signs `obj` (minus its own signatures/unsigned fields) per the Matrix signing spec. */
function signObject(obj: Record<string, any>, privateKey: crypto.KeyObject): string {
  const toSign = { ...obj }
  delete toSign.signatures
  delete toSign.unsigned
  const canonical = canonicalize(toSign)
  return toUnpaddedBase64(crypto.sign(null, Buffer.from(canonical, "utf-8"), privateKey))
}

function usernameFromUserId(userId: string): string {
  return userId.split(":")[0].replace("@", "")
}

/** POSTs a UIA-protected endpoint, retrying once with a session ID if the server demands one. */
async function requestWithUia(
  matrix: MatrixClient,
  endpoint: string,
  body: Record<string, any>,
  auth: Record<string, any>,
): Promise<any> {
  try {
    return await matrix.doRequest("POST", endpoint, null, { ...body, auth })
  } catch (err: any) {
    const session = err?.body?.session
    if (session) {
      return await matrix.doRequest("POST", endpoint, null, { ...body, auth: { ...auth, session } })
    }
    throw err
  }
}

export async function ensureCrossSigningBootstrapped(opts: CrossSigningBootstrapOptions): Promise<void> {
  const { matrix, userId, password, deviceId, storagePath, log, logError } = opts
  try {
    const existing = await matrix.doRequest("POST", "/_matrix/client/v3/keys/query", null, {
      device_keys: { [userId]: [] },
    })
    if (existing?.master_keys?.[userId]) {
      log("[XSIGN] Cross-signing already bootstrapped, skipping")
      return
    }

    if (!password) {
      log(
        "[XSIGN] This account has no cross-signing keys and MATRIX_PASSWORD is not set, so it can't be " +
          "bootstrapped automatically (Matrix's User-Interactive Auth requires a password for this endpoint). " +
          "Messages from this device will show as unverified until this is set up.",
      )
      return
    }

    log("[XSIGN] No cross-signing keys found for this account -- bootstrapping now (one-time)...")

    const master = generateSigningKeyPair()
    const selfSigning = generateSigningKeyPair()
    const userSigning = generateSigningKeyPair()
    const masterKeyId = "ed25519:" + master.pubB64

    const master_key = {
      user_id: userId,
      usage: ["master"],
      keys: { [masterKeyId]: master.pubB64 },
    }
    const self_signing_key: Record<string, any> = {
      user_id: userId,
      usage: ["self_signing"],
      keys: { ["ed25519:" + selfSigning.pubB64]: selfSigning.pubB64 },
    }
    const user_signing_key: Record<string, any> = {
      user_id: userId,
      usage: ["user_signing"],
      keys: { ["ed25519:" + userSigning.pubB64]: userSigning.pubB64 },
    }
    self_signing_key.signatures = { [userId]: { [masterKeyId]: signObject(self_signing_key, master.privateKey) } }
    user_signing_key.signatures = { [userId]: { [masterKeyId]: signObject(user_signing_key, master.privateKey) } }

    const auth = {
      type: "m.login.password",
      identifier: { type: "m.id.user", user: usernameFromUserId(userId) },
      password,
    }

    await requestWithUia(
      matrix,
      "/_matrix/client/v3/keys/device_signing/upload",
      { master_key, self_signing_key, user_signing_key },
      auth,
    )

    // Self-sign this device: fetch its current key data and add a signature from the new self-signing key.
    const keysResp = await matrix.doRequest("POST", "/_matrix/client/v3/keys/query", null, {
      device_keys: { [userId]: [deviceId] },
    })
    const deviceKeyObj = keysResp?.device_keys?.[userId]?.[deviceId]
    if (!deviceKeyObj) {
      throw new Error(`Could not fetch this device's own key data (${deviceId}) after uploading cross-signing keys`)
    }

    const deviceSignature = signObject(deviceKeyObj, selfSigning.privateKey)
    const signedDeviceKeyObj = {
      ...deviceKeyObj,
      signatures: {
        ...deviceKeyObj.signatures,
        [userId]: {
          ...deviceKeyObj.signatures?.[userId],
          ["ed25519:" + selfSigning.pubB64]: deviceSignature,
        },
      },
    }
    delete signedDeviceKeyObj.unsigned

    await matrix.doRequest("POST", "/_matrix/client/v3/keys/signatures/upload", null, {
      [userId]: { [deviceId]: signedDeviceKeyObj },
    })

    fs.mkdirSync(storagePath, { recursive: true })
    const keysFile = path.join(storagePath, "cross-signing-keys.json")
    fs.writeFileSync(
      keysFile,
      JSON.stringify({
        master_priv_jwk: master.privateKey.export({ format: "jwk" }),
        self_signing_priv_jwk: selfSigning.privateKey.export({ format: "jwk" }),
        user_signing_priv_jwk: userSigning.privateKey.export({ format: "jwk" }),
      }),
      { mode: 0o600 },
    )

    log(
      `[XSIGN] Cross-signing bootstrapped and device ${deviceId} self-signed. ` +
        `master=${master.pubB64} self_signing=${selfSigning.pubB64} user_signing=${userSigning.pubB64}. ` +
        `Private keys saved to ${keysFile}.`,
    )
  } catch (err: any) {
    logError(
      "[XSIGN] Cross-signing bootstrap failed (bot will keep running; messages may show as unverified " +
        "until this succeeds on a future restart):",
      err.message || err,
    )
  }
}
