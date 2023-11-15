import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import {
  SingleTrackLicense,
  SingleTrackReceipt,
  SingleTrackRequest,
} from "./types";

export const utf8Encoder = new TextEncoder();

/**
 * Ensures the following:
 * 1. The request timestamp is within 5 minutes of the current time.
 * 2. The request pubkey is a valid 64-character hex string.
 * 3. The random string r is a valid 32-character hex string.
 * 4. And the track id is a valid non-empty string.
 */
export function isTrackRequestValid(req: SingleTrackRequest) {
  if (typeof req.timestamp !== "number") return false;
  if (typeof req.clientPubkey !== "string") return false;
  if (typeof req.r !== "string") return false;
  if (typeof req.trackId !== "string") return false;
  if (req.clientPubkey.length !== 64) return false;
  if (req.r.length !== 32) return false;
  if (req.trackId.length === 0) return false;
  return true;
}

export function isTrackRequestCurrent(req: SingleTrackRequest) {
  const now = Math.floor(Date.now() / 1000);
  if (typeof req.timestamp !== "number") return false;
  if (req.timestamp < now - 300) return false;
  if (req.timestamp > now + 300) return false;
  return true;
}

export function getRequestHash(req: SingleTrackRequest): Uint8Array {
  if (!isTrackRequestValid(req))
    throw new Error("can't serialize invalid request");
  const serializedReq = JSON.stringify([
    req.clientPubkey,
    req.trackId,
    req.r,
    req.timestamp,
  ]);
  return sha256(utf8Encoder.encode(serializedReq));
}

/**
 * (To be used by host) Signs the request in the approprate serialization format and returns the signature.
 * If the request is invalid, returns null.
 */
export function approveRequest(
  req: SingleTrackRequest,
  pk: string
): SingleTrackLicense | null {
  if (!isTrackRequestValid(req) || !isTrackRequestCurrent(req)) return null;
  const hash = getRequestHash(req);
  const sig = schnorr.sign(hash, pk);
  const hostPubkey = bytesToHex(schnorr.getPublicKey(pk));
  return { ...req, hostSignature: bytesToHex(sig), hostPubkey };
}

export function isTrackLicenseValid(req: SingleTrackLicense): boolean {
  if (!isTrackRequestValid(req)) return false;
  if (typeof req.hostSignature !== "string") return false;
  if (req.hostSignature.length !== 128) return false;
  if (typeof req.hostPubkey !== "string") return false;
  if (req.hostPubkey.length !== 64) return false;
  const hash = getRequestHash(req);
  return schnorr.verify(req.hostSignature, hash, req.hostPubkey);
}

/**
 * (To be used by client) Signs the approved license and returns an object containing the signature
 * along with the license.
 */
export function confirmLicense(
  license: SingleTrackLicense,
  pk: string
): SingleTrackReceipt | null {
  if (!isTrackLicenseValid(license)) return null;
  const clientSig = schnorr.sign(license.hostSignature, pk);
  const clientPubkey = bytesToHex(schnorr.getPublicKey(pk));
  return { ...license, clientSignature: bytesToHex(clientSig), clientPubkey };
}

export function isTrackReceiptValid(receipt: SingleTrackReceipt): boolean {
  if (!isTrackLicenseValid(receipt)) return false;
  if (typeof receipt.clientSignature !== "string") return false;
  if (receipt.clientSignature.length !== 128) return false;
  if (typeof receipt.clientPubkey !== "string") return false;
  if (receipt.clientPubkey.length !== 64) return false;
  return schnorr.verify(
    receipt.clientSignature,
    receipt.hostSignature,
    receipt.clientPubkey
  );
}
