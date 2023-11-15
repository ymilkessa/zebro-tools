import { generatePrivateKey, getPublicKey, getRandomUuid } from "./utils";
import {
  SingleTrackRequest,
  approveRequest,
  confirmLicense,
} from "../dist/index";

/**
 * --- Client ---
 */
const clientk = generatePrivateKey();
const request = {
  clientPubkey: getPublicKey(clientk),
  timestamp: Math.floor(Date.now() / 1000),
  r: getRandomUuid(),
  trackId: "some track id",
} as SingleTrackRequest;

/**
 * --- Host ---
 */
const hostk = generatePrivateKey();
const license = approveRequest(request, hostk);
console.log("License: \n" + JSON.stringify(license, null, 2));

/**
 * --- Client ---
 */
const receipt = confirmLicense(license!, clientk);
console.log("Receipt: \n" + JSON.stringify(receipt, null, 2));
