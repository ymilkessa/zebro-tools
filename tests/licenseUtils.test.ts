import {
  SingleTrackRequest,
  SingleTrackLicense,
  SingleTrackReceipt,
} from "../src/types";
import {
  isTrackRequestValid,
  isTrackRequestCurrent,
  getRequestHash,
  approveRequest,
  isTrackLicenseValid,
  confirmLicense,
  isTrackReceiptValid,
  getRandomR,
} from "../src/licenseUtils";
import {
  generatePrivateKey,
  getPublicKey,
  getTimeInSeconds,
} from "./testUtils";

describe("licenseUtils", () => {
  let hostPrivkey: string;
  let clientPrivkey: string;
  let clientPubkey: string;
  let hostPubkey: string;
  let randomUuid: string;

  beforeAll(() => {
    hostPrivkey = generatePrivateKey();
    hostPubkey = getPublicKey(hostPrivkey);
    clientPrivkey = generatePrivateKey();
    clientPubkey = getPublicKey(clientPrivkey);
    randomUuid = getRandomR();
  });

  describe("isTrackRequestValid", () => {
    it("should return true for a valid request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      expect(isTrackRequestValid(req)).toBe(true);
    });

    it("should return false for a request with an invalid pubkey", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: "invalid-pubkey",
        r: randomUuid,
        trackId: "some-track-id",
      };
      expect(isTrackRequestValid(req)).toBe(false);
    });

    it("should return false for a request with an invalid r", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: "invalid-r",
        trackId: "some-track-id",
      };
      expect(isTrackRequestValid(req)).toBe(false);
    });
  });

  describe("isTrackRequestCurrent", () => {
    it("should return true for a current request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      expect(isTrackRequestCurrent(req)).toBe(true);
    });

    it("should return false for an expired request.", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds() - 6 * 60, // 6 minutes ago
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      expect(isTrackRequestCurrent(req)).toBe(false);
    });

    it("should return false for a request in the future.", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds() + 6 * 60, // 6 minutes from now
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      expect(isTrackRequestCurrent(req)).toBe(false);
    });
  });

  describe("approveRequest", () => {
    it("should return a valid license for a valid request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      expect(license).not.toBeNull();
      expect(isTrackLicenseValid(license!)).toBe(true);
      expect(license!.hostPubkey).toBe(hostPubkey);
    });

    it("should return null for an invalid request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: "invalid-pubkey",
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      expect(license).toBeNull();
    });
  });

  describe("isTrackLicenseValid", () => {
    it("should return true for a valid license", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      expect(isTrackLicenseValid(license!)).toBe(true);
    });

    it("should return false for a license with an invalid signature", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const randomStr = getRandomR();
      const license: SingleTrackLicense = {
        ...req,
        hostPubkey,
        hostSignature: randomStr + randomStr + randomStr + randomStr,
      };
      expect(isTrackLicenseValid(license)).toBe(false);
    });
  });

  describe("getRequestHash", () => {
    it("should return a Uint8Array of length 32", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: getPublicKey(generatePrivateKey()),
        r: randomUuid,
        trackId: "some-track-id",
      };
      const hash = getRequestHash(req);
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    it("should return the same hash for the same request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: getPublicKey(generatePrivateKey()),
        r: randomUuid,
        trackId: "some-track-id",
      };
      const hash1 = getRequestHash(req);
      const hash2 = getRequestHash(req);
      expect(hash1).toEqual(hash2);
    });

    it("should return different hashes for different requests", () => {
      const req1: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: getPublicKey(generatePrivateKey()),
        r: getRandomR(),
        trackId: "some-track-id",
      };
      const req2: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: getPublicKey(generatePrivateKey()),
        r: getRandomR(),
        trackId: "some-other-track-id",
      };
      const hash1 = getRequestHash(req1);
      const hash2 = getRequestHash(req2);
      expect(hash1).not.toEqual(hash2);
    });
  });

  describe("approveRequest", () => {
    it("should return a valid license for a valid request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      expect(license).not.toBeNull();
      expect(isTrackLicenseValid(license!)).toBe(true);
      expect(license!.hostPubkey).toBe(hostPubkey);
    });

    it("should return null for an invalid request", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey: "invalid-pubkey",
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      expect(license).toBeNull();
    });
  });

  describe("confirmLicense", () => {
    it("should return a valid receipt for a valid license", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      const receipt = confirmLicense(license!, clientPrivkey);
      expect(receipt).not.toBeNull();
      expect(isTrackReceiptValid(receipt!)).toBe(true);
      expect(receipt!.clientPubkey).toBe(clientPubkey);
    });

    it("should return null for an invalid license", () => {
      const clientPrivkey = generatePrivateKey();
      const randomStr = getRandomR();
      const license: SingleTrackLicense = {
        timestamp: getTimeInSeconds(),
        hostPubkey: "invalid-pubkey",
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
        hostSignature: randomStr + randomStr + randomStr + randomStr,
      };
      const receipt = confirmLicense(license, clientPrivkey);
      expect(receipt).toBeNull();
    });
  });

  describe("isTrackReceiptValid", () => {
    it("should return true for a valid receipt", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      const receipt = confirmLicense(license!, clientPrivkey);
      expect(isTrackReceiptValid(receipt!)).toBe(true);
    });

    it("should return false for a receipt with an invalid signature", () => {
      const req: SingleTrackRequest = {
        timestamp: getTimeInSeconds(),
        clientPubkey,
        r: randomUuid,
        trackId: "some-track-id",
      };
      const license = approveRequest(req, hostPrivkey);
      const receipt: SingleTrackReceipt = {
        ...license!,
        clientSignature: getRandomR() + getRandomR(),
        clientPubkey,
      };
      expect(isTrackReceiptValid(receipt)).toBe(false);
    });
  });

  describe("getRandomR", () => {
    it("should return a string of length 32", () => {
      const r = getRandomR();
      expect(r).toBeInstanceOf(String);
      expect(r.length).toBe(32);
    });
  });
});
