export interface SingleTrackRequest {
  clientPubkey: string;
  trackId: string;
  r: string;
  /**
   * Unix timestamp in seconds.
   */
  timestamp: number;
}

/**
 * Single track request plus the signature from a host.
 */
export interface SingleTrackLicense extends SingleTrackRequest {
  hostSignature: string;
  hostPubkey: string;
}

/**
 * Signed certificate along with the signature of the client that made the request.
 */
export interface SingleTrackReceipt extends SingleTrackLicense {
  clientSignature: string;
}
