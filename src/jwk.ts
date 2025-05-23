// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SimpleFetcher, Fetcher, fetch } from "./https.js";
import { JwtHeader, JwtPayload } from "./jwt-model.js";
import {
  Json,
  JsonObject,
  isJsonObject,
  safeJsonParse,
} from "./safe-json-parse.js";
import {
  JwkValidationError,
  JwksNotAvailableInCacheError,
  JwksValidationError,
  KidNotFoundInJwksError,
  WaitPeriodNotYetEndedJwkError,
  JwtWithoutValidKidError,
  JwkInvalidUseError,
  JwkInvalidKtyError,
} from "./error.js";
import { nodeWebCompat } from "#node-web-compat";
import {
  assertStringArrayContainsString,
  assertStringEquals,
} from "./assert.js";

interface DecomposedJwt {
  header: JwtHeader;
  payload: JwtPayload;
}

const optionalJwkFieldNames = [
  "use", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
  "alg", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
  "kid", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
  "n", // https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1
  "e", // https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2
  "x", // https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2
  "y", // https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3
  "crv", //https:// datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
] as const;
const mandatoryJwkFieldNames = [
  "kty", // https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
] as const;

type OptionalJwkFieldNames = (typeof optionalJwkFieldNames)[number];
type MandatoryJwkFieldNames = (typeof mandatoryJwkFieldNames)[number];
type OptionalJwkFields = {
  [key in OptionalJwkFieldNames]?: string;
};
type MandatoryJwkFields = {
  [key in MandatoryJwkFieldNames]: string;
};

export type Jwk = OptionalJwkFields & MandatoryJwkFields & JsonObject;

type RsaSignatureJwk = Jwk & {
  use?: "sig";
  kty: "RSA";
  n: string;
  e: string;
};

type EcSignatureJwk = Jwk & {
  use?: "sig";
  kty: "EC";
  crv: "P-256" | "P-384" | "P-521";
  x: string;
  y: string;
};

type OkpSignatureJwk = Jwk & {
  use?: "sig";
  /**
   * Octet Key Pair: https://www.rfc-editor.org/rfc/rfc8037.html#section-2
   */
  kty: "OKP";
  /**
   * Edwards-curves, for EdDSA: https://www.rfc-editor.org/rfc/rfc8037.html#section-3.1
   */
  crv: "Ed25519" | "Ed448";
  x: string;
};

export type SignatureJwk = RsaSignatureJwk | EcSignatureJwk | OkpSignatureJwk;

export type JwkWithKid = Jwk & {
  kid: string;
};

export function findJwkInJwks(jwks: Jwks, kid: string): JwkWithKid | undefined {
  return jwks.keys.find(
    (jwk) => jwk.kid != null && jwk.kid === kid
  ) as JwkWithKid;
}

interface JwksFields {
  keys: readonly Jwk[];
}

export type Jwks = JwksFields & JsonObject;
export interface JwksCache {
  getJwk(jwksUri: string, decomposedJwt: DecomposedJwt): Promise<JwkWithKid>;
  getCachedJwk(jwksUri: string, decomposedJwt: DecomposedJwt): JwkWithKid;
  addJwks(jwksUri: string, jwks: Jwks): void;
  getJwks(jwksUri: string): Promise<Jwks>;
}

/**
 * UTF-8 decode binary data and then JSON parse it, and ensure it is a JWKS
 * @param jwksBin
 * @returns Jwks
 */
export type JwksParser = (jwksBin: ArrayBuffer) => Jwks;

/**
 * UTF-8 decode binary data and then JSON parse it
 * @param jwksBin
 * @returns Jwks
 */
const parseJwks: JwksParser = function (jwksBin: ArrayBuffer) {
  let jwks: Json;
  try {
    const jwksText = new TextDecoder("utf8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(jwksBin);
    jwks = safeJsonParse(jwksText);
  } catch (err) {
    throw new JwksValidationError(`JWKS could not be parsed as JSON: ${err}`);
  }
  assertIsJwks(jwks);
  return jwks;
};

export async function fetchJwks(jwksUri: string): Promise<Jwks> {
  return fetch(jwksUri).then(parseJwks);
}

export async function fetchJwk(
  jwksUri: string,
  decomposedJwt: DecomposedJwt
): Promise<JwkWithKid> {
  if (!decomposedJwt.header.kid) {
    throw new JwtWithoutValidKidError(
      "JWT header does not have valid kid claim"
    );
  }
  const jwks = await fetchJwks(jwksUri);
  const jwk = findJwkInJwks(jwks, decomposedJwt.header.kid);
  if (!jwk) {
    throw new KidNotFoundInJwksError(
      `JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`
    );
  }
  return jwk;
}

export function assertIsJwks(jwks: Json): asserts jwks is Jwks {
  if (!jwks) {
    throw new JwksValidationError("JWKS empty");
  }
  if (!isJsonObject(jwks)) {
    throw new JwksValidationError("JWKS should be an object");
  }
  if (!Object.keys(jwks).includes("keys")) {
    throw new JwksValidationError("JWKS does not include keys");
  }
  if (!Array.isArray((jwks as { keys: Json }).keys)) {
    throw new JwksValidationError("JWKS keys should be an array");
  }
  for (const jwk of (jwks as { keys: Json[] }).keys) {
    assertIsJwk(jwk);
  }
}

export function assertIsSignatureJwk(jwk: Jwk): asserts jwk is SignatureJwk {
  assertStringArrayContainsString(
    "JWK kty",
    jwk.kty,
    ["EC", "RSA", "OKP"],
    JwkInvalidKtyError
  );
  if (jwk.kty === "EC") {
    assertIsEsSignatureJwk(jwk);
  } else if (jwk.kty === "RSA") {
    assertIsRsaSignatureJwk(jwk);
  } else if (jwk.kty === "OKP") {
    assertIsEdDSASignatureJwk(jwk);
  }
}

function assertIsEdDSASignatureJwk(jwk: Jwk): asserts jwk is OkpSignatureJwk {
  // Check JWK use
  if (jwk.use) {
    assertStringEquals("JWK use", jwk.use, "sig", JwkInvalidUseError);
  }

  // Check JWK kty
  assertStringEquals("JWK kty", jwk.kty, "OKP", JwkInvalidKtyError);

  // Check Curve (crv) has a value
  if (!jwk.crv) throw new JwkValidationError("Missing Curve (crv)");

  // Check X Coordinate (x) has a value
  if (!jwk.x) throw new JwkValidationError("Missing X Coordinate (x)");
}

function assertIsEsSignatureJwk(jwk: Jwk): asserts jwk is EcSignatureJwk {
  // Check JWK use
  if (jwk.use) {
    assertStringEquals("JWK use", jwk.use, "sig", JwkInvalidUseError);
  }

  // Check JWK kty
  assertStringEquals("JWK kty", jwk.kty, "EC", JwkInvalidKtyError);

  // Check Curve (crv) has a value
  if (!jwk.crv) throw new JwkValidationError("Missing Curve (crv)");

  // Check X Coordinate (x) has a value
  if (!jwk.x) throw new JwkValidationError("Missing X Coordinate (x)");

  // Check Y Coordinate (y) has a value
  if (!jwk.y) throw new JwkValidationError("Missing Y Coordinate (y)");
}

function assertIsRsaSignatureJwk(jwk: Jwk): asserts jwk is RsaSignatureJwk {
  // Check JWK use
  if (jwk.use) {
    assertStringEquals("JWK use", jwk.use, "sig", JwkInvalidUseError);
  }

  // Check JWK kty
  assertStringEquals("JWK kty", jwk.kty, "RSA", JwkInvalidKtyError);

  // Check modulus (n) has a value
  if (!jwk.n) throw new JwkValidationError("Missing modulus (n)");

  // Check exponent (e) has a value
  if (!jwk.e) throw new JwkValidationError("Missing exponent (e)");
}

export function assertIsJwk(jwk: Json): asserts jwk is Jwk {
  if (!jwk) {
    throw new JwkValidationError("JWK empty");
  }
  if (!isJsonObject(jwk)) {
    throw new JwkValidationError("JWK should be an object");
  }

  for (const field of mandatoryJwkFieldNames) {
    // disable eslint rule because `field` is trusted
    // eslint-disable-next-line security/detect-object-injection
    if (typeof jwk[field] !== "string") {
      throw new JwkValidationError(`JWK ${field} should be a string`);
    }
  }
  for (const field of optionalJwkFieldNames) {
    // disable eslint rule because `field` is trusted
    // eslint-disable-next-line security/detect-object-injection
    if (field in jwk && typeof jwk[field] !== "string") {
      throw new JwkValidationError(`JWK ${field} should be a string`);
    }
  }
}

export function isJwks(jwks: Json): jwks is Jwks {
  try {
    assertIsJwks(jwks);
    return true;
  } catch {
    return false;
  }
}

export function isJwk(jwk: Json): jwk is Jwk {
  try {
    assertIsJwk(jwk);
    return true;
  } catch {
    return false;
  }
}

export interface PenaltyBox {
  wait: (jwksUri: string, kid: string) => Promise<void>;
  registerFailedAttempt: (jwksUri: string, kid: string) => void;
  registerSuccessfulAttempt: (jwksUri: string, kid: string) => void;
}

type JwksUri = string;

export class SimplePenaltyBox implements PenaltyBox {
  waitSeconds: number;
  private waitingUris: Map<
    JwksUri,
    ReturnType<typeof nodeWebCompat.setTimeoutUnref>
  > = new Map();
  constructor(props?: { waitSeconds?: number }) {
    this.waitSeconds = props?.waitSeconds ?? 10;
  }
  async wait(jwksUri: string): Promise<void> {
    // SimplePenaltyBox does not actually wait but bluntly throws an error
    // Any waiting and retries are expected to be done upstream (e.g. in the browser / app)
    if (this.waitingUris.has(jwksUri)) {
      throw new WaitPeriodNotYetEndedJwkError(
        "Not allowed to fetch JWKS yet, still waiting for back off period to end"
      );
    }
  }
  release(jwksUri: string): void {
    const i = this.waitingUris.get(jwksUri);
    if (i) {
      clearTimeout(i);
      this.waitingUris.delete(jwksUri);
    }
  }
  registerFailedAttempt(jwksUri: string): void {
    const i = nodeWebCompat.setTimeoutUnref(() => {
      this.waitingUris.delete(jwksUri);
    }, this.waitSeconds * 1000);
    this.waitingUris.set(jwksUri, i);
  }
  registerSuccessfulAttempt(jwksUri: string): void {
    this.release(jwksUri);
  }
}

export class SimpleJwksCache implements JwksCache {
  fetcher: Fetcher;
  penaltyBox: PenaltyBox;
  jwksParser: JwksParser;
  private jwksCache: Map<JwksUri, Jwks> = new Map();
  private fetchingJwks: Map<JwksUri, Promise<Jwks>> = new Map();

  constructor(props?: {
    penaltyBox?: PenaltyBox;
    fetcher?: Fetcher;
    jwksParser?: JwksParser;
  }) {
    this.penaltyBox = props?.penaltyBox ?? new SimplePenaltyBox();
    this.fetcher = props?.fetcher ?? new SimpleFetcher();
    this.jwksParser = props?.jwksParser ?? parseJwks;
  }

  /**
   * Add a JWKS to the cache explicitly. E.g. you may want to do this, if you have already downloaded the JWKS.
   *
   * @param jwksUri - The URI where your IDP exposes the JWKS, e.g. `https://example.com/my-idp/.well-known/jwks.json` (this is used as cache key)
   * @param jwks - The JWKS
   */
  public addJwks(jwksUri: string, jwks: Jwks): void {
    this.jwksCache.set(jwksUri, jwks);
  }

  /**
   * Fetch and cache the JWKS from the jwksUri
   *
   * @param jwksUri - The URI where your IDP exposes the JWKS, e.g. `https://example.com/my-idp/.well-known/jwks.json`
   * @returns - The fetched jwks
   */
  public async getJwks(jwksUri: string): Promise<Jwks> {
    const existingFetch = this.fetchingJwks.get(jwksUri);
    if (existingFetch) {
      return existingFetch;
    }
    const jwksPromise = this.fetcher.fetch(jwksUri).then(this.jwksParser);
    this.fetchingJwks.set(jwksUri, jwksPromise);
    let jwks: Jwks;
    try {
      jwks = await jwksPromise;
    } finally {
      this.fetchingJwks.delete(jwksUri);
    }
    this.jwksCache.set(jwksUri, jwks);
    return jwks;
  }

  /**
   * Get the JWKS from the cache (synchronously). Raises an error if the JWKS is not yet cached, or does not have the right JWK.
   *
   * @param jwksUri - The URI where your IDP exposes the JWKS, e.g. `https://example.com/my-idp/.well-known/jwks.json` (this is used as cache key)
   * @param decomposedJwt - The decomposed JWT
   * @returns - The previously cached JWKS
   */
  public getCachedJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): JwkWithKid {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }
    if (!this.jwksCache.has(jwksUri)) {
      throw new JwksNotAvailableInCacheError(
        `JWKS for uri ${jwksUri} not yet available in cache`
      );
    }
    const jwk = findJwkInJwks(
      this.jwksCache.get(jwksUri)!,
      decomposedJwt.header.kid
    );
    if (!jwk) {
      throw new KidNotFoundInJwksError(
        `JWK for kid ${decomposedJwt.header.kid} not found in the JWKS`
      );
    }
    return jwk;
  }

  /**
   * Get the right JWK to verify the JWT with. This will fetch (and cache) the JWKS in case it's not yet been cached,
   * or if the cached JWKS doesn't have the right JWK (to account for key rotations, based on `kid`).
   *
   * @param jwksUri
   * @param decomposedJwt
   * @returns  - The JWK
   */
  public async getJwk(
    jwksUri: string,
    decomposedJwt: DecomposedJwt
  ): Promise<JwkWithKid> {
    if (typeof decomposedJwt.header.kid !== "string") {
      throw new JwtWithoutValidKidError(
        "JWT header does not have valid kid claim"
      );
    }

    // Try to get JWK from cache:
    const cachedJwks = this.jwksCache.get(jwksUri);
    if (cachedJwks) {
      const cachedJwk = findJwkInJwks(cachedJwks, decomposedJwt.header.kid);
      if (cachedJwk) {
        return cachedJwk;
      }
    }

    // Await any wait period that is currently in effect
    // This prevents us from flooding the JWKS URI with requests
    await this.penaltyBox.wait(jwksUri, decomposedJwt.header.kid);

    // Fetch the JWKS and (try to) locate the JWK
    const jwks = await this.getJwks(jwksUri);
    const jwk = findJwkInJwks(jwks, decomposedJwt.header.kid);

    // If the JWK could not be located, someone might be messing around with us
    // Register the failed attempt with the penaltyBox, so it can enforce a wait period
    // before trying again next time (instead of flooding the JWKS URI with requests)
    if (!jwk) {
      this.penaltyBox.registerFailedAttempt(jwksUri, decomposedJwt.header.kid);
      throw new KidNotFoundInJwksError(
        `JWK for kid "${decomposedJwt.header.kid}" not found in the JWKS`
      );
    } else {
      this.penaltyBox.registerSuccessfulAttempt(
        jwksUri,
        decomposedJwt.header.kid
      );
    }

    return jwk;
  }
}
