/// <reference types="cypress" />
import { JwtVerifier } from "aws-jwt-verify";
import {
  JwtExpiredError,
  JwtNotBeforeError,
  JwtInvalidIssuerError,
  JwtInvalidAudienceError,
  JwtInvalidSignatureError,
} from "aws-jwt-verify/error";
import {
  ISSUER,
  AUDIENCE,
  JWKSURI,
  VALID_TOKEN,
  VALID_TOKEN_FOR_JWK_WITHOUT_ALG,
  VALID_TOKEN_ES256,
  VALID_TOKEN_ES256_PADDED,
  VALID_TOKEN_ES512,
  VALID_TOKEN_Ed25519,
  // VALID_TOKEN_Ed448,
  EXPIRED_TOKEN,
  NOT_YET_VALID_TOKEN,
} from "../fixtures/example-token-data.json";
import {
  MS_ISSUER,
  MS_AUDIENCE,
  MS_JWKSURI,
  MS_INVALID_KID_TOKEN,
} from "../fixtures/ms-token-data.json";

describe("unit tests", () => {
  const INVALID_ISSUER = "https://example.org";
  const INVALID_JWKSURI = "/notexample-JWKS.json";
  const INVALID_AUDIENCE = "notaudience";

  beforeEach(() => {
    cy.intercept("GET", JWKSURI, { fixture: "example-JWKS" });
  });

  it("valid token", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN);

    expect(payload).to.exist;
  });

  it("valid token - es256", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN_ES256);

    expect(payload).to.exist;
  });

  it("valid token - es256 padded", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN_ES256_PADDED);

    expect(payload).to.exist;
  });

  it("valid token - es512", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN_ES512);

    expect(payload).to.exist;
  });

  // Note: Ed25519 is not yet supported in chromium without enable-experimental-web-platform-features enabled
  it("valid token - Ed25519", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN_Ed25519);

    expect(payload).to.exist;
  });

  // Note: Ed448 is not yet supported in chrome nor firefox
  // it("valid token - Ed448", async () => {
  //   const verifier = JwtVerifier.create({
  //     issuer: ISSUER,
  //     audience: AUDIENCE,
  //     jwksUri: JWKSURI,
  //   });
  //   const payload = await verifier.verify(VALID_TOKEN_Ed448);

  //   expect(payload).to.exist;
  // });

  it("valid token for JWK without alg", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });
    const payload = await verifier.verify(VALID_TOKEN_FOR_JWK_WITHOUT_ALG);

    expect(payload).to.exist;
  });

  it("expired token", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(EXPIRED_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtExpiredError);

      expect(ex.message).to.include("Token expired at ");
    }
  });

  it("not yet valid token", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(NOT_YET_VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtNotBeforeError);

      expect(ex.message).to.include("Token can't be used before ");
    }
  });

  it("invalid issuer", async () => {
    const verifier = JwtVerifier.create({
      issuer: INVALID_ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidIssuerError);

      expect(ex.message).to.include("Issuer not allowed");
    }
  });

  it("invalid audience", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: INVALID_AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidAudienceError);

      expect(ex.message).to.include("Audience not allowed");
    }
  });

  it("invalid signature", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: JWKSURI,
    });

    try {
      const payload = await verifier.verify(
        VALID_TOKEN.substring(0, VALID_TOKEN.length - 2)
      );

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex).to.be.an.instanceof(JwtInvalidSignatureError);

      expect(ex.message).to.include("Invalid signature");
    }
  });

  it("invalid JWKS Uri", async () => {
    const verifier = JwtVerifier.create({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUri: INVALID_JWKSURI,
    });

    try {
      const payload = await verifier.verify(VALID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex.message).to.include(`JWKS could not be parsed as JSON`);
    }
  });

  it("invalid JWK kid", async () => {
    // example token from https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
    const verifier = JwtVerifier.create({
      issuer: MS_ISSUER,
      audience: MS_AUDIENCE,
      jwksUri: MS_JWKSURI,
    });

    try {
      const payload = await verifier.verify(MS_INVALID_KID_TOKEN);

      expect(payload).to.not.exist;
    } catch (ex) {
      expect(ex.message).to.include(
        'JWK for kid "i6lGk3FZzxRcUb2C3nEQ7syHJlY" not found in the JWKS'
      );
    }
  });
});
