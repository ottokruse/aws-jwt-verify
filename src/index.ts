// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export { JwtVerifier } from "./jwt-verifier.js";
export { CognitoJwtVerifier } from "./cognito-verifier.js";

// Backward compatibility
import { JwtVerifier } from "./jwt-verifier.js";
/**
 * @deprecated since version 5.0.0, use JwtVerifier instead
 */
export const JwtRsaVerifier = JwtVerifier;
