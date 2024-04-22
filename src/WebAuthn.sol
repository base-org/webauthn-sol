// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FCL_ecdsa} from "FreshCryptoLib/FCL_ecdsa.sol";
import {FCL_Elliptic_ZZ} from "FreshCryptoLib/FCL_elliptic.sol";
import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {LibString} from "solady/utils/LibString.sol";

/// @title WebAuthn
///
/// @notice A library for verifying WebAuthn Authentication Assertions, built off the work
///         of Daimo.
///
/// @dev Attempts to use the RIP-7212 precompile for signature verification.
///      If precompile verification fails, it falls back to FreshCryptoLib.
///
/// @author Coinbase (https://github.com/base-org/webauthn-sol)
/// @author Daimo (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
library WebAuthn {
    using LibString for string;

    struct WebAuthnAuth {
        /// @dev The WebAuthn authenticator data.
        ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata.
        bytes authenticatorData;
        /// @dev The WebAuthn client data JSON.
        ///      See https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson.
        string clientDataJSON;
        /// @dev The index at which "challenge":"..." occurs in `clientDataJSON`.
        uint256 challengeIndex;
        /// @dev The index at which "type":"..." occurs in `clientDataJSON`.
        uint256 typeIndex;
        /// @dev The r value of secp256r1 signature
        uint256 r;
        /// @dev The s value of secp256r1 signature
        uint256 s;
    }

    /// @dev Bit 0 of the authenticator data struct, corresponding to the "User Present" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UP = 0x01;

    /// @dev Bit 2 of the authenticator data struct, corresponding to the "User Verified" bit.
    ///      See https://www.w3.org/TR/webauthn-2/#flags.
    bytes1 private constant _AUTH_DATA_FLAGS_UV = 0x04;

    /// @dev Secp256r1 curve order / 2 used as guard to prevent signature malleability issue.
    uint256 private constant _P256_N_DIV_2 = FCL_Elliptic_ZZ.n / 2;

    /// @dev The precompiled contract address to use for signature verification in the “secp256r1” elliptic curve.
    ///      See https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md.
    address private constant _VERIFIER = address(0x100);

    /// @dev The expected type (hash) in the client data JSON when verifying assertion signatures.
    ///      See https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    bytes32 private constant _EXPECTED_TYPE_HASH = keccak256('"type":"webauthn.get"');

    ///
    /// @notice Verifies a Webauthn Authentication Assertion as described
    /// in https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    ///
    /// @dev We do not verify all the steps as described in the specification, only ones relevant to our context.
    ///      Please carefully read through this list before usage.
    ///
    ///      Specifically, we do verify the following:
    ///         - Verify that authenticatorData (which comes from the authenticator, such as iCloud Keychain) indicates
    ///           a well-formed assertion with the user present bit set. If `requireUV` is set, checks that the authenticator
    ///           enforced user verification. User verification should be required if, and only if, options.userVerification
    ///           is set to required in the request.
    ///         - Verifies that the client JSON is of type "webauthn.get", i.e. the client was responding to a request to
    ///           assert authentication.
    ///         - Verifies that the client JSON contains the requested challenge.
    ///         - Verifies that (r, s) constitute a valid signature over both the authenicatorData and client JSON, for public
    ///            key (x, y).
    ///
    ///      We make some assumptions about the particular use case of this verifier, so we do NOT verify the following:
    ///         - Does NOT verify that the origin in the `clientDataJSON` matches the Relying Party's origin: tt is considered
    ///           the authenticator's responsibility to ensure that the user is interacting with the correct RP. This is
    ///           enforced by most high quality authenticators properly, particularly the iCloud Keychain and Google Password
    ///           Manager were tested.
    ///         - Does NOT verify That `topOrigin` in `clientDataJSON` is well-formed: We assume it would never be present, i.e.
    ///           the credentials are never used in a cross-origin/iframe context. The website/app set up should disallow
    ///           cross-origin usage of the credentials. This is the default behaviour for created credentials in common settings.
    ///         - Does NOT verify that the `rpIdHash` in `authenticatorData` is the SHA-256 hash of the RP ID expected by the Relying
    ///           Party: this means that we rely on the authenticator to properly enforce credentials to be used only by the correct RP.
    ///           This is generally enforced with features like Apple App Site Association and Google Asset Links. To protect from
    ///           edge cases in which a previously-linked RP ID is removed from the authorised RP IDs, we recommend that messages
    ///           signed by the authenticator include some expiry mechanism.
    ///         - Does NOT verify the credential backup state: this assumes the credential backup state is NOT used as part of Relying
    ///           Party business logic or policy.
    ///         - Does NOT verify the values of the client extension outputs: this assumes that the Relying Party does not use client
    ///           extension outputs.
    ///         - Does NOT verify the signature counter: signature counters are intended to enable risk scoring for the Relying Party.
    ///           This assumes risk scoring is not used as part of Relying Party business logic or policy.
    ///         - Does NOT verify the attestation object: this assumes that response.attestationObject is NOT present in the response,
    ///           i.e. the RP does not intend to verify an attestation.
    ///
    /// @param challenge    The challenge that was provided by the relying party.
    /// @param requireUV    A boolean indicating whether user verification is required.
    /// @param webAuthnAuth The `WebAuthnAuth` struct.
    /// @param x            The x coordinate of the public key.
    /// @param y            The y coordinate of the public key.
    ///
    /// @return `true` if the authentication assertion passed validation, else `false`.
    function verify(bytes memory challenge, bool requireUV, WebAuthnAuth memory webAuthnAuth, uint256 x, uint256 y)
        internal
        view
        returns (bool)
    {
        if (webAuthnAuth.s > _P256_N_DIV_2) {
            // guard against signature malleability
            return false;
        }

        // 11. Verify that the value of C.type is the string webauthn.get.
        // bytes("type":"webauthn.get").length = 21
        string memory _type = webAuthnAuth.clientDataJSON.slice(webAuthnAuth.typeIndex, webAuthnAuth.typeIndex + 21);
        if (keccak256(bytes(_type)) != _EXPECTED_TYPE_HASH) {
            return false;
        }

        // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64.encodeURL(challenge), '"'));
        string memory actualChallenge =
            webAuthnAuth.clientDataJSON.slice(webAuthnAuth.challengeIndex, webAuthnAuth.challengeIndex + expectedChallenge.length);
        if (keccak256(bytes(actualChallenge)) != keccak256(expectedChallenge)) {
            return false;
        }

        // Skip 13., 14., 15.

        // 16. Verify that the UP bit of the flags in authData is set.
        if (webAuthnAuth.authenticatorData[32] & _AUTH_DATA_FLAGS_UP != _AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags in
        // authData is set.
        if (requireUV && (webAuthnAuth.authenticatorData[32] & _AUTH_DATA_FLAGS_UV) != _AUTH_DATA_FLAGS_UV) {
            return false;
        }

        // skip 18.

        // 19. Let hash be the result of computing a hash over the cData using SHA-256.
        bytes32 clientDataJSONHash = sha256(bytes(webAuthnAuth.clientDataJSON));

        // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData
        // and hash.
        bytes32 messageHash = sha256(abi.encodePacked(webAuthnAuth.authenticatorData, clientDataJSONHash));
        bytes memory args = abi.encode(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
        // try the RIP-7212 precompile address
        (bool success, bytes memory ret) = _VERIFIER.staticcall(args);
        // staticcall will not revert if address has no code
        // check return length
        // note that even if precompile exists, ret.length is 0 when verification returns false
        // so an invalid signature will be checked twice: once by the precompile and once by FCL.
        // Ideally this signature failure is simulated offchain and no one actually pay this gas.
        bool valid = ret.length > 0;
        if (success && valid) return abi.decode(ret, (uint256)) == 1;

        return FCL_ecdsa.ecdsa_verify(messageHash, webAuthnAuth.r, webAuthnAuth.s, x, y);
    }
}
