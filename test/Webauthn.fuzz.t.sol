// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FCL_ecdsa} from "FreshCryptoLib/FCL_ecdsa.sol";

import {WebAuthn} from "../src/WebAuthn.sol";

import "forge-std/Test.sol";

contract WebAuthnFuzzTest is Test {
    using stdJson for string;

    string constant testFile = "/test/fixtures/assertions_fixture.json";

    /// @dev `WebAuthn.verify` should return `false` when `s` is above P256_N_DIV_2.
    function test_Verify_ShoulReturnFalse_WhenSAboveP256_N_DIV_2() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, testFile);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i = 0; i < count; i++) {
            (
                string memory jsonCaseSelector,
                string memory origin,
                bool uv,
                uint256 x,
                uint256 y,
                bytes memory challenge,
                uint256 r,
                uint256 s,
                bytes memory authenticatorData,
                string memory clientDataJsonCrossOriginAndRemainder
            ) = _parseJson({json: json, caseIndex: i, debugPrint: false});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases.
            if (s <= WebAuthn.P256_N_DIV_2) {
                s = FCL_ecdsa.n - s;
            }

            WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
                authenticatorData: authenticatorData,
                origin: origin,
                crossOriginAndRemainder: clientDataJsonCrossOriginAndRemainder,
                r: r,
                s: s
            });

            bool res =
                WebAuthn.verify({challenge: challenge, requireUserVerification: uv, webAuthnAuth: auth, x: x, y: y});

            // Assert the verification failed to guard against signature malleability.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));

            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `false` when the `up` flag is not set.
    function test_Verify_ShoulReturnFalse_WhenTheUpFlagIsNotSet() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, testFile);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i = 0; i < count; i++) {
            (
                string memory jsonCaseSelector,
                string memory origin,
                bool uv,
                uint256 x,
                uint256 y,
                bytes memory challenge,
                uint256 r,
                uint256 s,
                bytes memory authenticatorData,
                string memory clientDataJsonCrossOriginAndRemainder
            ) = _parseJson({json: json, caseIndex: i, debugPrint: false});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s <= P256_N_DIV_2 case
            if (s > WebAuthn.P256_N_DIV_2) {
                s = FCL_ecdsa.n - s;
            }

            // Unset the `up` flag.
            authenticatorData[32] = authenticatorData[32] & bytes1(0xfe);

            WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
                authenticatorData: authenticatorData,
                origin: origin,
                crossOriginAndRemainder: clientDataJsonCrossOriginAndRemainder,
                r: r,
                s: s
            });

            bool res =
                WebAuthn.verify({challenge: challenge, requireUserVerification: uv, webAuthnAuth: auth, x: x, y: y});

            // Assert the verification failed because the `up` flag was not set.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));

            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `false` when `requireUserVerification` is `true` but the
    ///       authenticator did not set the `uv` flag.
    function test_Verify_ShoulReturnFalse_WhenUserVerifictionIsRequiredButTestWasNotPerformed() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, testFile);
        string memory json = vm.readFile(path);
        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i = 0; i < count; i++) {
            (
                string memory jsonCaseSelector,
                string memory origin,
                bool uv,
                uint256 x,
                uint256 y,
                bytes memory challenge,
                uint256 r,
                uint256 s,
                bytes memory authenticatorData,
                string memory clientDataJsonCrossOriginAndRemainder
            ) = _parseJson({json: json, caseIndex: i, debugPrint: false});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases with uv not performed.
            if (uv == true) {
                continue;
            }

            if (s > WebAuthn.P256_N_DIV_2) {
                s = FCL_ecdsa.n - s;
            }

            WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
                authenticatorData: authenticatorData,
                origin: origin,
                crossOriginAndRemainder: clientDataJsonCrossOriginAndRemainder,
                r: r,
                s: s
            });

            bool res = WebAuthn.verify({
                challenge: challenge,
                requireUserVerification: true, // Set UV to required to ensure false is returned
                webAuthnAuth: auth,
                x: x,
                y: y
            });

            // Assert the verification failed because user verification was required but not performed by the authenticator.
            assertEq(res, false, string.concat("Failed on ", jsonCaseSelector));

            console.log("------------------------------------");
        }
    }

    /// @dev `WebAuthn.verify` should return `true` when `s` is below `P256_N_DIV_2` and `requireUserVerification`
    ///       "matches" with the `uv` flag set by the authenticator.
    function test_Verify_ShoulReturnTrue_WhenSBelowP256_N_DIV_2() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, testFile);
        string memory json = vm.readFile(path);

        uint256 count = abi.decode(json.parseRaw(".count"), (uint256));

        for (uint256 i = 0; i < count; i++) {
            (
                string memory jsonCaseSelector,
                string memory origin,
                bool uv,
                uint256 x,
                uint256 y,
                bytes memory challenge,
                uint256 r,
                uint256 s,
                bytes memory authenticatorData,
                string memory clientDataJsonCrossOriginAndRemainder
            ) = _parseJson({json: json, caseIndex: i, debugPrint: false});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s <= P256_N_DIV_2 cases
            if (s > WebAuthn.P256_N_DIV_2) {
                s = FCL_ecdsa.n - s;
            }

            console.log("s", vm.toString(s));

            WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
                authenticatorData: authenticatorData,
                origin: origin,
                crossOriginAndRemainder: clientDataJsonCrossOriginAndRemainder,
                r: r,
                s: s
            });

            bool res =
                WebAuthn.verify({challenge: challenge, requireUserVerification: uv, webAuthnAuth: auth, x: x, y: y});

            // Assert the verification succeeded.
            assertEq(res, true, string.concat("Failed on ", jsonCaseSelector));
            console.log("------------------------------------");
        }
    }

    /// @dev Helper function to parse a test case fron the given json string.
    /// @param json The json string to parse.
    /// @param caseIndex The test case index to parse.
    /// @param debugPrint Whether or not to enable debug printing.
    /// @return jsonCaseSelector The base json case selector (i.e. ".cases[34]")
    /// @return origin The origin.
    /// @return uv The uv flag.
    /// @return x The public key x coordinate.
    /// @return y The public key y coordinate.
    /// @return challenge The challenge used during the assertion.
    /// @return r The signature r value.
    /// @return s The signature s value.
    /// @return authenticatorData The authenticator data.
    /// @return clientDataJsonCrossOriginAndRemainder The client data JSON with the `origin`, `type` and `challenge` fields removed.
    function _parseJson(string memory json, uint256 caseIndex, bool debugPrint)
        private
        view
        returns (
            string memory jsonCaseSelector,
            string memory origin,
            bool uv,
            uint256 x,
            uint256 y,
            bytes memory challenge,
            uint256 r,
            uint256 s,
            bytes memory authenticatorData,
            string memory clientDataJsonCrossOriginAndRemainder
        )
    {
        jsonCaseSelector = string.concat(".cases.[", string.concat(vm.toString(caseIndex), "]"));
        origin = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".origin")), (string));
        uv = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".uv")), (bool));
        x = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".x")), (uint256));
        y = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".y")), (uint256));
        challenge = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".challenge")), (bytes));
        r = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".r")), (uint256));
        s = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".s")), (uint256));
        authenticatorData = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".authenticatorData")), (bytes));
        clientDataJsonCrossOriginAndRemainder = abi.decode(
            json.parseRaw(string.concat(jsonCaseSelector, ".clientDataJsonCrossOriginAndRemainder")), (string)
        );

        if (debugPrint) {
            console.log("uv", vm.toString(uv));
            console.log("x", vm.toString(x));
            console.log("y", vm.toString(y));
            console.log("challenge", vm.toString(challenge));
            console.log("r", vm.toString(r));
            console.log("s", vm.toString(s));
            console.log("authenticatorData", vm.toString(authenticatorData));
            console.log("clientDataJsonCrossOriginAndRemainder", clientDataJsonCrossOriginAndRemainder);
        }
    }
}
