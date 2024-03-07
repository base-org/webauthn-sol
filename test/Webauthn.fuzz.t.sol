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
                bytes memory challenge,
                bool uv,
                WebAuthn.WebAuthnAuth memory webAuthnAuth,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases.
            if (webAuthnAuth.s <= WebAuthn.P256_N_DIV_2) {
                webAuthnAuth.s = FCL_ecdsa.n - webAuthnAuth.s;
            }

            bool res = WebAuthn.verify({
                challenge: challenge,
                requireUserVerification: uv,
                webAuthnAuth: webAuthnAuth,
                x: x,
                y: y
            });

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
                bytes memory challenge,
                bool uv,
                WebAuthn.WebAuthnAuth memory webAuthnAuth,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s <= P256_N_DIV_2 case
            if (webAuthnAuth.s > WebAuthn.P256_N_DIV_2) {
                webAuthnAuth.s = FCL_ecdsa.n - webAuthnAuth.s;
            }

            // Unset the `up` flag.
            webAuthnAuth.authenticatorData[32] = webAuthnAuth.authenticatorData[32] & bytes1(0xfe);

            bool res = WebAuthn.verify({
                challenge: challenge,
                requireUserVerification: uv,
                webAuthnAuth: webAuthnAuth,
                x: x,
                y: y
            });

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
                bytes memory challenge,
                bool uv,
                WebAuthn.WebAuthnAuth memory webAuthnAuth,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s > P256_N_DIV_2 cases with uv not performed.
            if (uv == true) {
                continue;
            }

            if (webAuthnAuth.s > WebAuthn.P256_N_DIV_2) {
                webAuthnAuth.s = FCL_ecdsa.n - webAuthnAuth.s;
            }

            bool res = WebAuthn.verify({
                challenge: challenge,
                requireUserVerification: true, // Set UV to required to ensure false is returned
                webAuthnAuth: webAuthnAuth,
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
                bytes memory challenge,
                bool uv,
                WebAuthn.WebAuthnAuth memory webAuthnAuth,
                uint256 x,
                uint256 y
            ) = _parseJson({json: json, caseIndex: i});

            console.log("Veryfing", jsonCaseSelector);

            // Only interested in s <= P256_N_DIV_2 cases
            if (webAuthnAuth.s > WebAuthn.P256_N_DIV_2) {
                webAuthnAuth.s = FCL_ecdsa.n - webAuthnAuth.s;
            }

            bool res = WebAuthn.verify({
                challenge: challenge,
                requireUserVerification: uv,
                webAuthnAuth: webAuthnAuth,
                x: x,
                y: y
            });

            // Assert the verification succeeded.
            assertEq(res, true, string.concat("Failed on ", jsonCaseSelector));
            console.log("------------------------------------");
        }
    }

    /// @dev Helper function to parse a test case fron the given json string.
    /// @param json The json string to parse.
    /// @param caseIndex The test case index to parse.
    function _parseJson(string memory json, uint256 caseIndex)
        private
        pure
        returns (
            string memory jsonCaseSelector,
            bytes memory challenge,
            bool uv,
            WebAuthn.WebAuthnAuth memory webAuthnAuth,
            uint256 x,
            uint256 y
        )
    {
        jsonCaseSelector = string.concat(".cases.[", string.concat(vm.toString(caseIndex), "]"));
        challenge = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".challenge")), (bytes));
        uv = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".uv")), (bool));

        webAuthnAuth = WebAuthn.WebAuthnAuth({
            authenticatorData: abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".authenticator_data")), (bytes)),
            clientDataJSON: abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.json")), (string)),
            challengeIndex: abi.decode(
                json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.challenge_index")), (uint256)
                ),
            typeIndex: abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".client_data_json.type_index")), (uint256)),
            r: abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".r")), (uint256)),
            s: abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".s")), (uint256))
        });

        x = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".x")), (uint256));
        y = abi.decode(json.parseRaw(string.concat(jsonCaseSelector, ".y")), (uint256));
    }
}
