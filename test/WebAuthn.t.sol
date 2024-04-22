// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {WebAuthn} from "../src/WebAuthn.sol";
import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";
import {Test, console2} from "forge-std/Test.sol";

contract WebAuthnTest is Test {
    bytes challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

    function test_safari() public {
        uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;
        uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"', Base64Url.encode(challenge), '","origin":"http://localhost:3005"}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 43684192885701841787131392247364253107519555363555461570655060745499568693242,
            s: 22655632649588629308599201066602670461698485748654492451178007896016452673579
        });
        assertTrue(WebAuthn.verify(challenge, false, auth, x, y));
    }

    function test_chrome() public {
        uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;
        uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a",
            clientDataJSON: string.concat(
                '{"type":"webauthn.get","challenge":"', Base64Url.encode(challenge), '","origin":"http://localhost:3005","crossOrigin":false}'
            ),
            challengeIndex: 23,
            typeIndex: 1,
            r: 29739767516584490820047863506833955097567272713519339793744591468032609909569,
            s: 45947455641742997809691064512762075989493430661170736817032030660832793108102
        });
        assertTrue(WebAuthn.verify(challenge, false, auth, x, y));
    }
}
