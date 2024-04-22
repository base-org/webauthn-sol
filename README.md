## Solidity WebAuthn Authentication Assertion Verifier

Webauthn-sol is a Solidity library for verifying WebAuthn authentication assertions. It builds on [Daimo's WebAuthn.sol](https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol).

This library is optimized for Ethereum layer 2 rollup chains but will work on all EVM chains. Signature verification always attempts to use the [RIP-7212 precompile](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) and, if this fails, falls back to using [FreshCryptoLib](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_ecdsa.sol#L40).

> [!IMPORTANT]  
> FreshCryptoLib uses the `ModExp` precompile (`address(0x05)`), which is not supported on some chains, such as [Polygon zkEVM](https://www.rollup.codes/polygon-zkevm#precompiled-contracts). This library will not work on such chains, unless they support the RIP-7212 precompile. 

Code excerpts

```solidity
struct WebAuthnAuth {
    /// @dev https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata
    bytes authenticatorData;
    /// @dev https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson
    string clientDataJSON;
    /// The index at which "challenge":"..." occurs in clientDataJSON
    uint256 challengeIndex;
    /// The index at which "type":"..." occurs in clientDataJSON
    uint256 typeIndex;
    /// @dev The r value of secp256r1 signature
    uint256 r;
    /// @dev The s value of secp256r1 signature
    uint256 s;
}

function verify(
    bytes memory challenge,
    bool requireUserVerification,
    WebAuthnAuth memory webAuthnAuth,
    uint256 x,
    uint256 y
) internal view returns (bool) 
```

example usage
```solidity
bytes challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
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
```

### Developing 
After cloning the repo, run the tests using Forge, from [Foundry](https://github.com/foundry-rs/foundry?tab=readme-ov-file)
```bash
forge test
```