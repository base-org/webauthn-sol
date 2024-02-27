> [!IMPORTANT]  
> The code in this repository and its dependencies are still under audit. It is not yet recommended for production use.

## Solidity WebAuthn Authentication Assertion Verifier

Webauthn-sol is a Solidity library for verifying WebAuthn authentication assertions. It builds on [Daimo's WebAuthn.sol](https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol).

This library is optimized for Ethereum layer 2 rollup chains but will work on all EVM chains. Signature verification always attempts to use the [RIP-7212 precompile](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) and, if this fails, falls back to using [FreshCryptoLib](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_ecdsa.sol#L40).

As L1 calldata is the main cost driver of L2 transactions, this library is designed to minimize calldata. Rather than requiring the full clientDataJSON to be passed, we use a template to verify against what a well formed response *should* be, leveraging the [serialization specification](https://www.w3.org/TR/webauthn/#clientdatajson-serialization). 

Code excerpts

```solidity
struct WebAuthnAuth {
    /// @dev https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata
    bytes authenticatorData;
    /// @dev https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-origin
    string origin;
    /// @dev https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-crossorigin
    /// @dev 13. https://www.w3.org/TR/webauthn/#clientdatajson-serialization
    /// crossOrigin should always be present, re https://www.w3.org/TR/webauthn/#clientdatajson-serialization
    /// but in practice is sometimes not. For this reason we include with remainder. String may be empty.
    /// e.g.
    ///     ''
    ///     '"crossOrigin":false'
    ///     '"tokenBinding":{"status":"present","id":"TbId"}'
    ///     '"crossOrigin":false,"tokenBinding":{"status":"present","id":"TbId"}'
    string crossOriginAndRemainder;
    /// @dev The r value of secp256r1 signature
    uint256 r;
    /// @dev The s value of secp256r1 signature
    uint256 s;
}
...

function verify(
    bytes memory challenge,
    bool requireUserVerification,
    WebAuthnAuth memory webAuthnAuth,
    uint256 x,
    uint256 y
) internal view returns (bool)

... 

function test() public view {
    bytes challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
    uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;
    uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
    WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
        authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
        origin: "http://localhost:3005",
        crossOriginAndRemainder: "",
        r: 43684192885701841787131392247364253107519555363555461570655060745499568693242,
        s: 22655632649588629308599201066602670461698485748654492451178007896016452673579
    });
    assert(
        WebAuthn.verify(
            challenge, false, auth, x, y
        )
    );
}
```