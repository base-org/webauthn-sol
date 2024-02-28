from multiprocessing import Process
import sys
from flask import Flask, render_template_string

_app = Flask(__name__)


# HTML template with JavaScript for WebAuthn
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebAuthn Test with Flask</title>
</head>
<body>
    <h2>WebAuthn Test Page</h2>
    <button id="authButton">Authenticate with WebAuthn</button>
    <input type="text" id="challengeInput" value="fillme">

    <script>
var globalAssertion = null;
var rpId = '';

function setRpId(_rpId) {
    rpId = _rpId;
}

function arrayBufferToBase64Sync(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function getClientDataJsonCrossOriginAndRemainderAsString() {
    const utf8Decoder = new TextDecoder('utf-8');
    const decodedClientData = utf8Decoder.decode(
        globalAssertion.response.clientDataJSON)

    // parse the string as an object
    const clientDataObj = JSON.parse(decodedClientData);
    delete clientDataObj.origin;
    delete clientDataObj.type;
    delete clientDataObj.challenge;
    const remainderString = JSON.stringify(clientDataObj).slice(1, -1);

    return remainderString;
}

document.getElementById('authButton').addEventListener('click', async () => {
    try {
        // Retrieve the challenge from the input field
        const challengeInput = document.getElementById('challengeInput').value;
        // Convert the input challenge into a Uint8Array
        const challengeArray = new Uint8Array(challengeInput.split('').map(c => c.charCodeAt(0))).buffer;

        const options = {
            publicKey: {
                challenge: challengeArray, // Use the dynamically set challenge here
                rpId: rpId,
                userVerification: 'preferred',
                allowCredentials: [{
                    id: Uint8Array.from("coinbase", c => c.charCodeAt(0)),
                    type: 'public-key',
                    transports: ['usb', 'ble', 'nfc'],
                }],
            }
        };
        let assertion = await navigator.credentials.get(options);
        globalAssertion = assertion;
        // console.log('Assertion:', assertion);
    } catch (error) {
        console.error('Error:', error);
    }
});
    </script>
</body>
</html>
'''


@_app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


def _start():
    _app.run(host="127.0.0.1", port=5000)


server = Process(target=_start)


def listen():
    server.start()


def shutdown():
    server.terminate()
    server.join()


if __name__ == "__main__":
    listen()
