import os
import json
import base64
from base64 import urlsafe_b64decode
import time
import random
import argparse

from selenium import webdriver
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.virtual_authenticator import (
    Credential,
    VirtualAuthenticatorOptions,
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec

import app


def _build_chrome_webdriver():
    # Set up Chrome options
    options = ChromeOptions()
    options.add_argument("--headless")  # Ensure GUI is off
    options.add_argument("--no-sandbox")  # Bypass OS security model
    options.add_argument(
        "--disable-dev-shm-usage"
    )  # Overcome limited resource problems
    options.add_argument("--enable-logging")
    options.add_argument("--v=1")
    options.set_capability("goog:loggingPrefs", {'browser': 'ALL'})

    service = ChromeService(executable_path="/usr/bin/chromedriver")

    return webdriver.Chrome(
        options=options, service=service)


def _generate_private_key():
    private_key = ec.generate_private_key(ec.SECP256R1())

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # or use BestAvailableEncryption for encryption
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key = private_key.public_key()
    x = public_key.public_numbers().x
    y = public_key.public_numbers().y

    private_key_as_b64 = "\n".join(pem_private_key.decode().split("\n")[1:-2])

    return (x, y, private_key_as_b64)


def _add_virtual_authenticator(driver: WebDriver):
    options = VirtualAuthenticatorOptions()
    options.transport = VirtualAuthenticatorOptions.Transport.USB
    options.protocol = VirtualAuthenticatorOptions.Protocol.CTAP2

    uv = random.choice([True, False])
    options.is_user_verified = uv
    options.is_user_consenting = True
    options.has_user_verification = uv
    options.has_resident_key = random.choice([True, False])

    driver.add_virtual_authenticator(options)

    return uv


def _remove_virtual_authenticator(driver: WebDriver):
    driver.remove_virtual_authenticator()


def _create_credential(driver: WebDriver, private_key_as_b64: str):
    credential_id = bytearray(b"coinbase")
    rp_id = "localhost"
    private_key = urlsafe_b64decode(private_key_as_b64)
    sign_count = 0

    credential = Credential.create_non_resident_credential(
        credential_id, rp_id, private_key, sign_count
    )

    driver.add_credential(credential)

    return rp_id


def _trigger_assertion(driver: WebDriver, rp_id: str) -> tuple[str, str, str, str]:
    def _generate_random_string(length):
        # ASCII characters from space (32) to tilde (126)
        ascii_characters = ''.join(chr(i) for i in range(32, 127))
        # Generate random string
        random_string = ''.join(random.choice(ascii_characters)
                                for _ in range(length))
        return random_string

    challenge = _generate_random_string(random.randint(1, 1000))

    js_code = f"setRpId('{rp_id}')"
    driver.execute_script(js_code)

    input_element = driver.find_element(By.ID, "challengeInput")
    input_element.clear()
    input_element.send_keys(challenge)

    button = driver.find_element(By.ID, "authButton")
    button.click()
    driver.implicitly_wait(0.5)

    js_code = "return arrayBufferToBase64Sync(globalAssertion.response.authenticatorData);"
    authenticator_data_as_b64 = driver.execute_script(js_code)
    authenticator_data = f"0x{base64.b64decode(authenticator_data_as_b64).hex()}"

    js_code = "return arrayBufferToBase64Sync(globalAssertion.response.signature);"
    signature_as_b64 = driver.execute_script(js_code)
    signature = base64.b64decode(signature_as_b64)

    js_code = "return getClientDataJson();"
    client_data_json = driver.execute_script(
        js_code)

    return challenge, authenticator_data, signature, client_data_json


def _generate(size: int):
    app.listen()
    time.sleep(2)

    # TODO: Integrate other drivers (firefox, safari etc.)
    driver = _build_chrome_webdriver()
    driver.get("http://localhost:5000")
    driver.implicitly_wait(0.5)

    results = []
    while len(results) < size:
        uv = _add_virtual_authenticator(driver)

        x, y, private_key_as_b64 = _generate_private_key()

        rp_id = _create_credential(driver, private_key_as_b64)
        challenge, authenticator_data, signature, client_data_json = _trigger_assertion(
            driver, rp_id)

        _remove_virtual_authenticator(driver)

        r, s = utils.decode_dss_signature(signature)

        # NOTE: Intentionally keep those in the test cases to ensure the smart contract is correctly protected against signature malleability
        # if s > P256_N_DIV_2:
        #     print('Skipping because s too big')
        #     continue

        result = {}
        result["uv"] = uv
        result["x"] = x
        result["y"] = y
        result["challenge"] = challenge
        result["r"] = r
        result["s"] = s
        result["authenticator_data"] = authenticator_data
        result["client_data_json"] = {
            "json": client_data_json,
            "type_index": client_data_json.find("\"type\":"),
            "challenge_index": client_data_json.find("\"challenge\":")
        }
        results.append(result)

    driver.quit()
    app.shutdown()

    dir_name = os.path.dirname(os.path.realpath(__file__))
    obj = {"count": len(results), "cases": results}
    with open(f"{dir_name}/../fixtures/assertions_fixture.json", "w") as json_file:
        json_str = json.dumps(obj, indent=4)
        json_file.write(json_str)


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "count", help="Number of assertions to generate", type=int, )
    return parser.parse_args()


def main(args):
    count = args.count
    _generate(count)


if __name__ == "__main__":
    args = _parse_args()
    main(args)
