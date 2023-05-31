# source venv/bin/activate

import os
from farcaster import Warpcast
from dotenv import load_dotenv
import requests
from eth_account import messages, Account
import time
import re

load_dotenv()

client = Warpcast(mnemonic=os.environ.get("FARC_PRIVKEY"))
mnemonic = os.environ.get("KIWI_MNEMONIC")

def main():
	for cast in client.stream_casts(skip_existing=True):
		if cast.text.startswith("@fc-kiwi-bot2"):
			# print(cast.text)
			parent = client.get_cast(cast.parent_hash)
			# print(parent)
			link = extract_link(parent.cast.text)
			# print(link)
			response = send_to_kiwinews(cast.text[14:], link)

			if response.status_code == 200:
				print(response.json())
			else:
				print('Error: {}'.format(response.text))



def send_to_kiwinews(title, href):
	url = "https://news.kiwistand.com/api/v1/messages"
	
	request_body = {
		"timestamp": int(time.time()),
		"type": "amplify",
		"title": title,
		"href": href,
	}

	message = {
		"types": {
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "salt", "type": "bytes32"},
			],
			"Message": [
				{"name": "title", "type": "string"},
				{"name": "href", "type": "string"},
				{"name": "type", "type": "string"},
				{"name": "timestamp", "type": "uint256"},
			]
		},
		"primaryType": "Message",
		"domain": {
			"name": "kiwinews",
			"version": "1.0.0",
			"salt": bytes.fromhex("fe7a9d68e99b6942bb3a36178b251da8bd061c20ed1e795207ae97183b590e5b"),
		},
		"message": request_body
	}

	acct = Account.from_mnemonic(mnemonic)

	structured_msg = messages.encode_structured_data(message)
	# print(structured_msg.body.hex())

	signature = Account.sign_message(structured_msg, acct.key)

	request_body["signature"] = signature.signature.hex()

	response = requests.post(url, json=request_body)

	return response


def extract_link(text):
	url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
	urls = re.findall(url_pattern, text)
	
	return urls[0] if urls else None
