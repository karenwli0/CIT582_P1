from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    content = request.get_json(silent=True)

    payload = content.get('payload')
    platform = payload.get('platform')

    print(json.dumps(content, indent=1))

    result = False

    if platform == 'Ethereum':
        eth_account.Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = eth_account.Account.create_with_mnemonic()

        eth_pk = acct.address
        eth_sk = acct.key

        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg, eth_sk)

        if eth_account.Account.recover_message(eth_encoded_msg, signature=eth_sig_obj.signature.hex()) == eth_pk:
            result = True

    if platform == 'Algorand':
        algo_sk, algo_pk = algosdk.account.generate_account()
        algo_sig_str = algosdk.util.sign_bytes(payload.encode('utf-8'), algo_sk)

        if algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig_str, algo_pk):
            result = True

    # Check if signature is valid
    # if result:  # Should only be true if signature validates
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
