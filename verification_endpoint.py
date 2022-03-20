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
    sig = content.get('sig')
    pk = payload.get('pk')

    result = False

    if platform == 'Ethereum':

        # msg = payload.get('message')
        msg = json.dumps(payload)
        encoded_msg = eth_account.messages.encode_defunct(text=msg)

        if eth_account.Account.recover_message(encoded_msg, signature=sig) == pk:
            result = True

    if platform == 'Algorand':
        # msg = payload.get('message')
        msg = json.dumps(payload)

        if algosdk.util.verify_bytes(msg.encode('utf-8'), sig, pk):
            result = True

    # Check if signature is valid
    # Should only be true if signature validates
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')
