from flask import Flask, request, jsonify

app = Flask(__name__)

mailbox = {
    'maria': [],
    'joao': []
}

@app.route('/send', methods=['POST'])
def enviar_msg():
    data = request.json
    receiver = data['receiver']

    mailbox[receiver].append(data)

    return jsonify({"status": "ok"})

@app.route('/messages/<user>')
def get_messages(user):
    msgs = mailbox[user]
    mailbox[user] = []

    return jsonify(msgs)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
