import json
import hashlib, bottle
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from bottle import post, route, run, request, response

def encrypt(provided_data):
    salt = get_random_bytes(AES.block_size)
    private_key = hashlib.scrypt(provided_data['key'].encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(str(json.dumps(provided_data)), 'utf-8'))
    return {
        "cipher_text": b64encode(cipher_text).decode('utf-8'),
        "salt": b64encode(salt).decode('utf-8'),
        "nonce": b64encode(cipher_config.nonce).decode('utf-8'),
        "tag": b64encode(tag).decode('utf-8')
    }

def decrypt(provided_data):
    stroka = b64decode(provided_data['b64code']).decode('utf-8').replace("'", "\"")
    data = json.loads(stroka)
    salt = b64decode(data['salt'])
    cipher_text = b64decode(data['cipher_text'])
    nonce = b64decode(data['nonce'])
    tag = b64decode(data['tag'])
    private_key = hashlib.scrypt(provided_data['key'].encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted

@post('/')
def api():
    try:
        code = request.json['b64code']
    except KeyError:
        credentials = encrypt(request.json)
        return b64encode(bytes(str(credentials), 'utf-8')).decode('UTF-8')
    else:
        return decrypt(request.json)

if __name__ == '__main__':
    run(host='0.0.0.0', port=8008, debug=True, reloader=True)

app = bottle.default_app()