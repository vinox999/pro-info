from flask import Flask, request, jsonify
import requests, binascii, re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

INFO_TOKENS = [
    ("4602460359", "BY_PARAHEX-BTHCYBJH3-REDZED"),
]

def get_jwt(uid, pw):
    api_url = f"https://jwt-api-1-indol.vercel.app/token?uid={uid}&password={pw}"
    response = requests.get(api_url)
    try:
        json_response = response.json()
        if json_response.get('status') == 'success' and json_response.get('token'):
            return json_response['token']
    except:
        pass
    token_match = re.search(r"ToKen : (\S+)", response.text)
    if token_match:
        return token_match.group(1)
    return None

def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def Get_player_information(uid, token):
    try:
        encrypted_id = Encrypt_ID(uid)
        data = bytes.fromhex(encrypt_api(f"08{encrypted_id}1007"))
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB53',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        response = requests.post(url, headers=headers, data=data, verify=False)
        
        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            
            result = {
                "status": "success",
                "uid": uid,
                "data": {
                    "hex_preview": hex_response[:300] + "..." if len(hex_response) > 300 else hex_response,
                    "length": len(response.content)
                }
            }
            return result
        else:
            return {
                "status": "error", 
                "code": response.status_code, 
                "message": f"Failed for ID: {uid}"
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.route('/info', methods=['GET'])
def get_info():
    # طباعة كل المعاملات للتصحيح
    print(f"Args: {request.args}")
    print(f"Full path: {request.full_path}")
    
    uid = request.args.get('uid')
    
    # محاولة بديلة: قراءة من query_string مباشرة
    if not uid:
        from urllib.parse import parse_qs
        query_string = request.query_string.decode('utf-8') if request.query_string else ''
        parsed = parse_qs(query_string)
        uid = parsed.get('uid', [None])[0]
    
    if not uid:
        return jsonify({
            "error": "Missing uid", 
            "usage": "/info?uid=ID",
            "debug_received_args": dict(request.args),
            "debug_full_path": request.full_path
        }), 400
    
    token = get_jwt(INFO_TOKENS[0][0], INFO_TOKENS[0][1])
    if not token:
        return jsonify({"error": "Token failed"}), 500
    
    return jsonify(Get_player_information(uid, token))

@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def home():
    return jsonify({
        "service": "FreeFire Info API",
        "endpoint": "/info?uid=PLAYER_ID",
        "example": "/info?uid=3320446299",
        "note": "Make sure to include ?uid= in the URL"
    })

# لـ Vercel
app = app

if __name__ == '__main__':
    app.run(debug=True, port=5000)
