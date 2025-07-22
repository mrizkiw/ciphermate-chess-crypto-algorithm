import requests
import base64

URL = "http://localhost:5050"

PGN = '''[Event "Friendly Game"]
[Site "?"]
[Date "2024.07.21"]
[Round "?"]
[White "White"]
[Black "Black"]
[Result "*"]

1. e4 e5 2. Nf3 Nc6 3. Bb5 a6 4. Ba4 Nf6 5. O-O Be7 6. Re1 d6 7. c3 O-O 8. h3 Nb8 9. d4 Nbd7 10. Bc2 c5 11. Nbd2 Qc7 12. Nf1 b5 13. Ng3 g6 14. Bh6 Re8 15. Qd2 Bb7 16. Rad1 Rad8 17. Bb1 Bf8 18. Bxf8 Nxf8 19. Qh6 Ne6 20. dxe5 dxe5 21. Ng5 Rxd1 22. Rxd1 Nxg5 23. Qxg5 Nd7 24. Nh5 f6 25. Rxd7 Qxd7 26. Nxf6+ Kf7
'''

def print_result(title, resp):
    print(f"--- {title} ---")
    print("Status:", resp.status_code)
    print("Response:", resp.json())
    print()

def test_basic_encrypt():
    data = {
        'plaintext': "I love cryptography. Made with love by Mrizki W.",
        'key1': 'abcdefgh',
        'key2': 'a8,b8,c8,d8,e8,f8,g8,h8'
    }
    resp = requests.post(f"{URL}/encrypt", data=data)
    print_result("Basic Encrypt", resp)
    return resp.json().get("ciphertext", "")

def test_chess_encrypt():
    data = {
        'plaintext': 'HELLO',
        'key1': 'abcdefgh',
        'square': 'd8',
        'text_pgn': PGN
    }
    resp = requests.post(f"{URL}/encrypt", data=data)
    print_result("Encrypt with Square & PGN", resp)
    return resp.json().get("ciphertext", "")

def test_base64_encrypt():
    plaintext_b64 = base64.b64encode(b'HELLO').decode()
    key1_b64 = base64.b64encode(b'abcdefgh').decode()
    key2_b64 = base64.b64encode(b'a8,b8,c8').decode()
    data = {
        'plaintext': plaintext_b64,
        'key1': key1_b64,
        'key2': key2_b64,
        'square': 'd8',
        'text_pgn': PGN
    }
    headers = {'X-Encryption-Type': 'base64'}
    resp = requests.post(f"{URL}/encrypt", data=data, headers=headers)
    print_result("Base64 Encrypt", resp)
    return resp.json().get("ciphertext", "")

def test_decrypt(ciphertext, key2, square=None, text_pgn=None):
    data = {
        'ciphertext': ciphertext,
        'key1': 'abcdefgh',
        'key2': key2
    }
    if square:
        data['square'] = square
    if text_pgn:
        data['text_pgn'] = text_pgn
    resp = requests.post(f"{URL}/decrypt", data=data)
    print_result("Decrypt", resp)

def main():
    # Test basic encrypt & decrypt
    ct1 = test_basic_encrypt()
    if ct1:
        test_decrypt(ct1, "a8,b8,c8,d8,e8,f8,g8,h8")

    # Test chess (square & PGN) encrypt & decrypt
    ct2 = test_chess_encrypt()
    if ct2:
        test_decrypt(ct2, "d8,c7,d7", square="d8", text_pgn=PGN)

    # Test base64 encrypt & decrypt
    ct3 = test_base64_encrypt()
    if ct3:
        test_decrypt(ct3, "a8,b8,c8", square="d8", text_pgn=PGN)

if __name__ == "__main__":
    main()