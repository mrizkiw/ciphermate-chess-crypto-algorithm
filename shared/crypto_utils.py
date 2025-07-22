import time
import base64
import chess.pgn
from typing import List, Tuple, Dict, Any

# --- CONSTANTS AND HELPERS ---

class SBox:
    AES = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    AES_REVERSE = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ]
    MATRIX_8X8_DECRYPT = [
    [1, 9, 17, 25, 33, 41, 49, 57],
    [2, 10, 18, 26, 34, 42, 50, 58],
    [3, 11, 19, 27, 35, 43, 51, 59],
    [4, 12, 20, 28, 36, 44, 52, 60],
    [5, 13, 21, 29, 37, 45, 53, 61],
    [6, 14, 22, 30, 38, 46, 54, 62],
    [7, 15, 23, 31, 39, 47, 55, 63],
    [8, 16, 24, 32, 40, 48, 56, 64]
    ]
    BIN = [format(x, '08b') for x in AES]

PIECE_MAP = {
    "a8": "r", "h8": "r", "b8": "n", "g8": "n", "c8": "b", "f8": "b", "d8": "q", "e8": "k",
    "a1": "R", "h1": "R", "b1": "N", "g1": "N", "c1": "B", "f1": "B", "d1": "Q", "e1": "K",
    "a2": "P", "b2": "P", "c2": "P", "d2": "P", "e2": "P", "f2": "P", "g2": "P", "h2": "P",
    "a7": "p", "b7": "p", "c7": "p", "d7": "p", "e7": "p", "f7": "p", "g7": "p", "h7": "p"
}

def split_text(text: str, size: int) -> List[str]:
    return [text[i:i+size] for i in range(0, len(text), size)]

def pos_to_index(pos: str) -> Tuple[int, int]:
    return 8 - int(pos[1]), ord(pos[0]) - ord('a')

def is_valid_chess_pos(pos: str) -> bool:
    return (len(pos) == 2 and pos[0] in 'abcdefgh' and pos[1] in '12345678')

def s_box_lookup(hex_value: str) -> str:
    out = []
    for i in range(0, len(hex_value), 2):
        idx = int(hex_value[i], 16) * 16 + int(hex_value[i + 1], 16)
        out.append(SBox.BIN[idx])
    return ''.join(out)

def s_box_hex(hex_value: str) -> str:
    out = []
    for i in range(0, len(hex_value), 2):
        row = int(hex_value[i], 16)
        col = int(hex_value[i + 1], 16)
        out.append(format(SBox.AES[row * 16 + col], '02x'))
    return ''.join(out)

def s_box_reverse_lookup(hex_value: str) -> str:
    out = []
    for i in range(0, len(hex_value), 2):
        row = int(hex_value[i], 16)
        col = int(hex_value[i + 1], 16)
        out.append(format(SBox.AES_REVERSE[row * 16 + col], '08b'))
    return ''.join(out)

def xor_hex_strings(hex1: str, hex2: str, shift: int = 1) -> str:
    bin1 = ''.join(format(b, '08b') for b in bytes.fromhex(hex1))
    bin2 = ''.join(format(b, '08b') for b in bytes.fromhex(hex2))
    bin1 = bin1[shift:] + bin1[:shift]
    result = ''.join(str(int(a) ^ int(b)) for a, b in zip(bin1, bin2))
    result_hex = hex(int(result, 2))[2:].zfill((len(result) + 3) // 4)
    return result_hex if len(result_hex) % 2 == 0 else "0" + result_hex

def xor_hex_reverse(hex1: str, hex2: str, shift: int = 1) -> str:
    bin1 = ''.join(format(b, '08b') for b in bytes.fromhex(hex1))
    bin2 = ''.join(format(b, '08b') for b in bytes.fromhex(hex2))
    bin1 = bin1[shift:] + bin1[:shift]
    result = ''.join('1' if a != b else '0' for a, b in zip(bin1, bin2))
    result_hex = hex(int(result, 2))[2:].zfill((len(result) + 3) // 4)
    return result_hex

def pad_hex(hex_str: str, block: int = 16) -> str:
    padding = (block - len(hex_str) % block) % block
    return hex_str + '0' * padding

def to_ascii_from_hex(hex_str: str) -> str:
    return ''.join(chr(int(hex_str[i:i+2], 16)) if hex_str[i:i+2] != '00' else ' '
                   for i in range(0, len(hex_str), 2))

def pgn_to_text(pgn: str) -> str:
    if len(pgn.split('\n')) == 1:
        return pgn.replace("] ", "]\n")
    lines = pgn.strip().split('\n')
    return '\n'.join(lines)

def get_chess_matrix_from_positions(positions: List[str]) -> List[List[int]]:
    matrix = [[0 for _ in range(8)] for _ in range(8)]
    num = 1
    for pos in positions:
        row, col = pos_to_index(pos.strip())
        if matrix[row][col] == 0:
            matrix[row][col] = num
            num += 1
    for row in range(8):
        for col in range(8):
            if matrix[row][col] == 0:
                matrix[row][col] = num
                num += 1
    return matrix

def is_hexadecimal(ciphertext: str) -> bool:
    return all(char.isdigit() or char.lower() in 'abcdef' for char in ciphertext)

# --- ENCRYPTION LOGIC ---

def perform_encryption(plaintext: str, key1: str, key2_matrix: List[List[int]]) -> Tuple[str, str]:
    hex_plaintext = ''.join([format(ord(char), '02x') for char in plaintext])
    hex_key1 = ''.join([format(ord(char), '02x') for char in key1])
    key1_blocks_hex = [hex_key1[i:i+2] for i in range(0, len(hex_key1), 2)]
    key1_decimals = [int(block, 16) for block in key1_blocks_hex]
    shifted_number = (sum(key1_decimals) % 64) + 1
    encrypt_rounds = key1_decimals[0] + key1_decimals[1]
    addition = False
    for i in range(2, len(key1_decimals)):
        if addition:
            encrypt_rounds += key1_decimals[i]
        else:
            encrypt_rounds -= key1_decimals[i]
        addition = not addition
    encrypt_rounds_non_negative = abs(encrypt_rounds)
    rounds_modulo = (encrypt_rounds_non_negative % 10) + 1

    binary_plaintext = ''.join(format(byte, '08b') for byte in bytes.fromhex(plaintext))
    binary_key1 = ''.join(format(byte, '08b') for byte in bytes.fromhex(hex_key1))
    matrix_plain = [[0 for _ in range(8)] for _ in range(8)]
    matrix_key = [[0 for _ in range(8)] for _ in range(8)]

    index = 0
    for i in range(8):
        for j in range(8):
            bit_position = key2_matrix[i][j] - 1
            matrix_plain[i][j] = int(binary_plaintext[index + bit_position])
            matrix_key[i][j] = int(binary_key1[index + bit_position])

    blocks_plain = [matrix_plain[row][col] for col in range(8) for row in range(8)]
    blocks_key = [matrix_key[row][col] for col in range(8) for row in range(8)]
    output_plain = ''.join(map(str, blocks_plain))
    output_key = ''.join(map(str, blocks_key))
    xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(output_plain, output_key))
    shifted_xor_result = xor_result[shifted_number:] + xor_result[:shifted_number]
    shifted_xor_blocks = [shifted_xor_result[i:i+8] for i in range(0, len(shifted_xor_result), 8)]
    hex_result = ''.join(format(int(chunk, 2), '02x') for chunk in shifted_xor_blocks)
    hex_plaintext = hex_result
    hex_key1 = output_key

    ciphertext, key1_for_rounds = enkripsi_putaran(hex_plaintext, hex_key1, rounds_modulo, key2_matrix, shifted_number)
    hex_plaintext = ciphertext
    hex_key1 = key1_for_rounds

    sbox_plaintext = s_box_lookup(hex_plaintext)
    key1_blocks_bin = [hex_key1[i:i+8] for i in range(0, len(hex_key1), 8)]
    hex_key1 = ''.join(format(int(chunk, 2), '02x') for chunk in key1_blocks_bin)
    sbox_key1 = s_box_lookup(hex_key1)

    xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(sbox_plaintext, sbox_key1))
    shifted_xor_result = xor_result[shifted_number:] + xor_result[:shifted_number]
    shifted_xor_blocks = [shifted_xor_result[i:i+8] for i in range(0, len(shifted_xor_result), 8)]
    hex_result = ''.join(format(int(chunk, 2), '02x') for chunk in shifted_xor_blocks)
    ciphertext = hex_result
    result_ascii = to_ascii_from_hex(ciphertext)
    return ciphertext, result_ascii

def enkripsi_putaran(hex_plaintext, hex_key1, rounds_modulo, key2_matrix_8x8, shifted_number):
    ciphertext = hex_plaintext
    key1_for_rounds = hex_key1
    for _ in range(rounds_modulo):
        sbox_plaintext = s_box_lookup(ciphertext)
        key1_blocks_bin = [key1_for_rounds[i:i+8] for i in range(0, len(key1_for_rounds), 8)]
        key1_hex = ''.join(format(int(chunk, 2), '02x') for chunk in key1_blocks_bin)
        sbox_key1 = s_box_lookup(key1_hex)
        matrix_plain = [[0]*8 for _ in range(8)]
        matrix_key = [[0]*8 for _ in range(8)]
        for i in range(8):
            for j in range(8):
                bit_position = key2_matrix_8x8[i][j] - 1
                matrix_plain[i][j] = int(sbox_plaintext[bit_position])
                matrix_key[i][j] = int(sbox_key1[bit_position])
        output_plain = ''.join(str(matrix_plain[row][col]) for col in range(8) for row in range(8))
        output_key = ''.join(str(matrix_key[row][col]) for col in range(8) for row in range(8))
        xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(output_plain, output_key))
        shifted_xor_result = xor_result[shifted_number:] + xor_result[:shifted_number]
        shifted_xor_blocks = [shifted_xor_result[i:i+8] for i in range(0, len(shifted_xor_result), 8)]
        ciphertext = ''.join(format(int(chunk, 2), '02x') for chunk in shifted_xor_blocks)
        key1_for_rounds = output_key
    return ciphertext, key1_for_rounds

def perform_decryption(ciphertext: str, key1: str, key2_matrix: List[List[int]]) -> str:
    hex_key1 = ''.join([format(ord(char), '02x') for char in key1])
    key1_blocks_hex = [hex_key1[i:i+2] for i in range(0, len(hex_key1), 2)]
    key1_decimals = [int(block, 16) for block in key1_blocks_hex]
    shifted_number = (sum(key1_decimals) % 64) + 1
    encrypt_rounds = key1_decimals[0] + key1_decimals[1]
    addition = False
    for i in range(2, len(key1_decimals)):
        if addition:
            encrypt_rounds += key1_decimals[i]
        else:
            encrypt_rounds -= key1_decimals[i]
        addition = not addition
    encrypt_rounds_non_negative = abs(encrypt_rounds)
    rounds_modulo = (encrypt_rounds_non_negative % 10) + 1
    key1_binary = ''.join(format(byte, '08b') for byte in bytes.fromhex(hex_key1))
    key_matrix = [[0 for _ in range(8)] for _ in range(8)]
    index = 0
    for i in range(8):
        for j in range(8):
            bit_position = key2_matrix[i][j] - 1
            key_matrix[i][j] = int(key1_binary[index + bit_position])
    output_key = ''.join(str(key_matrix[row][col]) for col in range(8) for row in range(8))
    def generate_round_keys(output_key, rounds):
        round_keys = []
        for _ in range(rounds):
            key1_blocks_bin = [output_key[i:i+8] for i in range(0, len(output_key), 8)]
            hex_key1_local = ''.join(format(int(chunk, 2), '02x') for chunk in key1_blocks_bin)
            sbox_key1 = s_box_lookup(hex_key1_local)
            temp_key_matrix = [[0 for _ in range(8)] for _ in range(8)]
            for i in range(8):
                for j in range(8):
                    bit_position = key2_matrix[i][j] - 1
                    temp_key_matrix[i][j] = int(sbox_key1[index + bit_position])
            output_key = ''.join(str(temp_key_matrix[row][col]) for col in range(8) for row in range(8))
            round_keys.append(output_key)
        return round_keys
    round_keys = generate_round_keys(output_key, rounds_modulo)
    key1_blocks_bin = [round_keys[-1][i:i+8] for i in range(0, len(round_keys[-1]), 8)]
    hex_key1_final = ''.join(format(int(chunk, 2), '02x') for chunk in key1_blocks_bin)
    sbox_key1_final = s_box_lookup(hex_key1_final)
    byte_data = bytes.fromhex(ciphertext)
    ciphertext_binary = ''.join(format(byte, '08b') for byte in byte_data)
    shifted_xor = ciphertext_binary[-shifted_number:] + ciphertext_binary[:-shifted_number]
    xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(shifted_xor, sbox_key1_final))
    output_plaintext_bin = xor_result.zfill((len(xor_result) + 3) // 4 * 4)
    output_plaintext_hex = hex(int(output_plaintext_bin, 2))[2:].zfill(16)
    sbox_reverse = s_box_reverse_lookup(output_plaintext_hex)
    def generate_plaintext_rounds(sbox_reverse_val, rounds):
        plaintexts = []
        round_idx = rounds - 1
        for _ in range(rounds):
            shifted_xor = sbox_reverse_val[-shifted_number:] + sbox_reverse_val[:-shifted_number]
            xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(shifted_xor, round_keys[round_idx]))
            round_idx -= 1
            matrix_plain = [[0 for _ in range(8)] for _ in range(8)]
            for i in range(8):
                for j in range(8):
                    bit_position = SBox.MATRIX_8X8_DECRYPT[i][j] - 1
                    matrix_plain[i][j] = int(xor_result[index + bit_position])
            plain_blocks = [elem for row in matrix_plain for elem in row]
            key2_flat = [elem for row in key2_matrix for elem in row]
            plain_blocks_sorted = [plain_blocks[i] for i in sorted(range(len(key2_flat)), key=lambda k: key2_flat[k])]
            output_plaintext_bin = ''.join(map(str, plain_blocks_sorted))
            output_plaintext_bin = output_plaintext_bin.zfill((len(output_plaintext_bin) + 3) // 4 * 4)
            output_plaintext_hex = hex(int(output_plaintext_bin, 2))[2:].zfill(16)
            sbox_reverse_val = s_box_reverse_lookup(output_plaintext_hex)
            plaintexts.append(sbox_reverse_val)
        return plaintexts
    plaintexts = generate_plaintext_rounds(sbox_reverse, rounds_modulo)
    shifted_xor = plaintexts[-1][-shifted_number:] + plaintexts[-1][:-shifted_number]
    xor_result = ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(shifted_xor, output_key))
    matrix_plain = [[0 for _ in range(8)] for _ in range(8)]
    for i in range(8):
        for j in range(8):
            bit_position = SBox.MATRIX_8X8_DECRYPT[i][j] - 1
            matrix_plain[i][j] = int(xor_result[index + bit_position])
    plain_blocks = [elem for row in matrix_plain for elem in row]
    key2_flat = [elem for row in key2_matrix for elem in row]
    plain_blocks_sorted = [plain_blocks[i] for i in sorted(range(len(key2_flat)), key=lambda k: key2_flat[k])]
    output_plaintext_bin = ''.join(map(str, plain_blocks_sorted))
    output_plaintext_bin = output_plaintext_bin.zfill((len(output_plaintext_bin) + 3) // 4 * 4)
    output_plaintext_hex = hex(int(output_plaintext_bin, 2))[2:].zfill(16)
    if len(output_plaintext_hex) % 2 != 0:
        output_plaintext_hex = "0" + output_plaintext_hex
    decrypted_text = to_ascii_from_hex(output_plaintext_hex)
    return decrypted_text

# --- CORE ENCRYPTION/DECRYPTION API ---

def encrypt_core(data: Dict[str, Any], headers: Dict[str, Any]) -> Dict[str, Any]:
    start_time = time.time()
    plaintext = data.get('plaintext', '')
    if not plaintext:
        return {"ciphertext": "Mohon isi plaintext terlebih dahulu."}
    key1 = data.get('key1', '')
    if headers.get('Key1_type') == 'binary':
        bit_length = 8
        binary_values = [key1[i:i+bit_length] for i in range(0, len(key1), bit_length)]
        key1 = ''.join(chr(int(binary, 2)) for binary in binary_values)
    key2 = data.get('key2', '')
    pgn_text = data.get('text_pgn', '')
    square = data.get('square', '')

    fixed_results = []
    key2_matrix_8x8 = None

    # --- square logic ---
    squares_list = []
    if square and len(square) > 1 and len(pgn_text) > 1:
        squares_list = [sq.replace(" ", "") for sq in square.split(',')]
        for s_square in squares_list:
            pgn_output = pgn_to_text(pgn_text)
            sanitized_text = pgn_text.replace('\n', '').strip()
            filename_suffix = sanitized_text[-10:]
            filename = f"game_{filename_suffix}.pgn"
            with open(filename, "w") as file:
                file.write(pgn_output)
            piece_symbol = PIECE_MAP.get(s_square, "")
            def extract_moves(pgn_file, piece_symbol, s_square):
                moves = []
                promotions = []
                checkmate = []
                with open(pgn_file, "r") as file:
                    game = chess.pgn.read_game(file)
                    board = game.board()
                    prev_moves = []
                    modified_prev = ['NO MOVEMENT']
                    i = 0
                    for move in game.mainline_moves():
                        piece = board.piece_at(move.from_square)
                        if i == 0 and piece.symbol() == 'k' and piece_symbol == 'r' and chess.square_name(move.from_square) == 'e8':
                            if piece.symbol() != piece_symbol and piece_symbol == 'r' and board.san(move) == 'O-O-O' and s_square == 'a8':
                                moves.append(board.san(move))
                            if piece.symbol() != piece_symbol and piece_symbol == 'r' and board.san(move) == 'O-O' and s_square == 'h8':
                                moves.append(board.san(move))
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['f8'] if s_square == 'h8' else ['f1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['d8'] if s_square == 'h8' else ['d1']
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if i == 0 and piece.symbol() == 'K' and piece_symbol == 'R' and chess.square_name(move.from_square) == 'e1':
                            if piece.symbol() != piece_symbol and piece_symbol == 'R' and board.san(move) == 'O-O-O' and s_square == 'a1':
                                moves.append(board.san(move))
                            if piece.symbol() != piece_symbol and piece_symbol == 'R' and board.san(move) == 'O-O' and s_square == 'h1':
                                moves.append(board.san(move))
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['f8'] if s_square == 'h8' else ['f1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['d8'] if s_square == 'h8' else ['d1']
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if piece and piece.symbol() == piece_symbol and chess.square_name(move.from_square) == s_square:
                            san_move = board.san(move)
                            if 'x' in san_move and piece_symbol in ['P', 'p']:
                                san_move = san_move[2:]
                            moves.append(san_move)
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['g8'] if s_square == 'e8' else ['g1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['c8'] if s_square == 'e8' else ['c1']
                            elif piece.symbol() in ['P', 'p']:
                                modified_prev = [mv for mv in prev_moves]
                                modified_prev = [s[2:] if 'x' in s else s.replace('+', '') for s in modified_prev]
                            elif len(san_move) == 4 and '+' not in san_move:
                                modified_prev = [mv[2:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if i < len(modified_prev):
                            if 'x' in board.san(move) and modified_prev[-1] in board.san(move) and piece.symbol() != board.san(move)[0]:
                                if any('=' in mv for mv in modified_prev):
                                    break
                            if piece and piece.symbol() == piece_symbol and chess.square_name(move.from_square) == modified_prev[i]:
                                if 'x' in board.san(move) and chess.square_name(move.from_square)[0] != board.san(move)[0] and piece.symbol() in ['P', 'p']:
                                    break
                                moves.append(board.san(move))
                                prev_moves = moves
                                if piece.symbol() in ['P', 'p']:
                                    modified_prev = [mv for mv in prev_moves]
                                    modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                                else:
                                    modified_prev = [mv[1:] for mv in prev_moves]
                                    modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                                modified_prev = [item[1:] if len(item) == 3 else item for item in modified_prev]
                                if any('=' in item for item in modified_prev):
                                    piece_symbol = ''.join([item for item in modified_prev if '=' in item])
                                    piece_symbol = piece_symbol[-1]
                                    if any(len(item) == 4 for item in modified_prev):
                                        promotions = [item[:2] for item in modified_prev if len(item) == 4]
                                        modified_prev = [item[:2] if len(item) == 4 else item for item in modified_prev]
                                    if any(len(item) == 5 for item in modified_prev):
                                        promotions = [item[1:3] for item in modified_prev if len(item) == 5]
                                        modified_prev = [item[1:3] if len(item) == 5 else item for item in modified_prev]
                        if '#' in board.san(move):
                            checkmate = board.san(move)
                        board.push(move)
                return moves, modified_prev, promotions, checkmate
            moves, modified_prev, promotions, checkmate = extract_moves(filename, piece_symbol, s_square)
            if any('-O' in item for item in modified_prev):
                result = [item for item in modified_prev if 'O' not in item]
                if any('-O-O' in item for item in modified_prev):
                    if s_square == 'e8':
                        result = [s_square, "c8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "d1"] + result
                    else:
                        result = [s_square, "c1"] + result
                elif any('-O' in item for item in modified_prev):
                    if s_square == 'e8':
                        result = [s_square, "g8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "f8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "f1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "f8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "f1"] + result
                    else:
                        result = [s_square, "g1"] + result
                else:
                    if s_square == 'e8':
                        result = [s_square, "c8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'e1':
                        result = [s_square, "c1"] + result
                    else:
                        result = [s_square]
            elif modified_prev == ['NO MOVEMENT']:
                result = [s.replace('x', '').replace('+', '') for s in modified_prev]
                result = [s_square]
            else:
                result = [s.replace('x', '').replace('+', '') for s in modified_prev]
                result = [s_square] + result
            previous_letter = ''
            result_2 = []
            for item in result:
                if item[0].isdigit():
                    new_item = previous_letter + item
                else:
                    new_item = item
                    previous_letter = item[0]
                result_2.append(new_item)
            result_3 = []
            result_fixed = []
            for item in result_2:
                if item not in result_3:
                    result_3.append(item)
            for i in range(len(result_3)):
                if any('=' in item for item in result_3[i]):
                    result_3[i] = promotions[0] if promotions else result_3[i]
                elif any('#' in item for item in result_3[i]):
                    if len(checkmate) == 4:
                        result_3[i] = checkmate[1:][:-1]
                    elif len(checkmate) == 5:
                        result_3[i] = checkmate[2:][:-1]
                    elif len(checkmate) == 3:
                        result_3[i] = checkmate[:-1]
            for item in result_3:
                if item not in result_fixed:
                    result_fixed.append(item)
            result_fixed = ','.join(result_fixed)
            fixed_results.append(result_fixed)
            key2 = "".join(fixed_results)

    encryption_type = headers.get('X-Encryption-Type')

    if encryption_type == 'base64':
        plaintext = base64.b64decode(plaintext).decode('utf-8')
        key1 = base64.b64decode(key1).decode('utf-8')
        if len(square) > 1:
            key2 = key2
        else:
            key2 = base64.b64decode(key2).decode('utf-8')

    if len(key1) != 8:
        return {"ciphertext": "Error: key1 harus 8 karakter (termasuk spasi)."}

    if len(pgn_text) == 0 and len(square) > 0:
        if (len(pgn_text) == 0 and len(square) == 2):
            if square[-1].isdigit():
                return {"ciphertext": "Error: PGN harus diisi."}
            else:
                return {"ciphertext": "Error: Initial Square harus sesuai format: (a1)."}
        return {"ciphertext": "Error: Initial Square harus sesuai format: (a1)."}

    if len(pgn_text) > 0 and len(square) < 2:
        if (len(pgn_text) > 0 and len(square) == 0):
            return {"ciphertext": "Error: Initial Square harus diisi."}
        return {"ciphertext": "Error: Initial Square harus sesuai format: (a1)."}

    if '1.' not in pgn_text and key2 == square and len(square) != 0:
        return {"ciphertext": "Error: PGN salah."}

    if '1.' not in pgn_text and len(pgn_text) == 1:
        return {"ciphertext": "Error: PGN salah."}

    if key2:
        positions = key2.lower().replace(" ", "").split(',')
        valid_input = all(is_valid_chess_pos(pos.strip()) for pos in positions)
        duplicate_positions = len(set(positions)) != len(positions)
        if not valid_input or duplicate_positions:
            return {"ciphertext": "Error: Masukkan posisi blok yang benar (contoh: d8, b8, a8). Mohon cek panduan terlebih dahulu jika masih bingung."}
        key2_matrix_8x8 = get_chess_matrix_from_positions(positions)
    else:
        key2_matrix_8x8 = [[i*8 + j + 1 for j in range(8)] for i in range(8)]

    plaintext_hex = ''.join(format(ord(char), '02x') for char in plaintext)
    if len(plaintext_hex) % 16 != 0:
        plaintext_hex = pad_hex(plaintext_hex, 16)
    plaintext_blocks = split_text(plaintext_hex, 16)
    ciphertext_blocks = []
    previous_ciphertext_block = None
    for block in plaintext_blocks:
        ciphertext_block, _ = perform_encryption(block, key1, key2_matrix_8x8)
        if previous_ciphertext_block:
            ciphertext_block = xor_hex_strings(previous_ciphertext_block, ciphertext_block)
        ciphertext_blocks.append(ciphertext_block)
        previous_ciphertext_block = ciphertext_block
    ciphertext = ''.join(ciphertext_blocks)
    encryption_time = time.time() - start_time
    result = {"ciphertext": ciphertext, "encryption time": encryption_time}
    if square:
        result["result"] = fixed_results
    return result

def decrypt_core(data: Dict[str, Any], headers: Dict[str, Any]) -> Dict[str, Any]:
    start_time = time.time()
    ciphertext = data.get('ciphertext', '')
    if not ciphertext:
        return {"decrypted text": "Mohon isi ciphertext terlebih dahulu."}
    key1 = data.get('key1', '')
    if headers.get('Key1_type') == 'binary':
        bit_length = 8
        binary_values = [key1[i:i+bit_length] for i in range(0, len(key1), bit_length)]
        key1 = ''.join(chr(int(binary, 2)) for binary in binary_values)
    key2 = data.get('key2', '')
    pgn_text = data.get('text_pgn', '')
    square = data.get('square', '')

    results_fixed = []
    key2_matrix_8x8 = None

    # --- s_square logic for decrypt ---
    squares_list = []
    if square and len(square) > 1 and len(pgn_text) > 1:
        squares_list = [sq.replace(" ", "") for sq in square.split(',')]
        for s_square in squares_list:
            pgn_output = pgn_to_text(pgn_text)
            sanitized_text = pgn_text.replace('\n', '').strip()
            filename_suffix = sanitized_text[-10:]
            filename = f"game_{filename_suffix}.pgn"
            with open(filename, "w") as file:
                file.write(pgn_output)
            piece_symbol = PIECE_MAP.get(s_square, "")
            def extract_moves(pgn_file, piece_symbol, s_square):
                moves = []
                promotions = []
                checkmate = []
                with open(pgn_file, "r") as file:
                    game = chess.pgn.read_game(file)
                    board = game.board()
                    prev_moves = []
                    modified_prev = ['NO MOVEMENT']
                    i = 0
                    for move in game.mainline_moves():
                        piece = board.piece_at(move.from_square)
                        if i == 0 and piece.symbol() == 'k' and piece_symbol == 'r' and chess.square_name(move.from_square) == 'e8':
                            if piece.symbol() != piece_symbol and piece_symbol == 'r' and board.san(move) == 'O-O-O' and s_square == 'a8':
                                moves.append(board.san(move))
                            if piece.symbol() != piece_symbol and piece_symbol == 'r' and board.san(move) == 'O-O' and s_square == 'h8':
                                moves.append(board.san(move))
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['f8'] if s_square == 'h8' else ['f1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['d8'] if s_square == 'h8' else ['d1']
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if i == 0 and piece.symbol() == 'K' and piece_symbol == 'R' and chess.square_name(move.from_square) == 'e1':
                            if piece.symbol() != piece_symbol and piece_symbol == 'R' and board.san(move) == 'O-O-O' and s_square == 'a1':
                                moves.append(board.san(move))
                            if piece.symbol() != piece_symbol and piece_symbol == 'R' and board.san(move) == 'O-O' and s_square == 'h1':
                                moves.append(board.san(move))
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['f8'] if s_square == 'h8' else ['f1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['d8'] if s_square == 'h8' else ['d1']
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if piece and piece.symbol() == piece_symbol and chess.square_name(move.from_square) == s_square:
                            san_move = board.san(move)
                            if 'x' in san_move and piece_symbol in ['P', 'p']:
                                san_move = san_move[2:]
                            moves.append(san_move)
                            prev_moves = moves
                            if prev_moves == ['O-O']:
                                modified_prev = ['g8'] if s_square == 'e8' else ['g1']
                            elif prev_moves == ['O-O-O']:
                                modified_prev = ['c8'] if s_square == 'e8' else ['c1']
                            elif piece.symbol() in ['P', 'p']:
                                modified_prev = [mv for mv in prev_moves]
                                modified_prev = [s[2:] if 'x' in s else s.replace('+', '') for s in modified_prev]
                            elif len(san_move) == 4 and '+' not in san_move:
                                modified_prev = [mv[2:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                            else:
                                modified_prev = [mv[1:] for mv in prev_moves]
                                modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                        if i < len(modified_prev):
                            if 'x' in board.san(move) and modified_prev[-1] in board.san(move) and piece.symbol() != board.san(move)[0]:
                                if any('=' in mv for mv in modified_prev):
                                    break
                            if piece and piece.symbol() == piece_symbol and chess.square_name(move.from_square) == modified_prev[i]:
                                if 'x' in board.san(move) and chess.square_name(move.from_square)[0] != board.san(move)[0] and piece.symbol() in ['P', 'p']:
                                    break
                                moves.append(board.san(move))
                                prev_moves = moves
                                if piece.symbol() in ['P', 'p']:
                                    modified_prev = [mv for mv in prev_moves]
                                    modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                                else:
                                    modified_prev = [mv[1:] for mv in prev_moves]
                                    modified_prev = [s.replace('x', '').replace('+', '') for s in modified_prev]
                                modified_prev = [item[1:] if len(item) == 3 else item for item in modified_prev]
                                if any('=' in item for item in modified_prev):
                                    piece_symbol = ''.join([item for item in modified_prev if '=' in item])
                                    piece_symbol = piece_symbol[-1]
                                    if any(len(item) == 4 for item in modified_prev):
                                        promotions = [item[:2] for item in modified_prev if len(item) == 4]
                                        modified_prev = [item[:2] if len(item) == 4 else item for item in modified_prev]
                                    if any(len(item) == 5 for item in modified_prev):
                                        promotions = [item[1:3] for item in modified_prev if len(item) == 5]
                                        modified_prev = [item[1:3] if len(item) == 5 else item for item in modified_prev]
                        if '#' in board.san(move):
                            checkmate = board.san(move)
                        board.push(move)
                return moves, modified_prev, promotions, checkmate
            moves, modified_prev, promotions, checkmate = extract_moves(filename, piece_symbol, s_square)
            if any('-O' in item for item in modified_prev):
                result = [item for item in modified_prev if 'O' not in item]
                if any('-O-O' in item for item in modified_prev):
                    if s_square == 'e8':
                        result = [s_square, "c8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "d1"] + result
                    else:
                        result = [s_square, "c1"] + result
                elif any('-O' in item for item in modified_prev):
                    if s_square == 'e8':
                        result = [s_square, "g8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "f8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "f1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "f8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "f1"] + result
                    else:
                        result = [s_square, "g1"] + result
                else:
                    if s_square == 'e8':
                        result = [s_square, "c8"] + result
                    elif s_square == 'h8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'h1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'a8':
                        result = [s_square, "d8"] + result
                    elif s_square == 'a1':
                        result = [s_square, "d1"] + result
                    elif s_square == 'e1':
                        result = [s_square, "c1"] + result
                    else:
                        result = [s_square]
            elif modified_prev == ['NO MOVEMENT']:
                result = [s.replace('x', '').replace('+', '') for s in modified_prev]
                result = [s_square]
            else:
                result = [s.replace('x', '').replace('+', '') for s in modified_prev]
                result = [s_square] + result
            previous_letter = ''
            result_2 = []
            for item in result:
                if item[0].isdigit():
                    new_item = previous_letter + item
                else:
                    new_item = item
                    previous_letter = item[0]
                result_2.append(new_item)
            result_3 = []
            result_fixed = []
            for item in result_2:
                if item not in result_3:
                    result_3.append(item)
            for i in range(len(result_3)):
                if any('=' in item for item in result_3[i]):
                    result_3[i] = promotions[0] if promotions else result_3[i]
                elif any('#' in item for item in result_3[i]):
                    if len(checkmate) == 4:
                        result_3[i] = checkmate[1:][:-1]
                    elif len(checkmate) == 5:
                        result_3[i] = checkmate[2:][:-1]
                    elif len(checkmate) == 3:
                        result_3[i] = checkmate[:-1]
            for item in result_3:
                if item not in result_fixed:
                    result_fixed.append(item)
            result_fixed = ','.join(result_fixed)
            results_fixed.append(result_fixed)
            key2 = "".join(results_fixed)

    encryption_type = headers.get('X-Encryption-Type')

    if encryption_type == 'base64':
        ciphertext = base64.b64decode(ciphertext).decode('utf-8')
        key1 = base64.b64decode(key1).decode('utf-8')
        if len(square) > 1:
            key2 = key2
        else:
            key2 = base64.b64decode(key2).decode('utf-8')

    if len(ciphertext) % 16 != 0:
        return {"decrypted text": "Error: Cipherteks salah, cipherteks yang benar adalah kelipatan 16."}

    if len(key1) != 8:
        return {"decrypted text": "Error: key1 harus 8 karakter (termasuk spasi)."}

    if len(pgn_text) == 0 and len(square) > 0:
        if (len(pgn_text) == 0 and len(square) == 2):
            if square[-1].isdigit():
                return {"decrypted text": "Error: PGN harus diisi."}
            else:
                return {"decrypted text": "Error: Initial Square harus sesuai format: (a1)."}
        return {"decrypted text": "Error: Initial Square harus sesuai format: (a1)."}

    if len(pgn_text) > 0 and len(square) < 2:
        if (len(pgn_text) > 0 and len(square) == 0):
            return {"decrypted text": "Error: Initial Square harus diisi."}
        return {"decrypted text": "Error: Initial Square harus sesuai format: (a1)."}

    if '1.' not in pgn_text and key2 == square and len(square) != 0:
        return {"decrypted text": "Error: PGN salah."}

    if '1.' not in pgn_text and len(pgn_text) == 1:
        return {"decrypted text": "Error: PGN salah."}

    if key2:
        positions = key2.lower().replace(" ", "").split(',')
        valid_input = all(is_valid_chess_pos(pos.strip()) for pos in positions)
        duplicate_positions = len(set(positions)) != len(positions)
        if not valid_input or duplicate_positions:
            return {"decrypted text": "Error: Masukkan posisi blok yang benar (contoh: d8, b8, a8). Mohon cek panduan terlebih dahulu jika masih bingung."}
        key2_matrix_8x8 = get_chess_matrix_from_positions(positions)
    else:
        key2_matrix_8x8 = [[i*8 + j + 1 for j in range(8)] for i in range(8)]

    ciphertext_blocks = split_text(ciphertext, 16)
    decrypted_blocks = []
    previous_ciphertext_block = None
    block2 = None
    for i, block in enumerate(ciphertext_blocks):
        if previous_ciphertext_block:
            block2 = xor_hex_reverse(previous_ciphertext_block, block)
            previous_ciphertext_block = block
        if i == 0:
            decrypted_block = perform_decryption(block, key1, key2_matrix_8x8)
            decrypted_blocks.append(decrypted_block)
            previous_ciphertext_block = block
        else:
            decrypted_block = perform_decryption(block2, key1, key2_matrix_8x8)
            decrypted_blocks.append(decrypted_block)
    decrypted_text = ''.join(decrypted_blocks).rstrip()
    decryption_time = time.time() - start_time
    result = {
        "ciphertext": ciphertext,
        "decrypted text": decrypted_text,
        "decryption time": decryption_time
    }
    if square:
        result["result"] = results_fixed
    return result