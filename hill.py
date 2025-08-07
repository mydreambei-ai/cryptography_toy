import math

import numpy as np

from common import extended_gcd

PADDING_KEY = "\x00"
alphabet = PADDING_KEY + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

N = len(alphabet)

char_to_int = {char: idx for idx, char in enumerate(alphabet)}
int_to_char = {idx: char for idx, char in enumerate(alphabet)}


def inverse_matrix_2x2(A, p):
    """求 2x2 矩阵在有限域 Z/pZ 上的逆矩阵"""
    a, b = A[0]
    c, d = A[1]

    det = (a * d - b * c) % p
    if det == 0:
        raise ValueError("The matrix is not invertible.")

    det_inv = extended_gcd(det, p)[1]

    inv_A = [
        [(d * det_inv) % p, (-b * det_inv) % p],
        [(-c * det_inv) % p, (a * det_inv) % p],
    ]

    return np.array(inv_A)


def det(A):
    return (A[0][0] * A[1][1] - A[0][1] * A[1][0]) % N


def generate_key():
    while 1:
        key = np.random.randint(1, N, (2, 2))
        det_key = det(key)
        if math.gcd(det_key, N) != 1:
            continue
        return key


def pad_message(message, block_size):
    padding_len = block_size - (len(message) % block_size)
    padding = "\x00" * padding_len
    return message + padding


def text_to_matrix(text, block_size):
    """将文本转换为矩阵"""
    int_values = [char_to_int[char] for char in text]
    matrix = np.array(int_values).reshape(-1, block_size)
    return matrix


def matrix_to_text(matrix):
    """将矩阵转换为文本"""
    text = "".join(int_to_char[value] for value in matrix.flatten())
    return text


def encrypt(plain_text, key_matrix):
    block_size = key_matrix.shape[0]
    padded_text = pad_message(plain_text, block_size)
    plain_matrix = text_to_matrix(padded_text, block_size)
    cipher_matrix = np.dot(plain_matrix, key_matrix) % N
    cipher_text = matrix_to_text(cipher_matrix)
    return cipher_text


def decrypt(cipher_text, key_matrix):
    block_size = key_matrix.shape[0]
    cipher_matrix = text_to_matrix(cipher_text, block_size)
    inv_key_matrix = inverse_matrix_2x2(key_matrix, N)

    plain_matrix = np.dot(cipher_matrix, inv_key_matrix) % N
    plain_text = matrix_to_text(plain_matrix)
    return plain_text


if __name__ == "__main__":
    key = generate_key()
    m = "HELLOWORLD"
    m1 = encrypt(m, key)
    m2 = decrypt(m1, key)
    print(f"m: {m}\nm1: {m1}\nm2:{m2}")
