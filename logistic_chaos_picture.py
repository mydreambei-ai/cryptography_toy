import numpy as np
from PIL import Image


# -----------------------------
# Logistic map sequence generator
# -----------------------------
def logistic_map_sequence(length, r=3.99, x0=0.5):
    seq = np.zeros(length, dtype=np.uint8)
    x = x0
    for i in range(length):
        x = r * x * (1 - x)
        seq[i] = int((x * 1e14) % 256)  # 放大以增加熵
    return seq


# -----------------------------
# Encrypt/Decrypt function
# -----------------------------
def logistic_encrypt_decrypt(image_path, output_path, r=3.99, x0=0.5):
    img = Image.open(image_path).convert("RGB")
    img_array = np.array(img, dtype=np.uint8)
    flat = img_array.flatten()

    seq = logistic_map_sequence(len(flat), r, x0)

    # XOR
    encrypted = np.bitwise_xor(flat, seq)
    encrypted_img = encrypted.reshape(img_array.shape)

    # 使用无损格式保存
    Image.fromarray(encrypted_img).save(output_path, format="PNG")
    print(f"✅ Saved to {output_path}")
