import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import re

def decrypt_log(encrypted_line, key):
    if not encrypted_line.startswith("[LOCKED]"):
        return encrypted_line
    
    try:
        data = encrypted_line.replace("[LOCKED] ", "").strip()
        iv_hex, cipher_hex = data.split(":")
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(cipher_hex)
        
        # 使用 SHA256 派生密钥 (匹配 Node.js crypto.createHash('sha256'))
        key_bytes = hashlib.sha256(key.encode('utf-8')).digest()
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"[DECODE_FAILED] {encrypted_line.strip()} (Error: {str(e)})"

def main():
    if len(sys.argv) < 2:
        print("用法: python log_decode.py [LOCK_KEY]")
        print("请将需要解密的 log 文件命名为 log_1.txt 或 log_2.txt 放在同目录下。")
        return

    key = sys.argv[1]
    files_to_process = ["log_1.txt", "log_2.txt"]
    
    found_any = False
    for filename in files_to_process:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                print(f"\n--- 正在解密: {filename} ---")
                found_any = True
                for line in f:
                    print(decrypt_log(line, key), end="")
        except FileNotFoundError:
            continue
            
    if not found_any:
        print("错误: 在当前目录下未找到 log_1.txt 或 log_2.txt")

if __name__ == "__main__":
    main()
