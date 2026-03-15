import sys
import os
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
        print("请将需要解密的加密日志 (.txt) 放入 'log' 文件夹中。")
        return

    key = sys.argv[1]
    log_dir = "log"
    output_dir = "log_decode"

    if not os.path.exists(log_dir):
        print(f"错误: 未找到 '{log_dir}' 目录。请创建该目录并将加密日志放进去。")
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"已创建输出目录: {output_dir}")

    files = [f for f in os.listdir(log_dir) if f.endswith(".txt")]
    
    if not files:
        print(f"提示: 在 '{log_dir}' 目录下未找到任何 .txt 文件。")
        return

    print(f"发现 {len(files)} 个日志文件，开始解密...")
    
    for filename in files:
        input_path = os.path.join(log_dir, filename)
        output_path = os.path.join(output_dir, filename)
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f_in, \
                 open(output_path, 'w', encoding='utf-8') as f_out:
                print(f"  • 正在解密: {filename} -> {output_path}")
                for line in f_in:
                    f_out.write(decrypt_log(line, key))
        except Exception as e:
            print(f"  ❌ 处理 {filename} 时出错: {str(e)}")
            
    print("\n✅ 所有任务处理完毕。解密后的日志位于 'log_decode' 目录下。")

if __name__ == "__main__":
    main()
