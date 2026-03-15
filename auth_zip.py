import os
import sys
import getpass

try:
    import pyzipper
except ImportError:
    print("错误: 未安装 pyzipper 库。")
    print("请先运行: pip install pyzipper")
    sys.exit(1)

def create_auth_zip():
    auth_dir = os.path.join(os.getcwd(), "auth")
    output_filename = "auth.zip"

    if not os.path.exists(auth_dir):
        print(f"错误: 未找到 auth 目录 ({auth_dir})")
        return

    # 获取所有 json 文件
    files = [f for f in os.listdir(auth_dir) if f.endswith(".json")]
    
    if not files:
        print("错误: auth 目录下没有 .json 文件。")
        return

    print(f"找到 {len(files)} 个认证文件。")
    
    # 交互式输入密码
    password = getpass.getpass("请输入 ZIP 加密密码: ")
    confirm_password = getpass.getpass("请再次确认密码: ")

    if password != confirm_password:
        print("错误: 两次输入的密码不一致！")
        return

    print(f"正在压缩并加密为 {output_filename}...")
    
    temp_inner_zip = "data.bundle" # 内部打包文件
    try:
        # 第一层：将所有文件打包进一个临时的未加密包中，这样外部就看不到文件名了
        print("正在进行第一层打包（隐藏文件名）...")
        with pyzipper.ZipFile(temp_inner_zip, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
            for f in files:
                file_path = os.path.join(auth_dir, f)
                # 统一放进 inner_auth 目录
                zf.write(file_path, arcname=os.path.join("auth", f))

        # 第二层：将内部包进行加密压缩
        print(f"正在进行第二层加密压缩...")
        # 注意：这里改用兼容性最强的传统加密 (ZipCrypto)，以便 Linux 的 unzip 命令直接解压
        with pyzipper.ZipFile(output_filename, 'w', compression=pyzipper.ZIP_DEFLATED) as zf:
            zf.setencryption(pyzipper.Encryption.TRADITIONAL)
            zf.setpassword(password.encode('utf-8'))
            zf.write(temp_inner_zip, arcname="bundle.zip")
                
        print(f"\n✅ 成功！双层加密后的文件已保存为: {os.path.abspath(output_filename)}")
        print("💡 现在外部只能看到一个 'bundle.zip'，看不到具体的 json 文件名了。")
    except Exception as e:
        print(f"压缩失败: {str(e)}")
    finally:
        # 清理临时文件
        if os.path.exists(temp_inner_zip):
            os.remove(temp_inner_zip)

if __name__ == "__main__":
    create_auth_zip()
