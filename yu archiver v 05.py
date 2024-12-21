import os
import sys
import bz2
import zlib
import lzma
import tarfile
import shutil
import io
import concurrent.futures
import hashlib
from typing import Union, List, Optional

class YuanYangCompressor:
    def __init__(self, max_workers: Optional[int] = None):
        """
        初始化压缩器
        :param max_workers: 并行工作的最大线程数，默认为CPU核心数
        """
        self.max_workers = max_workers or os.cpu_count()
        # 压缩级别映射，优化低档压缩速度
        self.compression_levels = {
            9: {'method': 'store', 'level': 0},   # 仅存档，无压缩
            8: {'method': 'zlib', 'level': 1},    # 最低压缩
            7: {'method': 'zlib', 'level': 3},    
            6: {'method': 'zlib', 'level': 5},   
            5: {'method': 'bzip2', 'level': 1},  
            4: {'method': 'bzip2', 'level': 3},  
            3: {'method': 'bzip2', 'level': 5},  
            2: {'method': 'lzma', 'level': 4},   # 降低压缩级别提高速度
            1: {'method': 'lzma', 'level': 7}    # 降低压缩级别提高速度
        }

    def _generate_sha256_hash(self, data: bytes) -> str:
        """
        生成SHA-256哈希值
        :param data: 输入字节数据
        :return: 十六进制哈希字符串
        """
        return hashlib.sha256(data).hexdigest()

    def _encrypt_file_with_hash(self, source_path: str, target_path: str):
        """
        使用源文件内容的SHA-256哈希值加密文件
        :param source_path: 源文件路径
        :param target_path: 目标文件路径
        """
        with open(source_path, 'rb') as f:
            original_data = f.read()
        
        # 计算哈希值
        file_hash = self._generate_sha256_hash(original_data)
        
        # 将哈希值作为加密密钥
        hash_bytes = bytes.fromhex(file_hash)
        
        # 异或加密
        encrypted_data = bytearray(len(original_data))
        for i in range(len(original_data)):
            encrypted_data[i] = original_data[i] ^ hash_bytes[i % len(hash_bytes)]
        
        # 保存加密后的文件
        with open(target_path, 'wb') as f:
            # 在文件开头存储文件哈希值，用于解密验证
            f.write(file_hash.encode('utf-8'))
            f.write(b'\n')  # 分隔符
            f.write(encrypted_data)

    def _decrypt_file_with_hash(self, encrypted_path: str, target_path: str):
        """
        使用SHA-256哈希值解密文件
        :param encrypted_path: 加密文件路径
        :param target_path: 目标解密文件路径
        """
        with open(encrypted_path, 'rb') as f:
            # 尝试读取哈希值
            first_line = f.readline()
            try:
                # 尝试解码哈希值
                original_hash = first_line.decode('utf-8').strip()
                
                # 如果成功解码，说明是加密文件
                # 读取加密数据
                encrypted_data = f.read()
                
                # 重新生成哈希值作为解密密钥
                hash_bytes = bytes.fromhex(original_hash)
                
                # 异或解密
                decrypted_data = bytearray(len(encrypted_data))
                for i in range(len(encrypted_data)):
                    decrypted_data[i] = encrypted_data[i] ^ hash_bytes[i % len(hash_bytes)]
                
                # 验证解密后的内容哈希值
                decrypted_hash = self._generate_sha256_hash(decrypted_data)
                if decrypted_hash != original_hash:
                    raise ValueError("解密验证失败，文件可能被篡改")
                
                # 保存解密后的文件
                with open(target_path, 'wb') as out_f:
                    out_f.write(decrypted_data)
                
            except (UnicodeDecodeError, ValueError):
                # 如果不是加密文件，直接复制原文件
                f.seek(0)
                with open(target_path, 'wb') as out_f:
                    shutil.copyfileobj(f, out_f)

    def _compress_store(self, source_path: str, archive_path: str, is_encrypted: bool = False):
        """仅存档，不压缩，可选哈希加密"""
        with tarfile.open(archive_path, "w") as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        
        # 如果需要加密
        if is_encrypted:
            temp_path = archive_path + '.temp'
            os.rename(archive_path, temp_path)
            self._encrypt_file_with_hash(temp_path, archive_path)
            os.remove(temp_path)

    def _compress_zlib(self, source_path: str, archive_path: str, level: int, is_encrypted: bool = False):
        """使用zlib压缩，可选哈希加密"""
        with tarfile.open(archive_path, f"w:gz", compresslevel=level) as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        
        # 如果需要加密
        if is_encrypted:
            temp_path = archive_path + '.temp'
            os.rename(archive_path, temp_path)
            self._encrypt_file_with_hash(temp_path, archive_path)
            os.remove(temp_path)

    def _compress_bzip2(self, source_path: str, archive_path: str, level: int, is_encrypted: bool = False):
        """使用bzip2压缩，可选哈希加密"""
        with tarfile.open(archive_path, f"w:bz2", compresslevel=level) as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        
        # 如果需要加密
        if is_encrypted:
            temp_path = archive_path + '.temp'
            os.rename(archive_path, temp_path)
            self._encrypt_file_with_hash(temp_path, archive_path)
            os.remove(temp_path)

    def _compress_lzma(self, source_path: str, archive_path: str, level: int, is_encrypted: bool = False):
        """使用LZMA压缩，可选哈希加密"""
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        tar_buffer.seek(0)
        
        # 使用 LZMA 压缩 
        with open(archive_path, 'wb') as f_out:
            with lzma.open(f_out, 'wb', preset=level) as lzma_out:
                lzma_out.write(tar_buffer.getvalue())
        
        # 如果需要加密
        if is_encrypted:
            temp_path = archive_path + '.temp'
            os.rename(archive_path, temp_path)
            self._encrypt_file_with_hash(temp_path, archive_path)
            os.remove(temp_path)

    def _parallel_file_compression(self, sources: List[str], archive_paths: List[str], compression_configs: List[dict], is_encrypted: bool):
        """
        并行压缩多个文件/文件夹
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交并发任务
            futures = []
            for source, archive_path, config in zip(sources, archive_paths, compression_configs):
                future = executor.submit(
                    self._single_file_compression, 
                    source, 
                    archive_path, 
                    config['method'], 
                    config['level'],
                    is_encrypted
                )
                futures.append(future)
            
            # 等待所有任务完成并处理异常
            concurrent.futures.wait(futures)
            for future in futures:
                try:
                    future.result()  # 检查是否有异常
                except Exception as e:
                    print(f"压缩任务异常: {e}")

    def _single_file_compression(self, source_path: str, archive_path: str, method: str, level: int, is_encrypted: bool):
        """单文件压缩处理"""
        if method == 'store':
            self._compress_store(source_path, archive_path, is_encrypted)
        elif method == 'zlib':
            self._compress_zlib(source_path, archive_path, level, is_encrypted)
        elif method == 'bzip2':
            self._compress_bzip2(source_path, archive_path, level, is_encrypted)
        elif method == 'lzma':
            self._compress_lzma(source_path, archive_path, level, is_encrypted)
        else:
            raise ValueError("不支持的压缩方法")

    def compress(self, source_path: Union[str, List[str]], archive_path: str, level: int = 5, is_encrypted: bool = False):
        """
        压缩文件/文件夹
        """
        # 规范化输入
        sources = [source_path] if isinstance(source_path, str) else source_path
        
        # 确保文件扩展名为 .yu
        archive_paths = []
        for i, source in enumerate(sources):
            path = archive_path if len(sources) == 1 else f"{archive_path}_{i+1}"
            if not path.endswith('.yu'):
                path += '.yu'
            archive_paths.append(path)

        # 验证压缩级别
        if level not in range(1, 10):
            raise ValueError("压缩级别必须在1-9之间")

        # 准备压缩配置
        compression_configs = [self.compression_levels[level]] * len(sources)

        # 并行压缩
        self._parallel_file_compression(sources, archive_paths, compression_configs, is_encrypted)
        
        for path in archive_paths:
            print(f"压缩完成：{path}")
        
        return archive_paths[0] if len(archive_paths) == 1 else archive_paths

    def _extract_with_normal_permissions(self, tar_obj, extract_path):
        """
        使用普通用户权限解压文件
        :param tar_obj: tarfile对象
        :param extract_path: 解压目标路径
        """
        # 定义普通用户的权限掩码
        NORMAL_PERMISSION = 0o644  # 文件权限
        NORMAL_DIR_PERMISSION = 0o755  # 目录权限
    
        for member in tar_obj.getmembers():
            # 设置普通权限
            if member.isdir():
                member.mode = NORMAL_DIR_PERMISSION
            else:
                member.mode = NORMAL_PERMISSION
            
            # 解压单个文件
            tar_obj.extract(member, path=extract_path)

    def decompress(self, archive_path: str, extract_path: str = None):
        """
        解压缩文件
        """
        # 验证压缩文件是否存在
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"文件 {archive_path} 不存在")

        # 如果未指定解压路径，使用压缩文件名创建目录
        if extract_path is None:
            base_name = os.path.splitext(os.path.basename(archive_path))[0]
            extract_path = os.path.join(os.getcwd(), base_name + "_extracted")

        # 确保目标目录存在
        os.makedirs(extract_path, exist_ok=True)

        # 临时解密文件
        temp_path = archive_path + '.temp'
        self._decrypt_file_with_hash(archive_path, temp_path)

        # 支持多种压缩格式的解压
        try:
            # 尝试不同的解压方法
            opened_file = None
            tar_buffer = None
            
            try:
                # 尝试 LZMA 解压
                opened_file = lzma.open(temp_path, 'rb')
                tar_buffer = io.BytesIO(opened_file.read())
            except Exception:
                # 如果 LZMA 失败，尝试 gzip 压缩
                try:
                    opened_file = tarfile.open(temp_path, 'r:gz')
                    self._extract_with_normal_permissions(opened_file, extract_path)
                    return extract_path
                except Exception:
                    # 如果 gzip 失败，尝试 bzip2 压缩
                    try:
                        opened_file = tarfile.open(temp_path, 'r:bz2')
                        self._extract_with_normal_permissions(opened_file, extract_path)
                        return extract_path
                    except Exception:
                        # 如果所有压缩方法都失败，尝试普通 tar
                        try:
                            opened_file = tarfile.open(temp_path, 'r')
                            self._extract_with_normal_permissions(opened_file, extract_path)
                            return extract_path
                        except Exception as e:
                            raise RuntimeError(f"无法识别的压缩格式: {e}")
            
            # 处理 LZMA 压缩的情况
            if tar_buffer:
                with tarfile.open(fileobj=tar_buffer) as tar:
                    tar.extractall(path=extract_path)
            
            # 关闭文件
            if opened_file:
                opened_file.close()
            
            # 删除临时解密文件
            os.remove(temp_path)
            
            print(f"解压完成：{archive_path} -> {extract_path}")
            return extract_path
        
        except Exception as e:
            # 删除临时解密文件
            if os.path.exists(temp_path):
                os.remove(temp_path)
            print(f"解压错误: {e}")
            raise

def main():
    # 检查参数数量
    if len(sys.argv) < 4:
        print("压缩用法: yu '文件/文件夹名' '压缩包文件名' '-压缩级别' ['-cry']")
        print("解压用法: yu '-dec' '压缩包文件名' '解压目标文件夹'")
        sys.exit(1)

    # 支持更多的并行压缩选项
    compressor = YuanYangCompressor()

    # 判断是压缩还是解压缩
    if sys.argv[1] == '-dec':
        # 解压缩模式
        archive_path = sys.argv[2]
        extract_path = sys.argv[3]

        # 验证 .yu 扩展名
        if not archive_path.endswith('.yu'):
            print("错误：压缩文件必须以 .yu 为扩展名")
            sys.exit(1)

        try:
            compressor.decompress(archive_path, extract_path)
        except Exception as e:
            print(f"解压失败: {e}")
            sys.exit(1)
    else:
        # 压缩模式
        source_path = sys.argv[1]
        archive_path = sys.argv[2]
        level = int(sys.argv[3].replace('-', ''))
        
        # 检查是否启用加密
        is_encrypted = '-cry' in sys.argv

        try:
            compressor.compress(source_path, archive_path, level, is_encrypted)
        except Exception as e:
            print(f"压缩失败: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
