#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <cstring>
#include <libgen.h>
#include <errno.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <dirent.h>
#include <limits.h>
#include <cstdint>
#include <algorithm>

// ===================== 全局常量配置区（与解密端100%一致） =====================
const char* const ENCRYPT_SECTION_NAME = ".encrypt_text";
// ✅ 核心：极简异或密钥（与解密端完全一致）
static const uint8_t XOR_KEY[] = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
static const size_t XOR_KEY_LEN = sizeof(XOR_KEY) / sizeof(XOR_KEY[0]);

// ===================== 加密工具类（极简异或版，与解密端严格对称） =====================
class CryptoTool {
public:
    static CryptoTool& getInstance() {
        static CryptoTool instance;
        return instance;
    }

    CryptoTool(const CryptoTool&) = delete;
    CryptoTool& operator=(const CryptoTool&) = delete;

    // ✅ 核心入口：极简异或加密（与解密端完全对称）
    void simpleXorEncrypt(uint8_t* data, size_t len) {
        if (!data || len == 0) return;
        // 循环异或密钥，100%可逆，无任何分段/位操作问题
        for (size_t i = 0; i < len; i++) {
            data[i] ^= XOR_KEY[i % XOR_KEY_LEN];
        }
    }

    // ✅ 调试用 - 打印异或密钥（用于和解密端对比）
    void printXorKey() {
        printf("[CryptoTool] XOR key (for debug):\n");
        for (int i = 0; i < XOR_KEY_LEN; i++) {
            printf("%02X ", XOR_KEY[i]);
        }
        printf("\n");
    }

private:
    CryptoTool() = default;
    ~CryptoTool() = default;
};

// ===================== 文件工具类（保留，无修改） =====================
class FileHelper {
public:
    static std::string getExeDir(int argc, char** argv) {
        char exePath[PATH_MAX] = {0};
        if (argc > 0 && argv[0] != nullptr && strlen(argv[0]) > 0) {
            if (realpath(argv[0], exePath) == nullptr) {
                char cwd[PATH_MAX] = {0};
                if (getcwd(cwd, sizeof(cwd)) != nullptr) {
                    snprintf(exePath, sizeof(exePath), "%s/%s", cwd, argv[0]);
                    realpath(exePath, exePath);
                } else {
                    return ".";
                }
            }
        } else {
            return ".";
        }
        
        std::string path(exePath);
        size_t pos = path.find_last_of('/');
        return (pos == std::string::npos) ? "." : path.substr(0, pos);
    }

    static std::vector<std::string> listFiles(const std::string& dir, const std::string& suffix) {
        std::vector<std::string> files;
        DIR* dp = opendir(dir.c_str());
        
        if (!dp) {
            fprintf(stderr, "[FileHelper] Failed to open directory: %s\n", dir.c_str());
            return files;
        }
        
        dirent* entry = nullptr;
        while ((entry = readdir(dp)) != nullptr) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            std::string fullPath = dir + "/" + entry->d_name;
            struct stat fileStat;
            
            if (stat(fullPath.c_str(), &fileStat) != 0 || !S_ISREG(fileStat.st_mode)) {
                continue;
            }
            
            if (fullPath.size() >= suffix.size() && 
                fullPath.substr(fullPath.size() - suffix.size()) == suffix) {
                files.push_back(fullPath);
            }
        }
        
        closedir(dp);
        return files;
    }

    static bool mkdirIfNotExist(const std::string& dir) {
        if (access(dir.c_str(), F_OK) == 0) {
            return true;
        }
        
        // 递归创建目录（支持多级目录）
        std::string temp = dir;
        size_t pos = 0;
        while ((pos = temp.find('/', pos + 1)) != std::string::npos) {
            std::string subDir = temp.substr(0, pos);
            if (access(subDir.c_str(), F_OK) != 0 && mkdir(subDir.c_str(), 0755) != 0) {
                fprintf(stderr, "[FileHelper] Failed to create subdir: %s\n", subDir.c_str());
                return false;
            }
        }
        
        if (mkdir(dir.c_str(), 0755) == 0) {
            return true;
        }
        
        return false;
    }

    static off_t getFileSize(const std::string& filePath) {
        struct stat st;
        return stat(filePath.c_str(), &st) == 0 ? st.st_size : -1;
    }

    // 验证文件完整性（加密前后MD5，可选）
    static std::string getFileMD5(const std::string& filePath) {
        // 可选：实现MD5计算，用于验证加密后文件未损坏
        return "unimplemented";
    }
};

// ===================== 核心加密函数（替换为异或加密） =====================
static bool encryptElfObjectFile(const std::string& objFilePath, CryptoTool& crypto) {
    off_t fileSize = FileHelper::getFileSize(objFilePath);
    if (fileSize <= 0) {
        fprintf(stderr, "[OBJ_ENC] ERROR: File empty or not exist! %s\n", objFilePath.c_str());
        return false;
    }

    int fd = open(objFilePath.c_str(), O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[OBJ_ENC] Open fail: %s %s\n", objFilePath.c_str(), strerror(errno));
        return false;
    }

    uint8_t* mapAddr = (uint8_t*)mmap(nullptr, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapAddr == MAP_FAILED) {
        fprintf(stderr, "[OBJ_ENC] Mmap fail: %s %s\n", objFilePath.c_str(), strerror(errno));
        close(fd);
        return false;
    }

    // Linux ELF解析（保留原有校验逻辑）
    Elf64_Ehdr* elfHdr = (Elf64_Ehdr*)mapAddr;
    if (memcmp(elfHdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[OBJ_ENC] Not a valid ELF file: %s\n", objFilePath.c_str());
        munmap(mapAddr, fileSize);
        close(fd);
        return false;
    }

    // 校验ELF位数（仅支持64位）
    if (elfHdr->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "[OBJ_ENC] Only 64-bit ELF supported: %s\n", objFilePath.c_str());
        munmap(mapAddr, fileSize);
        close(fd);
        return false;
    }

    Elf64_Shdr* shdr = (Elf64_Shdr*)(mapAddr + elfHdr->e_shoff);
    const char* shstrtab = (const char*)(mapAddr + shdr[elfHdr->e_shstrndx].sh_offset);
    bool found = false;

    for (int i = 0; i < elfHdr->e_shnum; ++i) {
        if (strcmp(shstrtab + shdr[i].sh_name, ENCRYPT_SECTION_NAME) == 0) {
            uint8_t* secData = mapAddr + shdr[i].sh_offset;
            size_t secSize = shdr[i].sh_size;
            
            if (secSize > 0) {
                printf("[OBJ_ENC] Encrypting %s: offset=0x%lx, size=0x%lx [极简异或加密]\n", 
                       ENCRYPT_SECTION_NAME, (unsigned long)shdr[i].sh_offset, (unsigned long)secSize);
                // ✅ 核心修改：替换为极简异或加密
                crypto.simpleXorEncrypt(secData, secSize);
                // 刷新缓存，确保数据写入
                __sync_synchronize();
            } else {
                printf("[OBJ_ENC] WARN: %s section is empty in %s\n", ENCRYPT_SECTION_NAME, objFilePath.c_str());
            }
            
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "[OBJ_ENC] WARN: %s not found in %s\n", 
                ENCRYPT_SECTION_NAME, objFilePath.c_str());
    }

    // 同步到磁盘（确保数据落盘）
    msync(mapAddr, fileSize, MS_SYNC | MS_INVALIDATE);
    munmap(mapAddr, fileSize);
    close(fd);
    
    // 验证文件大小未变
    off_t afterSize = FileHelper::getFileSize(objFilePath);
    if (afterSize == fileSize) {
        printf("[OBJ_ENC] Success! File size unchanged: %s (size: %ld bytes)\n", 
               objFilePath.c_str(), afterSize);
        return true;
    } else {
        fprintf(stderr, "[OBJ_ENC] ERROR: File size changed! before: %ld, after: %ld\n", 
                fileSize, afterSize);
        return false;
    }
}

// ===================== 批量加密器（保留结构，替换加密调用） =====================
class ObjEncryptor {
public:
    ObjEncryptor() : crypto(CryptoTool::getInstance()) {
        // 打印密钥，方便和解密端对比
        crypto.printXorKey();
    }
    
    int batchEncrypt(const std::string& objDir) {
        auto objFiles = FileHelper::listFiles(objDir, ".o");
        
        if (objFiles.empty()) {
            printf("[ObjEncryptor] No .o files found in %s\n", objDir.c_str());
            return 0;
        }

        int success = 0;
        for (const auto& file : objFiles) {
            printf("\n[ObjEncryptor] Processing: %s\n", file.c_str());
            if (encryptElfObjectFile(file, crypto)) {
                success++;
            }
        }
        
        printf("\n[ObjEncryptor] Summary: Processed %zu files, %d successful, %zu failed\n",
               objFiles.size(), success, objFiles.size() - success);
        
        return objFiles.size() - success;
    }

private:
    CryptoTool& crypto;
};

// ===================== 主函数（无修改） =====================
int main(int argc, char** argv) {
    printf("========================================\n");
    printf("Linux ELF Object File Encryptor (极简异或版)\n");
    printf("========================================\n");

    // 支持自定义目标目录（参数传入）
    std::string objDir;
    if (argc >= 2) {
        objDir = argv[1];
    } else {
        std::string exeDir = FileHelper::getExeDir(argc, argv);
        objDir = exeDir + "/../lib/";
    }
    
    printf("[Main] Target directory: %s\n", objDir.c_str());
    if (!FileHelper::mkdirIfNotExist(objDir)) {
        fprintf(stderr, "Failed to create directory: %s\n", objDir.c_str());
        return -1;
    }

    ObjEncryptor encryptor;
    int failed = encryptor.batchEncrypt(objDir);

    printf("\nEncryption complete. Failed: %d\n", failed);
    
    return failed > 0 ? -1 : 0;
}
