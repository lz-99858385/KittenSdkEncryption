/*#pragma GCC diagnostic ignored "-Wattributes"
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/elf.h>
#include <sys/stat.h>
#include <cstring>
#include <libgen.h>
#include <errno.h>
#include <cstdlib>
#include <string>
#include <vector>
#include <dirent.h>
#include <limits.h>

// ===================== 唯一全局常量：加密段名称 + 异或密钥（你可以随便改） =====================
const char* const ENCRYPT_SECTION_NAME = ".encrypt_text";
// ✅ 核心：自定义固定异或密钥，16字节（可改成任意长度、任意值）
const uint8_t XOR_KEY[16] = {0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
const size_t XOR_KEY_LEN = sizeof(XOR_KEY);

// ===================== 极简加密工具类（只有简单异或，无任何多余逻辑） =====================
class CryptoTool {
public:
    static CryptoTool& getInstance() {
        static CryptoTool instance;
        return instance;
    }

    CryptoTool(const CryptoTool&) = delete;
    CryptoTool& operator=(const CryptoTool&) = delete;

    // ✅ 核心功能：简单异或加密（解密时调用同一个函数即可，异或可逆）
    void simpleXorCrypt(uint8_t* data, size_t len) {
        if (!data || len == 0) return;
        for (size_t i = 0; i < len; ++i) {
            data[i] ^= XOR_KEY[i % XOR_KEY_LEN]; // 密钥循环使用
        }
    }

private:
    CryptoTool() = default;
    ~CryptoTool() = default;
};

// ===================== 文件工具类（保留核心功能，无冗余） =====================
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
                    fprintf(stderr, "[FileHelper] getcwd failed: %s\n", strerror(errno));
                    fflush(stderr);
                    return ".";
                }
            }
        } else {
            fprintf(stderr, "[FileHelper] argv[0] empty\n");
            fflush(stderr);
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
            fprintf(stderr, "[FileHelper] Open dir fail: %s %s\n", dir.c_str(), strerror(errno));
            fflush(stderr);
            return files;
        }
        dirent* entry = nullptr;
        while ((entry = readdir(dp)) != nullptr) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            std::string fullPath = dir + "/" + entry->d_name;
            struct stat fileStat;
            if (stat(fullPath.c_str(), &fileStat) != 0 || !S_ISREG(fileStat.st_mode)) continue;
            if (fullPath.size() >= suffix.size() && fullPath.substr(fullPath.size() - suffix.size()) == suffix) {
                files.push_back(fullPath);
            }
        }
        closedir(dp);
        return files;
    }

    static bool mkdirIfNotExist(const std::string& dir) {
        if (access(dir.c_str(), F_OK) == 0) return true;
        if (mkdir(dir.c_str(), 0755) == 0) {
            printf("[FileHelper] Create dir: %s\n", dir.c_str());
            fflush(stdout);
            return true;
        }
        fprintf(stderr, "[FileHelper] Mkdir fail: %s %s\n", dir.c_str(), strerror(errno));
        fflush(stderr);
        return false;
    }

    static off_t getFileSize(const std::string& filePath) {
        struct stat st;
        return stat(filePath.c_str(), &st) == 0 ? st.st_size : -1;
    }
};

// ===================== 核心加密函数（只保留ELF解析+异或，无多余逻辑） =====================
static bool encryptElfObjectFile(const std::string& objFilePath, CryptoTool& crypto) {
    off_t fileSize = FileHelper::getFileSize(objFilePath);
    if (fileSize <= 0) {
        fprintf(stderr, "[OBJ_ENC] ERROR: File empty or not exist! %s\n", objFilePath.c_str());
        fflush(stderr);
        return false;
    }

    int fd = open(objFilePath.c_str(), O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[OBJ_ENC] Open fail: %s %s\n", objFilePath.c_str(), strerror(errno));
        fflush(stderr);
        return false;
    }

    uint8_t* mapAddr = (uint8_t*)mmap(nullptr, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapAddr == MAP_FAILED) {
        fprintf(stderr, "[OBJ_ENC] Mmap fail: %s %s\n", objFilePath.c_str(), strerror(errno));
        close(fd);
        fflush(stderr);
        return false;
    }

    // 解析ELF，找.encrypt_text段
    Elf64_Ehdr* elfHdr = (Elf64_Ehdr*)mapAddr;
    if (memcmp(elfHdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[OBJ_ENC] Not valid ELF: %s\n", objFilePath.c_str());
        munmap(mapAddr, fileSize);
        close(fd);
        fflush(stderr);
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
                printf("[OBJ_ENC] Encrypt %s: offset=0x%lx, size=0x%lx\n", ENCRYPT_SECTION_NAME, shdr[i].sh_offset, secSize);
                crypto.simpleXorCrypt(secData, secSize);
            }
            found = true;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "[OBJ_ENC] WARN: %s not found in %s\n", ENCRYPT_SECTION_NAME, objFilePath.c_str());
    }

    // 同步+释放资源
    msync(mapAddr, fileSize, MS_SYNC);
    munmap(mapAddr, fileSize);
    close(fd);
    printf("[OBJ_ENC] Success: %s (size unchanged)\n", objFilePath.c_str());
    fflush(stdout);
    return true;
}

// ===================== 批量加密器 =====================
class ObjEncryptor {
public:
    ObjEncryptor() : crypto(CryptoTool::getInstance()) {}
    int batchEncrypt(const std::string& objDir) {
        auto objFiles = FileHelper::listFiles(objDir, ".o");
        if (objFiles.empty()) {
            printf("[ObjEncryptor] No .o files in %s\n", objDir.c_str());
            return 0;
        }

        int success = 0;
        for (const auto& file : objFiles) {
            if (encryptElfObjectFile(file, crypto)) success++;
        }
        printf("[ObjEncryptor] Total: %zu, Success: %d, Failed: %zu\n", objFiles.size(), success, objFiles.size()-success);
        fflush(stdout);
        return objFiles.size() - success;
    }
private:
    CryptoTool& crypto;
};

// ===================== 主函数（极简） =====================
int main(int argc, char** argv) {
    printf("========================================\n");
    printf("[Main] QNX AARCH64 Simple XOR Encrypt Tool\n");
    printf("========================================\n");
    fflush(stdout);

    std::string exeDir = FileHelper::getExeDir(argc, argv);
    std::string objDir = exeDir + "/static";
    FileHelper::mkdirIfNotExist(objDir);

    ObjEncryptor encryptor;
    int failed = encryptor.batchEncrypt(objDir);

    printf("\n[Main] Finish! Failed count: %d\n", failed);
    return failed > 0 ? -1 : 0;
}
*/