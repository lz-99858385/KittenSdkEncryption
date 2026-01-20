#!/bin/bash
# build.sh - Linux 本机构建脚本

set -e  # 遇到错误立即退出

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

echo "[INFO] 开始构建 Linux 版本..."
echo "[INFO] 项目目录: $SCRIPT_DIR"
echo "[INFO] 构建目录: $BUILD_DIR"

# 清理并创建构建目录
if [ -d "$BUILD_DIR" ]; then
    echo "[INFO] 清理构建目录: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

# 配置 CMake
echo "[INFO] 配置 CMake 项目..."
cd "$BUILD_DIR"
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_LINUX_VERSION=ON

if [ $? -ne 0 ]; then
    echo "[ERROR] CMake 配置失败"
    exit 1
fi

echo "[INFO] CMake 配置成功"

# 编译项目
echo "[INFO] 开始编译项目..."

# 获取 CPU 核心数用于并行编译
cores=$(nproc)
echo "[INFO] 使用 $cores 个核心进行编译"

make -j$cores

if [ $? -ne 0 ]; then
    echo "[ERROR] 编译失败"
    exit 1
fi

echo "[INFO] 编译成功"

# 显示构建结果
echo ""
echo "[INFO] 构建完成！"
echo "构建目录: $BUILD_DIR"

# 显示生成的文件
if [ -d "$BUILD_DIR/lib" ]; then
    echo "生成的库文件:"
    ls -la "$BUILD_DIR/lib/"*.a 2>/dev/null || echo "  无库文件"
fi

if [ -d "$BUILD_DIR/bin" ]; then
    echo "生成的可执行文件:"
    ls -la "$BUILD_DIR/bin/"* 2>/dev/null || echo "  无可执行文件"
fi

echo "[INFO] 构建脚本执行完成"
