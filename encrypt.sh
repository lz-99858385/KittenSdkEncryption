#!/bin/bash

# encrypt.sh - 预编译处理脚本
# 功能：解包静态库 -> 执行加密工具 -> 重新打包

set -e  # 遇到错误立即退出

echo "=== 开始执行预编译处理脚本 ==="

# 检查当前目录
CURRENT_DIR=$(pwd)
echo "当前目录: $CURRENT_DIR"

# 1. 进入build目录
BUILD_DIR="build"
if [ ! -d "$BUILD_DIR" ]; then
    echo "错误: build目录不存在，请先运行CMake配置"
    exit 1
fi

cd "$BUILD_DIR"
echo "已进入build目录: $(pwd)"

# 2. 进入lib目录执行ar x *.a
LIB_DIR="lib"
if [ ! -d "$LIB_DIR" ]; then
    echo "错误: lib目录不存在"
    exit 1
fi

cd "$LIB_DIR"
echo "已进入lib目录: $(pwd)"

# 查找.a文件
A_FILES=$(ls *.a 2>/dev/null || true)
if [ -z "$A_FILES" ]; then
    echo "警告: 未找到.a文件，跳过解包步骤"
else
    echo "找到.a文件: $A_FILES"
    
    # 解包所有.a文件
    for A_FILE in $A_FILES; do
        echo "解包静态库: $A_FILE"
        ar x "$A_FILE"
    done
    
    # 检查解包结果
    O_FILES=$(ls *.o 2>/dev/null || true)
    if [ -n "$O_FILES" ]; then
        echo "解包成功，生成.o文件: $O_FILES"
    else
        echo "警告: 解包后未生成.o文件"
    fi
fi

# 3. 退出到build目录，进入bin目录执行encrypt_tool
cd ..  # 回到build目录
echo "回到build目录: $(pwd)"

BIN_DIR="bin"
if [ ! -d "$BIN_DIR" ]; then
    echo "错误: bin目录不存在"
    exit 1
fi

cd "$BIN_DIR"
echo "已进入bin目录: $(pwd)"

# 检查encrypt_tool是否存在
if [ ! -f "encrypt_tool" ]; then
    echo "错误: encrypt_tool可执行文件不存在"
    exit 1
fi

echo "执行加密工具: ./encrypt_tool"
./encrypt_tool

# 4. 退出到build目录，进入lib目录执行ar rsc *.o
cd ..  # 回到build目录
echo "回到build目录: $(pwd)"

cd "$LIB_DIR"
echo "再次进入lib目录: $(pwd)"

O_FILES=$(ls *.o 2>/dev/null || true)
if [ -z "$O_FILES" ]; then
    echo "警告: 未找到.o文件，跳过打包步骤"
else
    echo "找到.o文件: $O_FILES"
    
    # 直接替换原来的.a文件，而不是创建新的
    echo "重新打包为原来的 encrypt_core.a"
    ar rcs encrypt_core.a *.o
    
    # 检查打包结果
    if [ -f "encrypt_core.a" ]; then
        echo "打包成功: encrypt_core.a (已替换)"
        echo "复制 encrypt_core.a 到项目根目录的lib目录"

        cp encrypt_core.a "$CURRENT_DIR/lib/"
        if [ -f "$CURRENT_DIR/lib/encrypt_core.a" ]; then
            echo "复制成功: $CURRENT_DIR/lib/encrypt_core.a"
        else
            echo "警告: 复制到项目lib目录失败"
        fi

    else
        echo "错误: 打包失败"
        exit 1
    fi
fi
# 回到原始目录
cd "$CURRENT_DIR"
echo "回到原始目录: $(pwd)"



echo "=== 预编译处理脚本执行完成 ==="
