#ifndef SIMPLE_TEST_CLASS_H
#define SIMPLE_TEST_CLASS_H

#include "decryptor_linux.h"
#include <string>

// 简化测试类
class SimpleTestClass {
public:
    SimpleTestClass();
    ~SimpleTestClass();

    // 初始化方法 - 调用解密类
    void init();

    // 10个简单方法，其中5个加上加密宏
    void method1();
    void method2();
    void method3();
    void method4();
    void method5();
    
    CRYPT_FUNC void method6();
    CRYPT_FUNC void method7();
    CRYPT_FUNC void method8();
    CRYPT_FUNC void method9();
    CRYPT_FUNC void method10();

private:
    int m_counter;
};

#endif // SIMPLE_TEST_CLASS_H
