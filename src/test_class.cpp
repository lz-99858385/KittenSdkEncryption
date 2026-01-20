#include "test_class.h"
#include <iostream>

// ===================== 构造函数和析构函数 =====================
SimpleTestClass::SimpleTestClass() : m_counter(0) {
    std::cout << "[SimpleTestClass] Constructor called" << std::endl;
}

SimpleTestClass::~SimpleTestClass() {
    std::cout << "[SimpleTestClass] Destructor called, counter: " << m_counter << std::endl;
}

// ===================== 初始化方法 - 调用解密类 =====================
void SimpleTestClass::init() {
    std::cout << "[SimpleTestClass] Initializing..." << std::endl;
    
    // 调用解密类进行初始化
    Decryptor::setTargetInfo(Decryptor::TYPE_STATIC_A, nullptr);
    bool result = Decryptor::decrypt();
    
    std::cout << "[SimpleTestClass] Decryptor initialization result: " << (result ? "SUCCESS" : "FAILED") << std::endl;
    std::cout << "[SimpleTestClass] Is decrypted: " << (Decryptor::isDecrypted() ? "YES" : "NO") << std::endl;
}

// ===================== 普通方法实现 =====================
void SimpleTestClass::method1() {
    m_counter++;
    std::cout << "[SimpleTestClass] method1 called, counter: " << m_counter << std::endl;
}

void SimpleTestClass::method2() {
    m_counter += 2;
    std::cout << "[SimpleTestClass] method2 called, counter: " << m_counter << std::endl;
}

void SimpleTestClass::method3() {
    m_counter *= 2;
    std::cout << "[SimpleTestClass] method3 called, counter: " << m_counter << std::endl;
}

void SimpleTestClass::method4() {
    if (m_counter > 10) {
        m_counter -= 5;
    }
    std::cout << "[SimpleTestClass] method4 called, counter: " << m_counter << std::endl;
}

void SimpleTestClass::method5() {
    m_counter = (m_counter + 1) % 100;
    std::cout << "[SimpleTestClass] method5 called, counter: " << m_counter << std::endl;
}

// ===================== 加密方法实现 =====================
CRYPT_FUNC void SimpleTestClass::method6() {
    m_counter += 10;
    std::cout << "[SimpleTestClass] method6 (encrypted) called, counter: " << m_counter << std::endl;
    
    // 简单的计算逻辑
    int result = m_counter * 2 + 1;
    std::cout << "[SimpleTestClass] method6 calculation: " << m_counter << " * 2 + 1 = " << result << std::endl;
}

CRYPT_FUNC void SimpleTestClass::method7() {
    m_counter -= 3;
    if (m_counter < 0) m_counter = 0;
    std::cout << "[SimpleTestClass] method7 (encrypted) called, counter: " << m_counter << std::endl;
    
    // 简单的计算逻辑
    double square = m_counter * m_counter;
    std::cout << "[SimpleTestClass] method7 calculation: " << m_counter << "^2 = " << square << std::endl;
}

CRYPT_FUNC void SimpleTestClass::method8() {
    m_counter = m_counter * 3 % 50;
    std::cout << "[SimpleTestClass] method8 (encrypted) called, counter: " << m_counter << std::endl;
    
    // 简单的计算逻辑
    int sum = 0;
    for (int i = 0; i <= m_counter; i++) {
        sum += i;
    }
    std::cout << "[SimpleTestClass] method8 calculation: sum(0.." << m_counter << ") = " << sum << std::endl;
}

CRYPT_FUNC void SimpleTestClass::method9() {
    m_counter += 7;
    std::cout << "[SimpleTestClass] method9 (encrypted) called, counter: " << m_counter << std::endl;
    
    // 简单的计算逻辑
    bool isEven = (m_counter % 2 == 0);
    std::cout << "[SimpleTestClass] method9 calculation: " << m_counter << " is " << (isEven ? "even" : "odd") << std::endl;
}

CRYPT_FUNC void SimpleTestClass::method10() {
    m_counter = (m_counter + 20) % 30;
    std::cout << "[SimpleTestClass] method10 (encrypted) called, counter: " << m_counter << std::endl;
    
    // 简单的计算逻辑
    int factorial = 1;
    for (int i = 1; i <= std::min(m_counter, 5); i++) {
        factorial *= i;
    }
    std::cout << "[SimpleTestClass] method10 calculation: factorial(" << std::min(m_counter, 5) << ") = " << factorial << std::endl;
}
