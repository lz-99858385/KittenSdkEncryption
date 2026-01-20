#include "test_class.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>

static std::atomic<bool> g_running(true);

void sigint_handler(int) {
    g_running.store(false);
}

int main() {
    std::signal(SIGINT, sigint_handler);

    std::cout << "run_test starting. Press Ctrl+C to stop.\n";

    SimpleTestClass tester;
    tester.init();

    while (g_running.load()) {
        tester.method1();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        tester.method2();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        tester.method3();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        tester.method4();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        tester.method5();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        tester.method6();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        tester.method7();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        tester.method8();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    }

    std::cout << "run_test exiting.\n";
    return 0;
}