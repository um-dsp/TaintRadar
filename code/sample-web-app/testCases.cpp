#include <iostream>
#include <string>

// Literals
int san0 = 0;
float san1 = 2.3;
std::string san2 = "Hello World";

// Assignment propagation
std::string unsan0 = argv[1]; // Assuming command line argument
std::string san3 = filter_input(unsan0);
std::string san4 = san3 + " .";
san4 = san4 + san3;
std::string unsan1 = unsan0 + san4;

// Type casting
int san5 = std::stoi(unsan0);
std::string san6 = san3;
std::string unsan2 = std::to_string(std::stoi(unsan0));
san6 = unsan1;
unsan2 = unsan1;
double san7 = std::stod(san6) + 1.1;

// Functions (by value)
std::string customSan(std::string p1) {
    std::string unsan3 = p1;
    std::string san8 = filter_input(unsan3);
    return san8;
}
std::string san9 = customSan(unsan1);

std::string customUnsan(std::string p1) {
    std::string unsan5 = unsan0 + p1;
    return unsan5;
}
std::string unsan6 = customUnsan(san6);

std::string getInput() {
    std::string input;
    std::cin >> input;
    return input;
}
std::string unsan7 = getInput();

std::string addTwo(float p1, std::string p2) {
    std::string tmp = std::to_string(p1) + p2;
    return tmp;
}
std::string san10 = addTwo(san1, san2);
std::string unsan8 = addTwo(san1, unsan2);

std::string customSan2nd(std::string p1, std::string p2) {
    return p1 + filter_input(p2);
}
std::string san11 = customSan2nd(san3, unsan2);
std::string unsan9 = customSan2nd(unsan1, unsan2);
std::string unsan10 = customSan2nd(unsan1, san2);

// Functions (by reference)
void customSanRef(std::string& p1) {
    p1 = filter_input(p1);
}
std::string san12 = unsan1;
customSanRef(san12);

void customAddRef(std::string& p1, int p2) {
    p1 = p1 + std::to_string(p2);
}
std::string san13 = san12;
customAddRef(san13, san0);
std::string unsan11 = san13;
customAddRef(unsan11, unsan1);

std::string san1stArg(std::string& p1, std::string& p2) {
    p1 = filter_input(p1);
    return p1 + p2;
}
std::string san14 = unsan10;
std::string unsan12 = unsan11;
std::string unsan13 = san1stArg(san14, unsan12);

void customUnsanRef(std::string& p1) {
    p1 = p1 + unsan0;
}
std::string unsan14 = san14;
customUnsanRef(unsan14);