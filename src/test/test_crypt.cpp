#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <opencv2/core.hpp>
#include <opencv2/opencv.hpp>
#include <opencv2/highgui.hpp>
#include <cstring>
#include <iostream>
#include <string>
#include "cryption.hpp"

int main(){
    cv::Mat input, encrypted, decrypted;
    input.create(cv::Size(6, 7), CV_16UC3);
    cv::randu(input, cv::Scalar::all(0), cv::Scalar::all(65555));

    std::cout << input << std::endl;
    cv::Mat mask = cv::Mat::zeros(input.size(), CV_16UC1);
    cv::rectangle(mask, cv::Point(1,2), cv::Point(4,5), cv::Scalar(1), cv::FILLED);
    std::cout << mask << std::endl;

    // for(auto iter = input.begin(); iter != input.end(); iter++){
    //     std::cout << (int)*iter << " ";
    // }

    EncInfo encinfo;
    strcpy(encinfo.cipher_mode, "AES-256-CBC");
    memcpy(encinfo.iv, "0123456789abcdef", 16);
    secure_bytes key;
    key.resize(32);
    memcpy(key.data(), "0123456789abcdef0123456789abcdef", 32);
    if(encrypt_mat(input, encrypted, key, encinfo, mask) < 0){
        std::cerr << "failed to encrypt";
        return 1;
    }
    std::cout << encrypted << std::endl;
    std::cout << (input != encrypted)/255 << std::endl;
    if(decrypt_mat(encrypted, decrypted, key, encinfo, mask) < 0){
        std::cerr << "failed to decrypt";
        return 1;
    }
    std::cout << decrypted << std::endl;
    std::cout << (input != decrypted) << std::endl;
    return 0;
}
