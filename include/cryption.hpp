#include <openssl/evp.h>
#include <opencv2/core.hpp>
#include <sys/types.h>
#include <memory>
#include <string>

using EVP_CIPHER_ptr = std::unique_ptr<EVP_CIPHER, decltype(&::EVP_CIPHER_free)>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_ptr = std::unique_ptr<EVP_MD, decltype(&::EVP_MD_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;

using secure_bytes = std::basic_string<uchar>;

struct EncInfo{
    char filename[32];
    char cipher_mode[32];
    cv::Size size;
    unsigned int cipher_size;
    unsigned char iv[32];
    unsigned char keydgst[64];
    float randvec[];
};

int encrypt_mat(cv::Mat &input, cv::Mat &output, const unsigned char *key,
                const unsigned char *iv,const char *cipher_mode = "AES-256-CBC") noexcept;

int decrypt_mat(cv::Mat &input, cv::Mat &output, const unsigned char *key,
                const unsigned char *iv, const char *cipher_mode = "AES-256-CBC") noexcept;

bool save_as_png(const std::string &save_name, const cv::Mat &image, const cv::Mat &mask,
                 const EncInfo &encinfo, const cv::Mat &randvec) noexcept;
bool load_png(const std::string &input_name, cv::Mat &output, cv::Mat &mask, 
              EncInfo &encinfo, cv::Mat &randvec) noexcept;

int digest(const void *data, size_t count, secure_bytes &dgst, const char *md_name = "SHA256") noexcept;
int digest(const void *data, size_t count, unsigned char *dgst, const char *md_name = "SHA256") noexcept;

int encrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, EncInfo &encinfo) noexcept;
int encrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, EncInfo &encinfo, const cv::Mat &mask) noexcept;
// int encrypt_mat(const cv::Mat &input, cv::Mat &output, const unsigned char *key, EncInfo &encinfo) noexcept;
int decrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, const EncInfo &encinfo) noexcept;
int decrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, const EncInfo &encinfo, const cv::Mat &mask) noexcept;
// int decrypt_mat(const cv::Mat &input, cv::Mat &output, const unsigned char *key, const EncInfo &encinfo) noexcept;
