#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <opencv2/core.hpp>
#include <opencv2/highgui.hpp>
#include <png.h>
#include <string>
#include <iostream>
#include <filesystem>
#include <memory>
#include <cstdio>
#include <cassert>
#include "cryption.hpp"

#define DEBUG 1

bool save_as_png(const std::string &save_name, const cv::Mat &image, const cv::Mat &mask, const EncInfo &encinfo, const cv::Mat &randvec) noexcept{
    std::filesystem::path save_path(save_name);
    if(save_path.extension() != ".png"){
        #if DEBUG
        std::cerr << "output format shold be PNG" << std::endl;
        #endif
        return false;
    }
    cv::Mat save_image, temp;
    std::vector<cv::Mat> split;
    cv::split(image, split);
    split.push_back(mask == 0);
    cv::merge(split, save_image);
    cv::imwrite(save_name, save_image);
    FILE *ifp;
    ifp = fopen(save_name.c_str(), "rb");
    if(!ifp){
        #if DEBUG
        std::cerr << "failed to read image" << std::endl;
        #endif
        return false;
    }
    const int signum = 8;
    unsigned char header[signum];
    fread(header, 1, signum, ifp);
    if(png_sig_cmp(header, 0, signum)){
        #if DEBUG
        std::cerr << "not png" << std::endl;
        #endif
        return 1;
    }
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr){
        #if DEBUG
        std::cerr << "failed to read png" << std::endl;
        #endif
        return false;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr){
        png_destroy_read_struct(&png_ptr, (png_infopp)NULL, (png_infopp)NULL);
        #if DEBUG
        std::cerr << "failed to read info" << std::endl;
        #endif
        return false;
    }

    png_init_io(png_ptr, ifp);
    png_set_sig_bytes(png_ptr, signum);
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

    cv::Mat save_vec = randvec.clone();
    size_t randvec_size = save_vec.total() * save_vec.elemSize();
    std::unique_ptr<EncInfo> save_encinfo((EncInfo*)malloc(sizeof(EncInfo) + randvec_size));
    memcpy(save_encinfo.get(), &encinfo, sizeof(EncInfo));
    memcpy(&(save_encinfo->randvec), randvec.ptr<float>(0), randvec_size);
    png_unknown_chunk chunks[] = {
        {
            .name = "ciph",
            .data = (png_byte*)save_encinfo.get(),
            .size = sizeof(EncInfo) + randvec_size,
            .location = PNG_AFTER_IDAT
        },
    };
    png_set_unknown_chunks(png_ptr, info_ptr, chunks, sizeof(chunks)/sizeof(png_unknown_chunk));

    FILE *ofp = fopen(save_name.c_str(), "wb");
    if(!ofp){
        #if DEBUG
        std::cerr << "failed to open output file" << std::endl;
        #endif
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return false;
    }
    png_structp wpng_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!wpng_ptr){
        #if DEBUG
        std::cerr << "failed to write png" << std::endl;
        #endif
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return false;
    }
    png_init_io(wpng_ptr, ofp);
    png_write_png(wpng_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    png_destroy_write_struct(&wpng_ptr, NULL);
    fclose(ifp);
    fclose(ofp);
    return true;
}

bool load_png(const std::string &input_name, cv::Mat &output, cv::Mat &mask, EncInfo &encinfo, cv::Mat &randvec) noexcept{
    FILE *ifp;
    ifp = fopen(input_name.c_str(), "rb");
    if(!ifp){
        #if DEBUG
        std::cerr << "failed to read image " << input_name << std::endl;
        #endif
        return false;
    }
    const int signum = 8;
    unsigned char header[signum];
    fread(header, 1, signum, ifp);
    if(png_sig_cmp(header, 0, signum)){
        #if DEBUG
        std::cerr << "not png" << std::endl;
        #endif
        return false;
    }
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr){
        #if DEBUG
        std::cerr << "failed to read png" << std::endl;
        #endif
        return false;
    }
    char name[5];
    strcpy(name, "ciph");
    png_set_keep_unknown_chunks(png_ptr, PNG_HANDLE_CHUNK_IF_SAFE, (png_bytep)name, 1);

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr){
        png_destroy_read_struct(&png_ptr, (png_infopp)NULL, (png_infopp)NULL);
        #if DEBUG
        std::cerr << "failed to read info" << std::endl;
        #endif
        return false;
    }

    png_init_io(png_ptr, ifp);
    png_set_sig_bytes(png_ptr, signum);
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);
    png_unknown_chunkp chunk_ptr = NULL;
    if(png_get_unknown_chunks(png_ptr, info_ptr, &chunk_ptr) != 1){
        #if DEBUG
        std::cerr << "failed to get chunk info" << std::endl;
        #endif
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return false;
    }

    memcpy(&encinfo, chunk_ptr->data, sizeof(EncInfo));

    randvec = cv::Mat(128, (chunk_ptr->size-sizeof(EncInfo))/128/sizeof(float), CV_32FC1, ((EncInfo*)(chunk_ptr->data))->randvec);
    randvec = randvec.clone();
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(ifp);
    cv::Mat input;
    std::vector<cv::Mat> split;
    input = cv::imread(input_name, cv::IMREAD_UNCHANGED | cv::IMREAD_ANYDEPTH);
    cv::split(input, split);
    mask = ~split.back().clone();
    split.pop_back();
    cv::merge(split, output);
    return true;
}

int encrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, EncInfo &encinfo) noexcept{
    cv::Mat mask = cv::Mat::ones(input.size(), CV_8UC1);
    return encrypt_mat(input, output, key, encinfo, mask);
}

int encrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, EncInfo &encinfo, 
                const cv::Mat &mask) noexcept{
    if(mask.type() != CV_8UC1){
        cv::Mat _mask;
        mask.convertTo(_mask, CV_8UC1);
        return encrypt_mat(input, output, key, encinfo, _mask);
    }
    EVP_CIPHER_ptr cipher(EVP_CIPHER_fetch(NULL, encinfo.cipher_mode, NULL), EVP_CIPHER_free);
    if(cipher.get() == NULL){
        #if DEBUG
        std::cerr << "no algorithm: " << encinfo.cipher_mode << std::endl;
        #endif
        return -1;
    }
    int ivlen = EVP_CIPHER_get_iv_length(cipher.get());
    int blksize = EVP_CIPHER_get_block_size(cipher.get());
    int keysize = EVP_CIPHER_get_key_length(cipher.get());
    if((int)key.size() < keysize){
        #if DEBUG
        std::cerr << "input key length ("<< key.size() << ") is shorter than " << keysize << std::endl;
        #endif
        return -1;
    }
    if(ivlen > (int)sizeof(encinfo.iv)){
        #if DEBUG
        std::cerr << "length of iv is too big " << ivlen << " > " << sizeof(encinfo.iv) << std::endl;
        #endif
        return -1;
    }
    RAND_bytes(encinfo.iv, ivlen);
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if(ctx.get() == NULL){
        #if DEBUG
        std::cerr << "failed to create contex" << std::endl;
        #endif
        return -1;
    }
    if(EVP_EncryptInit_ex(ctx.get(), cipher.get(), NULL, key.data(), encinfo.iv) != 1){
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);

    cv::Size input_sz = input.size();
    encinfo.size = input_sz;
    size_t datasize = input.total() * input.elemSize();

    output = input.clone();

    std::unique_ptr<unsigned char[]> srcbuf(new unsigned char[datasize]);
    std::unique_ptr<unsigned char[]> dstbuf(new unsigned char[datasize]);

    int encsize = 0;
    int elem = input.elemSize();
    for(int i = 0; i < input.rows; i++){
        const uchar *input_ptr = input.ptr<uchar>(i);
        for(int j = 0; j < input.cols; j++){
            if(mask.at<uchar>(i,j) > 0){
                memcpy(srcbuf.get() + encsize, input_ptr, elem);
                encsize += elem;
            }
            input_ptr += elem;
        }
    }
    encsize = encsize / (elem * blksize) * (elem * blksize);

    int outlen, totallen = 0;
    if(!EVP_EncryptUpdate(ctx.get(), dstbuf.get(), &outlen, srcbuf.get(), encsize)){
        return -1;
    }
    totallen += outlen;
    if(!EVP_EncryptFinal_ex(ctx.get(), dstbuf.get() + outlen, &outlen)){
        return -1;
    }

    totallen += outlen;
    assert(totallen == (int)encsize);

    encsize = 0;
    for(int i = 0; i < output.rows && encsize < totallen; i++){
        uchar *output_ptr = output.ptr<uchar>(i);
        for(int j = 0; j < output.cols; j++){
            if(mask.at<uchar>(i,j) > 0){
                memcpy(output_ptr, dstbuf.get() + encsize, elem);
                encsize += elem;
                if(encsize == totallen) break;
            }
            output_ptr += elem;
        }
    }
    assert(totallen == (int)encsize);

    encinfo.cipher_size = totallen;
    if(digest(key.data(), keysize, encinfo.keydgst) < 0){
        #if DEBUG
        std::cerr << "failed to create key digest" << std::endl;
        #endif
        return -1;
    }
    return totallen;
}

int decrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key, const EncInfo &encinfo) noexcept{
    cv::Mat mask = cv::Mat::ones(input.size(), CV_8UC1);
    return decrypt_mat(input, output, key, encinfo, mask);
}

int decrypt_mat(const cv::Mat &input, cv::Mat &output, const secure_bytes &key,
                const EncInfo &encinfo, const cv::Mat &mask) noexcept{
    if(mask.type() != CV_8UC1){
        cv::Mat _mask;
        mask.convertTo(_mask, CV_8UC1);
        return decrypt_mat(input, output, key, encinfo, _mask);
    }
    EVP_CIPHER_ptr cipher(EVP_CIPHER_fetch(NULL, encinfo.cipher_mode, NULL), EVP_CIPHER_free);
    if(cipher.get() == NULL){
        #if DEBUG
        std::cerr << "no algorithm: " << encinfo.cipher_mode << std::endl;
        #endif
        return -1;
    }

    secure_bytes keydgst;
    int keysize = EVP_CIPHER_get_key_length(cipher.get());
    int blksize = EVP_CIPHER_get_block_size(cipher.get());
    int dgstsize;
    if((dgstsize = digest(key.data(), keysize, keydgst)) < 0){
        #if DEBUG
        std::cerr << "failed to create key digest" << std::endl;
        #endif
        return -1;
    }
    if(memcmp(keydgst.data(), encinfo.keydgst, dgstsize) != 0){
        return -1;
    }

    if((int)key.size() < keysize){
        #if DEBUG
        std::cerr << "input key length ("<< key.size() << ") is shorter than " << keysize << std::endl;
        #endif
        return -1;
    }

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if(ctx.get() == NULL){
        #if DEBUG
        std::cerr << "failed to create contex" << std::endl;
        #endif
        return -1;
    }

    if(EVP_DecryptInit_ex(ctx.get(), cipher.get(), NULL, key.data(), encinfo.iv) != 1){
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  
    size_t datasize = input.total() * input.elemSize();
    output = input.clone();

    std::unique_ptr<unsigned char[]> srcbuf(new unsigned char[datasize]);
    std::unique_ptr<unsigned char[]> dstbuf(new unsigned char[datasize]);

    int encsize = 0;
    int elem = input.elemSize();

    for(int i = 0; i < input.rows; i++){
        const uchar *input_ptr = input.ptr<uchar>(i);
        for(int j = 0; j < input.cols; j++){
            if(mask.at<uchar>(i,j) > 0){
                memcpy(srcbuf.get() + encsize, input_ptr, elem);
                encsize += elem;
            }
            input_ptr += elem;
        }
    }
    encsize = encsize / (elem * blksize) * (elem * blksize);

    int outlen, totallen = 0;
    if(!EVP_DecryptUpdate(ctx.get(), dstbuf.get(), &outlen, srcbuf.get(), encsize)){
        return -1;
    }
    totallen += outlen;
    if(!EVP_DecryptFinal_ex(ctx.get(), dstbuf.get() + outlen, &outlen)){
        #if DEBUG
        std::cerr << "failed to decrypt" << std::endl;
        #endif
        return -1;
    }
    totallen += outlen;
    assert(totallen == (int)encsize);

    encsize = 0;
    for(int i = 0; i < output.rows && encsize < totallen; i++){
        uchar *output_ptr = output.ptr<uchar>(i);
        for(int j = 0; j < output.cols; j++){
            if(mask.at<uchar>(i,j) > 0){
                memcpy(output_ptr, dstbuf.get() + encsize, elem);
                encsize += elem;
                if(encsize == totallen) break;
            }
            output_ptr += elem;
        }
    }
    assert(totallen == (int)encsize);

    return totallen;
}

int digest(const void *data, size_t count, secure_bytes &dgst, const char *md_name) noexcept{
    EVP_MD_ptr md(EVP_MD_fetch(NULL, md_name, NULL), EVP_MD_free);
    if(md.get() == NULL){
        #if DEBUG
        std::cerr << "no algorithm: " << md_name << std::endl;
        #endif
        return -1;
    }
    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(ctx.get() == NULL){
        #if DEBUG
        std::cerr << "failed to create context" << std::endl;
        #endif
        return -1;
    }
    int dgstsize = EVP_MD_get_size(md.get());
    dgst.resize(dgstsize);
    if(EVP_DigestInit_ex2(ctx.get(), md.get(), NULL) != 1){
        return -1;
    }
    if(!EVP_DigestUpdate(ctx.get(), data, count)){
        return -1;
    }
    unsigned int md_len;
    if(!EVP_DigestFinal_ex(ctx.get(), dgst.data(), &md_len)){
        return -1;
    }
    assert(dgstsize == (int)md_len);
    return md_len;
}

int digest(const void *data, size_t count, unsigned char *dgst, const char *md_name) noexcept{
    secure_bytes s_dgst;
    if(digest(data, count, s_dgst, md_name) < 0){
        return -1;
    }
    s_dgst.copy(dgst, s_dgst.size());
    return s_dgst.size();
}

// below are no longer used

int encrypt_mat(cv::Mat &input, cv::Mat &output, const unsigned char *key, 
                const unsigned char *iv, const char *cipher_mode) noexcept{
    EVP_CIPHER_ptr cipher(EVP_CIPHER_fetch(NULL, cipher_mode, NULL), EVP_CIPHER_free);
    if(cipher.get() == NULL){
        return -1;
    }
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if(ctx.get() == NULL){
        return -1;
    }
    if(EVP_EncryptInit_ex(ctx.get(), cipher.get(), NULL, key, iv) != 1){
        return -1;
    }

    cv::Size input_sz = input.size();
    cv::Size output_sz = input_sz;
    std::vector<cv::Mat> planes, crypted(input.channels());
    cv::split(input, planes);

    // resize for padding
    output_sz.width = (input_sz.width * input.elemSize1() + 16) / input.elemSize1();
    int enc_len = 0;

    for(auto in_iter = planes.begin(), out_iter = crypted.begin();
        in_iter != planes.end() && out_iter != crypted.end();
        in_iter++, out_iter++){
        out_iter->create(output_sz, in_iter->type());
        for(int i=0; i<input_sz.height; i++){
            int totallen = 0, outlen;
            const uchar *src = in_iter->ptr(i);
            uchar *dst = out_iter->ptr(i);
            if(!EVP_EncryptUpdate(ctx.get(), dst, &outlen, src, input_sz.width * input.elemSize1())){
                return -1;
            }
            totallen += outlen;
            if(!EVP_EncryptFinal_ex(ctx.get(), dst + outlen, &outlen)){
                return -1;
            }
            totallen += outlen;
            if(enc_len == 0) enc_len = totallen;
            assert(totallen == enc_len);
        }
    }
    cv::merge(crypted, output);
    assert(enc_len % input.elemSize1() == 0);
    output = output(cv::Rect(0,0,enc_len/input.elemSize1(),output_sz.height)).clone();

    return 0;
}

int decrypt_mat(cv::Mat &input, cv::Mat &output, const unsigned char *key,
                const unsigned char *iv, const char *cipher_mode) noexcept{
    EVP_CIPHER_ptr cipher(EVP_CIPHER_fetch(NULL, cipher_mode, NULL), EVP_CIPHER_free);
    if(cipher.get() == NULL){
        return -1;
    }
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if(ctx.get() == NULL){
        return -1;
    }
    if(EVP_DecryptInit_ex(ctx.get(), cipher.get(), NULL, key, iv) != 1){
        return -1;
    }

    int outlen;
    cv::Size input_sz = input.size();
    cv::Size output_sz = input_sz;
    std::vector<cv::Mat> encrypted, decrypted(input.channels());
    cv::split(input, encrypted);
    int dec_len = 0;

    for(auto in_iter = encrypted.begin(), out_iter = decrypted.begin();
        in_iter != encrypted.end() && out_iter != decrypted.end();
        in_iter++, out_iter++){
        out_iter->create(output_sz, in_iter->type());
        for(int i=0; i<input_sz.height; i++){
            int totallen = 0;
            const uchar *src = in_iter->ptr(i);
            uchar *dst = out_iter->ptr(i);
            if(!EVP_DecryptUpdate(ctx.get(), dst, &outlen, src, input_sz.width * input.elemSize1())){
                return -1;
            }
            totallen += outlen;
            if(!EVP_DecryptFinal_ex(ctx.get(), dst + outlen, &outlen)){
                return -1;
            }
            totallen += outlen;
            if(dec_len == 0) dec_len = totallen;
            assert(totallen == dec_len);
        }
    }
    cv::merge(decrypted, output);
    assert(dec_len % input.elemSize1() == 0);
    output = output(cv::Rect(0,0,dec_len/input.elemSize1(),output_sz.height)).clone();

    return 0;
}
