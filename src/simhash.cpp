#include "lsh.hpp"

SimHash::SimHash(unsigned int dim, unsigned int hashbit, int type){
    randvec.create(dim, hashbit, type);
    cv::randn(randvec, 0.0, 1000.0);
}


SimHash::SimHash(const cv::Mat &randvec){
    this->randvec = randvec.clone();
}

unsigned long SimHash::hash(cv::Mat &feature, cv::Mat &lshash) {
    cv::Mat product = feature * randvec;
    lshash.create(product.size(), CV_8UC1);
    unsigned long hashkey = 0;
    auto iter_prod = product.begin<float>();
    auto iter_hash = lshash.begin<uchar>();
    size_t pos = 0;
    for(; iter_prod != product.end<float>(); iter_prod++, iter_hash++, pos++){
        pos = pos < sizeof(unsigned int) * 8 ? pos : 0;
        *iter_hash = *iter_prod > 0.0 ? 1 : 0;
        hashkey ^= *iter_hash << pos;
    }
    return ++hashmap[hashkey];
}

void SimHash::init_randvec(){
    cv::randn(randvec, 0.0, 1000.0);
    hashmap.clear();
}

cv::Mat& SimHash::get_randvec(){
    return randvec;
}
