#include <opencv2/core.hpp>
#include <bitset>
#include <map>
#include <string>

class SimHash {
private:
    cv::Mat randvec;
    std::map <unsigned long, unsigned long> hashmap;

public:
    SimHash(unsigned int dim, unsigned int hashbit = 32, int type = CV_32FC1);
    SimHash(const cv::Mat &randvec);
    unsigned long hash(cv::Mat &feature, cv::Mat &lshash);
    void init_randvec();
    cv::Mat& get_randvec();
};
