#include <opencv2/imgproc.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/objdetect.hpp>

#include <iostream>
#include <fstream>
#include <iomanip>
#include <filesystem>
#include "lsh.hpp"
#include "cryption.hpp"

static void visualize(cv::Mat& input, cv::Mat& faces, std::string text, int thickness = 2){
    cv::Mat blur;
    // cv::GaussianBlur(input, blur, cv::Size(175, 175), 15, 15);
    cv::resize(input, blur, input.size()/50, 0, 0);
    cv::resize(blur, blur, input.size(), 0, 0, cv::INTER_LINEAR);
    for (int i = 0; i < faces.rows; i++){
        cv::Rect2i face = cv::Rect2i(int(faces.at<float>(i, 0)), int(faces.at<float>(i, 1)), int(faces.at<float>(i, 2)), int(faces.at<float>(i, 3)));
        // Draw bounding box
        if(i == 0)
            cv::rectangle(input, face, cv::Scalar(0, 0, 255), thickness);
        else
            cv::rectangle(input, face, cv::Scalar(0, 255, 0), thickness);
        // Draw landmarks
        cv::circle(input, cv::Point2i(int(faces.at<float>(i, 4)), int(faces.at<float>(i, 5))), 2, cv::Scalar(255, 0, 0), thickness);
        cv::circle(input, cv::Point2i(int(faces.at<float>(i, 6)), int(faces.at<float>(i, 7))), 2, cv::Scalar(0, 0, 255), thickness);
        cv::circle(input, cv::Point2i(int(faces.at<float>(i, 8)), int(faces.at<float>(i, 9))), 2, cv::Scalar(0, 255, 0), thickness);
        cv::circle(input, cv::Point2i(int(faces.at<float>(i, 10)), int(faces.at<float>(i, 11))), 2, cv::Scalar(255, 0, 255), thickness);
        cv::circle(input, cv::Point2i(int(faces.at<float>(i, 12)), int(faces.at<float>(i, 13))), 2, cv::Scalar(0, 255, 255), thickness);
        auto max = [](int x, int y) -> int {return x > y ? x : y;};
        auto min = [](int x, int y) -> int {return x > y ? y : x;};
        cv::Point leftup(max(0, int(faces.at<float>(i, 0) - faces.at<float>(i, 2) * 0.25)),
                         max(0, int(faces.at<float>(i, 1) - faces.at<float>(i, 3) * 0.25)) 
                        );
        cv::Point rightdown(min(input.cols, int(faces.at<float>(i, 0) + faces.at<float>(i, 2) * 1.25)),
                         min(input.rows, int(faces.at<float>(i, 1) + faces.at<float>(i, 3) * 1.25)) 
                        );

        cv::Rect2i vivid = cv::Rect2i(leftup, rightdown);
        
        input(vivid).copyTo(blur(vivid));
    }
    input = blur.clone();
    cv::displayOverlay("Video", text);
}

struct EncCallbackArgs{
    cv::Mat &input;
    cv::Mat &output;
    cv::Mat &mask;
    EncInfo &encinfo;
    secure_bytes &enckey;
    std::string &algorithm;
    std::string &keybits;
    std::string &mode;
    cv::Ptr<cv::FaceDetectorYN> &detector;
    int &fill;
    int &pensize;
};

static void enc_callback(EncCallbackArgs *args){
    std::string cipher_mode = args->algorithm + "-" + args->keybits + "-" + args->mode;
    strncpy(args->encinfo.cipher_mode, cipher_mode.c_str(), sizeof(args->encinfo.cipher_mode));
    if(encrypt_mat(args->input, args->output, args->enckey, args->encinfo, args->mask) < 0){
        cv::imshow("Image", args->output);
        cv::displayOverlay("Image", "failed to encrypt image");
        return;
    }
    cv::imshow("Image", args->output);
}

static void mouse_callback(int event, int x , int y , int flags, EncCallbackArgs *args){
    static cv::Point prevPt;
    static bool isBrushDown = false;
    static bool isShiftDown = false;
    cv::Point pt(x, y);

    if(flags & cv::EVENT_FLAG_SHIFTKEY || isShiftDown){
        if(event == cv::EVENT_LBUTTONDOWN){
            isShiftDown = true;
            prevPt = pt;
        }
        else if(event == cv::EVENT_LBUTTONUP){
            cv::rectangle(args->mask, prevPt, pt, cv::Scalar(args->fill), cv::FILLED);
            isShiftDown = false;
            enc_callback(args);
        }
        else if(isShiftDown){
            cv::Mat show = args->output.clone();
            cv::rectangle(show, prevPt, pt, cv::Scalar::all(0), 1);
            cv::imshow("Image", show);
        }
    }
    else{
        bool lbutton = (bool)(flags & cv::EVENT_FLAG_LBUTTON);
        bool buttonup = event == cv::EVENT_LBUTTONUP;
        bool buttondown = event == cv::EVENT_LBUTTONDOWN;
        if(lbutton && isBrushDown){
            cv::line(args->mask, prevPt, pt, cv::Scalar(args->fill), args->pensize, cv::LINE_8, 0);
            cv::line(args->output, prevPt, pt, cv::Scalar::all(0), args->pensize, cv::LINE_8, 0);
            cv::imshow("Image", args->output);
        }

        if(lbutton ^ (buttonup || buttondown)){
            prevPt = pt;
            isBrushDown = true;
        }else{
            isBrushDown = false;
            if(buttonup)
                enc_callback(args);
        }
    }
}

static void face_callback(EncCallbackArgs *args){
    cv::Mat faces;
    args->detector->setInputSize(args->input.size());
    args->detector->detect(args->input, faces);
    for(int i=0; i<faces.rows; i++){
        cv::rectangle(args->mask, cv::Rect2i(int(faces.at<float>(i, 0)), int(faces.at<float>(i, 1)), 
            int(faces.at<float>(i, 2)), int(faces.at<float>(i, 3))), cv::Scalar(args->fill), cv::FILLED);
    }
    enc_callback(args);
}

int main(int argc, char** argv){
    cv::CommandLineParser parser(argc, argv,
        "{help  h           |            | Print this message}"
        "{input i           |            | Path to the input file}"
        "{output o          |            | Path to the output file}"
        "{video v           | 0          | Path to the input video}"
        "{encrypt e         | false      | Encrypt input file}"
        "{decrypt d         | false      | Decrypt input file}"
        "{match m           | 16         | Match count of LSH}"
        "{kfile k           |            | Output key of Encryption/Input key of Decryption}"
        "{scale sc          | 1.0        | Scale factor used to cv::resize input video frames}"
        "{fd_model fd       | face_detection_yunet_2022mar.onnx| Path to the face detection model}"
        "{fr_model fr       | face_recognition_sface_2021dec.onnx | Path to the face recognition model}"
        "{score_threshold   | 0.9        | Filter out faces of score < score_threshold}"
        "{nms_threshold     | 0.3        | Suppress bounding boxes of iou >= nms_threshold}"
        "{top_k             | 5000       | Keep top_k bounding boxes before NMS}"
    );
    if (parser.has("help")){
        parser.printMessage();
        return 0;
    }

    cv::String fd_modelPath = parser.get<cv::String>("fd_model");
    cv::String fr_modelPath = parser.get<cv::String>("fr_model");

    float scoreThreshold = parser.get<float>("score_threshold");
    float nmsThreshold = parser.get<float>("nms_threshold");
    int topK = parser.get<int>("top_k");

    float scale = parser.get<float>("scale");

    bool enc_mode = parser.get<bool>("encrypt");
    bool dec_mode = enc_mode ? false : parser.get<bool>("decrypt");
    if(!dec_mode) enc_mode = true;

    std::string input_file = parser.get<std::string>("input");
    std::string output_file = parser.get<std::string>("output");

    //! [initialize_FaceDetectorYN]
    // Initialize FaceDetectorYN
    cv::Ptr<cv::FaceDetectorYN> detector = cv::FaceDetectorYN::create(fd_modelPath, "", cv::Size(320, 320), scoreThreshold, nmsThreshold, topK);
    //! [initialize_FaceDetectorYN]
    cv::Ptr<cv::FaceRecognizerSF> recognizer = cv::FaceRecognizerSF::create(fr_modelPath, "");

    cv::TickMeter tm;

    cv::VideoCapture capture;
    int frameWidth, frameHeight;

    secure_bytes inkey;

    if(parser.has("kfile") && dec_mode){
        std::string key_path = parser.get<std::string>("kfile");
        std::ifstream keyfile(key_path, std::ios::binary);
        if(!keyfile){
            std::cerr << "failed to open " << key_path << std::endl;
            return 1;
        }
        size_t filesize = std::filesystem::file_size(key_path);
        if(filesize < 16){
            std::cerr << "size of " << key_path << " is too short" << std::endl;
            return 1;
        }
        if(filesize > 512){
            std::cerr << "size of " << key_path << " is too big" << std::endl;
            return 1;
        }
        inkey.resize(filesize);
        keyfile.read((char*)inkey.data(), inkey.size());
        std::cout << "load key from " << key_path << std::endl;
    }


    // else if(parser.has("video")){
    if(parser.has("video")){
        std::string video = parser.get<std::string>("video");
        if (video.size() == 1 && isdigit(video[0]))
            capture.open(parser.get<int>("video"));
        else
            capture.open(video); 

        if (capture.isOpened()){
            frameWidth = int(capture.get(cv::CAP_PROP_FRAME_WIDTH) * scale);
            frameHeight = int(capture.get(cv::CAP_PROP_FRAME_HEIGHT) * scale);
            std::cout << "Video " << video
                << ": width=" << frameWidth
                << ", height=" << frameHeight
                << std::endl;
        }
        else{
            std::cout << "Could not initialize video capturing: " << video << "\n";
            return 1;
        }

        detector->setInputSize(cv::Size(frameWidth, frameHeight));
    }


    if(enc_mode){
        secure_bytes enckey;
        cv::Mat input_image, output_image, mask;
        input_image = cv::imread(input_file, cv::IMREAD_COLOR | cv::IMREAD_ANYDEPTH);
        if(input_image.empty()){
            std::cerr << "failed to open image file: " << input_file << std::endl;
            return 1;
        }
        mask = cv::Mat::zeros(input_image.size(), input_image.depth());
        std::cout << cv::typeToString(mask.type()) << std::endl;
        cv::namedWindow("Image");
        cv::imshow("Image", input_image);
        cv::moveWindow("Image", 100, 300);

        cv::namedWindow("Video");
        cv::moveWindow("Video", 110 + input_image.rows, 300);

        SimHash simhash(128, 32);
        cv::Mat detected;
        ulong match = parser.get<ulong>("match"), max_count = 0;

        int nFrame = 0;
        for (;;){
            // Get frame
            cv::Mat frame;
            if (!capture.read(frame)){
                std::cerr << "Can't grab frame! Stop\n";
                break;
            }

            cv::resize(frame, frame, cv::Size(frameWidth, frameHeight));

            // Inference
            cv::Mat faces;
            tm.start();

            detector->detect(frame, faces);

            if(faces.rows > 0){
                cv::Mat aligned, feature;
                cv::Mat lshash;
                recognizer->alignCrop(frame, faces.row(0), aligned);
                // cv::imshow("face", aligned);
                recognizer->feature(aligned, feature);
                ulong count = simhash.hash(feature, lshash);
                if(count >= match){
                    cv::displayOverlay("Image", cv::format("Facial key is generated ! Processed %d frames", nFrame), 5000);
                    digest(lshash.ptr<uchar>(0), lshash.cols * lshash.elemSize1(), enckey);
                    break;
                }
                max_count = count > max_count ? count : max_count;
            }

            tm.stop();
            cv::Mat result = frame.clone();
            // Draw results on the input image
            std::string text = cv::format("Frame : %d, FPS : %.2f, Progress %ld/%ld",
                nFrame, (float)tm.getFPS(), max_count, match);
            visualize(result, faces, text);

            // Visualize results
            cv::imshow("Video", result);

            ++nFrame;

            int key = cv::waitKey(1);
            if (key == 'q' || key == 'Q')
                break;
            if (key == 'r' || key == 'R'){
                max_count = 0;
                simhash.init_randvec();
            }
        }
        cv::destroyWindow("Video");
        if(enckey.empty()){
            std::cerr << "failed to generate facial key" << std::endl;
            return 1;
        }
        if(parser.has("kfile")){
            std::string outkey = parser.get<std::string>("kfile");
            std::ofstream outkeyfile(outkey, std::ios::binary);
            if(!outkeyfile){
                std::cerr << "failed to open " << outkey << std::endl;
            }
            else{
                outkeyfile.write((char *)enckey.data(), enckey.size());
            }
        }
        std::filesystem::path input_path(input_file);
        EncInfo encinfo;
        for(auto &a : enckey){
            std::cout << std::hex << (int)a;
        }
        std::cout << std::dec << std::endl;

        strncpy(encinfo.filename, input_path.filename().c_str(), sizeof(encinfo.filename));

        std::string algorithm;
        std::string keybits = "256";
        std::string mode = "CBC";
        bool save = false;
        int fill = 1;
        int pensize = 10;

        EncCallbackArgs callbackargs = {
            .input = input_image,
            .output = output_image,
            .mask = mask,
            .encinfo = encinfo,
            .enckey = enckey,
            .algorithm = algorithm,
            .keybits = keybits,
            .mode = mode,
            .detector = detector,
            .fill = fill,
            .pensize = pensize,
        };

        cv::createButton("AES", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->algorithm = "AES";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX, true);

        cv::createButton("CAMELLIA", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->algorithm = "CAMELLIA";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("128", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->keybits = "128";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX|cv::QT_NEW_BUTTONBAR, true);

        cv::createButton("192", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->keybits = "192";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("256", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->keybits = "256";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("CBC", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->mode = "CBC";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX|cv::QT_NEW_BUTTONBAR, true);

        cv::createButton("CFB", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->mode = "CFB";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("CTR", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->mode = "CTR";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("OFB", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->mode = "OFB";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("ECB", [](int state, void *userdata) -> void {
                if(state){
                    ((EncCallbackArgs *)userdata)->mode = "ECB";
                    enc_callback((EncCallbackArgs *)userdata);
                }
            }, &callbackargs, cv::QT_RADIOBOX);

        cv::createButton("Fill", [](int state, void *userdata) -> void {
                if(state){
                    *(int*)userdata = 1;
                }
            }, &fill, cv::QT_RADIOBOX|cv::QT_NEW_BUTTONBAR, true);

        cv::createButton("Clear", [](int state, void *userdata) -> void {
                if(state){
                    *(int*)userdata = 0;
                }
            }, &fill, cv::QT_RADIOBOX);

        cv::createButton("Faces", [](int state, void *userdata) -> void {
                face_callback((EncCallbackArgs *)userdata);
            }, &callbackargs, cv::QT_PUSH_BUTTON|cv::QT_NEW_BUTTONBAR);

        cv::createButton("All", [](int state, void *userdata) -> void {
                ((EncCallbackArgs *)userdata)->mask.setTo(cv::Scalar(((EncCallbackArgs *)userdata)->fill));
                enc_callback((EncCallbackArgs *)userdata);
            }, &callbackargs, cv::QT_PUSH_BUTTON|cv::QT_NEW_BUTTONBAR);

        cv::setMouseCallback("Image", (cv::MouseCallback)mouse_callback, &callbackargs);

        cv::createTrackbar("Pen size", "Image", &pensize, mask.cols / 10);
        cv::setTrackbarMin("Pen size", "Image", 1);

        cv::createButton("Save", [](int state, void *userdata) -> void {
                *(bool *)userdata = true;
            }, &save, cv::QT_PUSH_BUTTON|cv::QT_NEW_BUTTONBAR);
        
        while(!save){
            int key = cv::waitKey(500);
            if(key == 'q' || key == 'Q'){
                break;
            }
        }

        if(save){
            if(!save_as_png(output_file, output_image, mask, encinfo, simhash.get_randvec())){
                std::cerr << "failed to save image" << std::endl;
                return 1;
            }
            std::cout << "save as " << output_file << std::endl;
        }
        std::cout << simhash.get_randvec().size() << std::endl;
        std::cout << encinfo.filename << " " << encinfo.cipher_mode << " " 
            << encinfo.size << " " << encinfo.cipher_size << std::endl;
    }
    else if(dec_mode){
        cv::Mat input_image, output_image, mask;
        EncInfo encinfo;
        cv::Mat randvec;
        secure_bytes deckey;
        if(!load_png(input_file, input_image, mask, encinfo, randvec)){
            std::cerr << "failed to load png file" << std::endl;
        }
        std::cout << encinfo.filename << " " << encinfo.cipher_mode << " " 
            << encinfo.size << " " << encinfo.cipher_size << std::endl;
        std::cout << randvec.size() << std::endl;
        cv::namedWindow("Image");
        cv::imshow("Image", input_image);
        cv::moveWindow("Image", 300, 300);

        // if(!inkey.empty()){
        //     if(decrypt_mat(input_image, output_image, inkey, encinfo, mask) >= 0){
        //         std::cout << "decrypted" << std::endl;
        //         deckey = inkey;
        //     }
        //     else{
        //         std::cerr << "failed to decrypt with key file" << std::endl;
        //     }
        // }
        // else{
        {
            cv::namedWindow("Video");
            cv::moveWindow("Video", 310 + input_image.rows, 300);
            SimHash simhash(randvec);

            int nFrame = 0;
            while(true){
                // Get frame
                cv::Mat frame;
                if (!capture.read(frame)){
                    std::cerr << "Can't grab frame! Stop\n";
                    break;
                }

                cv::resize(frame, frame, cv::Size(frameWidth, frameHeight));

                // Inference
                cv::Mat faces;
                tm.start();

                detector->detect(frame, faces);

                if(faces.rows > 0){
                    cv::Mat aligned, feature;
                    cv::Mat lshash;
                    secure_bytes key;
                    recognizer->alignCrop(frame, faces.row(0), aligned);
                    // cv::imshow("face", aligned);
                    recognizer->feature(aligned, feature);
                    simhash.hash(feature, lshash);
                    digest(lshash.ptr<uchar>(0), lshash.cols * lshash.elemSize1(), key);
                    // for(auto &a : deckey){
                    //     std::cout << std::hex << (int)a;
                    // }
                    // std::cout << std::dec << std::endl;
                    // std::cout << lshash << std::endl;
                    if(decrypt_mat(input_image, output_image, key, encinfo, mask) >= 0){
                        cv::displayOverlay("Image", cv::format("%s is successfully decrypted ! Processed %d frames", encinfo.filename, nFrame), 5000);
                        deckey = key;
                        break;
                    }
                    if(nFrame > 91 && !inkey.empty()){
                        if(decrypt_mat(input_image, output_image, inkey, encinfo, mask) >= 0){
                            cv::displayOverlay("Image", cv::format("%s is successfully decrypted ! Processed %d frames", encinfo.filename, nFrame), 5000);
                            deckey = inkey;
                        }
                        break;
                    }
                }

                tm.stop();
                cv::Mat result = frame.clone();
                // Draw results on the input image
                std::string text = cv::format("Frame : %d, FPS : %.2f", nFrame, (float)tm.getFPS());
                visualize(result, faces, text);

                // Visualize results
                cv::imshow("Video", result);

                ++nFrame;

                int key = cv::waitKey(1);
                if (key == 'q' || key == 'Q')
                    break;
            }
            cv::destroyWindow("Video");
            std::cout << "Processed " << nFrame << " frames" << std::endl;
        }
        if(deckey.empty()){
            std::cerr << "failed to decrypt" << std::endl;
            cv::waitKey(0);
            return 1;
        }
        cv::imshow("Image", output_image);
        cv::waitKey(0);
        cv::imwrite(encinfo.filename, output_image);
    }

    std::cout << "Done." << std::endl;
    return 0;
}
