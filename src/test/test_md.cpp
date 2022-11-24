#include "cryption.hpp"
#include <cstdio>
#include <cstring>

int main(int argc, char **argv){
    if(argc < 2){
        return 1;
    }
    unsigned char md[64];
    int len;
    if(argc > 2) len = digest(argv[1], strlen(argv[1]), md, argv[2]);
    else len = digest(argv[1], strlen(argv[1]), md);
    printf("%d\n", len);
    for(int i=0; i<len; i++){
        printf("%02x", md[i]);
    }
    puts("");
    secure_bytes bytes;
    if(argc > 2) len = digest(argv[1], strlen(argv[1]), bytes, argv[2]);
    else len = digest(argv[1], strlen(argv[1]), bytes);
    printf("%d\n", len);
    for(int i=0; i<bytes.size(); i++){
        printf("%02x", bytes[i]);
    }
    puts("");
}
