#include <vector>
#include <functional>
int SHA1(char* msg, long long msg_len, unsigned char digest[])
{
    const long long BYTE_SIZE = 8;
    const unsigned char ADDITIONAL_1ST = 0x80;
    const long long add_total = 64;
    const long long  add_1st_len = 56;
    const long long  add_2nd_len = 8;
    long long remain = msg_len % add_1st_len;
    long long msg_new_len = msg_len + add_total - remain;
    long long end_1st = msg_new_len - add_2nd_len;
    std::vector<unsigned char> msg_new(msg_new_len);
    for (int i = 0; i < msg_len; ++i) {
        msg_new[i] = msg[i];
    }
    msg_new[msg_len] = ADDITIONAL_1ST;
    const size_t size_of_long_long = sizeof(long long);
    union SeparateMsgLen {
        long long len;
        char byte[size_of_long_long];
    };
    SeparateMsgLen separate_msg_len;
    separate_msg_len.len = msg_len * BYTE_SIZE;
    for (int i = 0; i < size_of_long_long;++i) {
        long long iter = end_1st + i;
        msg_new[iter] = separate_msg_len.byte[size_of_long_long - i - 1];
    }
    typedef unsigned int SHA132BIT;
    const SHA132BIT Kt[4] = { 0x5A827999 ,0x6ED9EBA1  ,0x8F1BBCDC,0xCA62C1D6 };
    std::function<SHA132BIT(SHA132BIT B,
        SHA132BIT C,
        SHA132BIT D)> ft[4] =
    {
        [](SHA132BIT B,SHA132BIT C,SHA132BIT D)->SHA132BIT {return (B&C) | ((~B)&D); },
        [](SHA132BIT B,SHA132BIT C,SHA132BIT D)->SHA132BIT {return B ^ C ^ D; },
        [](SHA132BIT B,SHA132BIT C,SHA132BIT D)->SHA132BIT {return (B&C) | (B&D) | (C&D); },
        [](SHA132BIT B,SHA132BIT C,SHA132BIT D)->SHA132BIT {return B ^ C ^ D; },
    };
    SHA132BIT H[5] = { 0x67452301,0xEFCDAB89, 0x98BADCFE, 0x10325476,0xC3D2E1F0};
    SHA132BIT W[80];
    union SeparateWord
    {
        SHA132BIT word;
        unsigned char bytes[4];
    };
    auto LoadBytesToWord = [](auto bytes_ptr) {
        SeparateWord word;
        for (int i = 3; i >= 0; --i){
            word.bytes[i] = *bytes_ptr;
            bytes_ptr++;
        }
        return word.word;
    };
    for (auto msg_iter = std::begin(msg_new);
    msg_iter < std::end(msg_new);) {
        for (int i = 0; i < 16; ++i) {
            W[i] = LoadBytesToWord(msg_iter);
            msg_iter += 4;
        }
        auto LeftShift = [](SHA132BIT word, size_t n) {
            return (word << n) | (word >> (32 - n));
        };
        for (int i = 16; i < 80; ++i) {
            SHA132BIT Wt = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
            W[i] = LeftShift(Wt, 1);
        }
        SHA132BIT A, B, C, D, E;
        A = H[0];
        B = H[1];
        C = H[2];
        D = H[3];
        E = H[4];
        for (int i = 0; i < 80; ++i) {
            int which = i / 20;
            SHA132BIT TEMP = LeftShift(A, 5) + ft[which](B, C, D) + E + W[i] + Kt[which];
            E = D;
            D = C;
            C = LeftShift(B, 30);
            B = A;
            A = TEMP;
        }
        H[0] += A;
        H[1] += B;
        H[2] += C;
        H[3] += D;
        H[4] += E;
    }
    auto LoadWordToBytes = [](SHA132BIT word,auto bytes_ptr) {
        SeparateWord w;
        w.word = word;
        for (int i = 3; i >= 0; --i) {
            *bytes_ptr = w.bytes[i];
            ++bytes_ptr;
        }
    };
    for each(auto h in H) {
        LoadWordToBytes(h, digest);
        digest += 4;
    }
    return 0;
}
#include <iostream>
#include <iomanip>
int main(void)
{
    char msg[] = "abc";
    long long msg_len = sizeof(msg)-1;
    unsigned char digest[20];
    SHA1(msg, msg_len, digest);
    for each(auto v in digest) {
        std::cout << std::hex << static_cast<unsigned int>(v);
    }
    char c;
    std::cin >> c;
    return 0;
}