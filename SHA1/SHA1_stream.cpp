#include <istream>
#include <functional>
typedef unsigned int WORD;
typedef unsigned char BYTE;

inline void CvtEndian(BYTE*source, size_t length, BYTE*destance) 
{
    BYTE *iter= source+length - 1;
    if (source == destance) {
        for (size_t i = 0; i < static_cast<size_t>(length / 2); ++i) {
            std::swap(*destance++, *iter--);
        }
    }
    else {
        for (size_t i = 0; i < length; ++i) {
            *destance++ = *iter--;
        }
    }
}
int SHA1(std::istream& read_in, unsigned char digest[20])
{
    unsigned long long msg_length = 0;
    const size_t MSG_BYTES_LENGTH = 64;
    const size_t MSG_WORDS_LENGTH = 16;
    union ReadCache {
        BYTE bytes[MSG_BYTES_LENGTH];
        WORD words[MSG_WORDS_LENGTH];
    };
    WORD H[5] = { 0x67452301,0xEFCDAB89, 0x98BADCFE, 0x10325476,0xC3D2E1F0 };
    bool others = true;
    do {
        ReadCache cache;
        read_in.read(reinterpret_cast<char*>(cache.bytes), MSG_BYTES_LENGTH);
        size_t read_length = static_cast<size_t>(read_in.gcount());
        msg_length += read_length;
        if (read_length < MSG_BYTES_LENGTH) {
            others = false;
            const BYTE ADDITIONAL_1ST = 0x80;
            const BYTE ADDITIONAL_OTHERS = 0x00;
            cache.bytes[read_length] = ADDITIONAL_1ST;
            const size_t ADDITIONAL_LENGTH = 56;
            for (size_t i = 1; i < ADDITIONAL_LENGTH - read_length; ++i) {
                cache.bytes[read_length + i] = ADDITIONAL_OTHERS;
            }
            msg_length *= 8;
            CvtEndian(reinterpret_cast<BYTE*>(&msg_length), sizeof(msg_length), cache.bytes + ADDITIONAL_LENGTH);//to big endian;
        }

        for (auto& word:cache.words) {
            CvtEndian(reinterpret_cast<BYTE*>(&word), sizeof(WORD), reinterpret_cast<BYTE*>(&word));//to little endian;
        }
        const static WORD Kt[4] = { 0x5A827999 ,0x6ED9EBA1  ,0x8F1BBCDC,0xCA62C1D6 };
        const static std::function<WORD(WORD B,WORD C,WORD D)> ft[4] =
        {
            [](WORD B,WORD C,WORD D)->WORD {return (B&C) | ((~B)&D); },
            [](WORD B,WORD C,WORD D)->WORD {return B ^ C ^ D; },
            [](WORD B,WORD C,WORD D)->WORD {return (B&C) | (B&D) | (C&D); },
            [](WORD B,WORD C,WORD D)->WORD {return B ^ C ^ D; },
        };
        WORD W[80];
        for (size_t i = 0; i < MSG_WORDS_LENGTH; ++i) {
            W[i] = cache.words[i];
        }
        auto LeftShift = [](WORD word, size_t n) {return (word << n) | (word >> (32 - n)); };
        for (size_t i = 16; i < 80; ++i) {
            WORD Wt = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
            W[i] = LeftShift(Wt, 1);
        }
        WORD ABCDE[5] = { H[0],H[1],H[2],H[3],H[4] };
        for (size_t i = 0; i < 80; ++i) {
            size_t which = static_cast<size_t>(i / 20);
            WORD TEMP = LeftShift(ABCDE[0],5)+ft[which](ABCDE[1],ABCDE[2],ABCDE[3])+ABCDE[4]+ W[i] + Kt[which];
            ABCDE[4] = ABCDE[3];
            ABCDE[3] = ABCDE[2];
            ABCDE[2] = LeftShift(ABCDE[1], 30);
            ABCDE[1] = ABCDE[0];
            ABCDE[0] = TEMP;
        }
        for (size_t i = 0; i < 5; ++i) {
            H[i] += ABCDE[i];
        }
    } while (others);
    for (size_t i = 0; i < 5; ++i) {
        size_t pos = i*sizeof(WORD);
        CvtEndian(reinterpret_cast<BYTE*>(&H[i]), sizeof(WORD), reinterpret_cast<BYTE*>(digest + pos));
    }
    return 0;
}
#if 1
#include <sstream>
#include <iostream>
#include <iomanip>
int main(void)
{
    char msg[] = "abc";
    std::stringstream msg_stream(msg);
    unsigned char digest[20];
    SHA1(msg_stream, digest);
    for (auto v : digest) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(v);
    }
    char c;
    std::cin >> c;
}
#endif