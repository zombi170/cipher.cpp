/**
 * \file ciphers.cpp
 *
 * Ebben a fájlban kell megvalósítania az CaesarCipher, MyCipher, CipherQueue osztályok metódusait.
 * 
 * Ezt a fájlt be kell adni (fel kell tölteni) a megoldással.
 */

#include "memtrace.h"
#include "ciphers.h"

/// CaesarCipher függvények
std::string CaesarCipher::encode(const std::string& message){
    std::string::const_iterator begin = message.begin();
    std::string::const_iterator end = message.end();
    std::string uj;
    while (begin != end){
        if (*begin != ' ' && (int(*begin) < 97 || int(*begin) > 122))
            throw "X079FB";

        if (*begin == ' ')
            uj.push_back(' ');
        else if (shift + int(*begin) > 122)
            uj.push_back(97 + shift + int(*begin) - 123);
        else
            uj.push_back(shift + int(*begin));

        ++begin;
    }

    return uj;
}

std::string CaesarCipher::decode(const std::string& ciphertext){
    std::string::const_iterator begin = ciphertext.begin();
    std::string::const_iterator end = ciphertext.end();
    std::string uj;
    while (begin != end){
        if (*begin != ' ' && (int(*begin) < 97 || int(*begin) > 122))
            throw "X079FB";

        if (*begin == ' ')
            uj.push_back(' ');
        else if (int(*begin) - shift < 97)
            uj.push_back(-97 + int(*begin) - shift + 123);
        else
            uj.push_back(int(*begin) - shift);

        ++begin;
    }

    return uj;
}

Cipher* CaesarCipher::clone() const{
    return new CaesarCipher(*this);
}

/// MyCipher függvények
std::string MyCipher::encode(const std::string& message){
    std::string::const_iterator begin = message.begin();
    std::string::const_iterator end = message.end();
    std::string uj;
    int i = 0, j = 0;
    while (begin != end){
        if (*begin != ' ' && (int(*begin) < 97 || int(*begin) > 122))
            throw "X079FB";

        if (*begin == ' ')
            uj.push_back(' ');
        else if (int(key[i]) - 97 + offset + j + int(*begin) > 122)
            uj.push_back(((int(key[i]) - 97 + offset + j + int(*begin) - 97) % 26) + 97);
        else
            uj.push_back(int(key[i]) - 97 + offset + j + int(*begin));

        ++i;
        ++j;
        ++begin;

        if (i >= int(key.size()))
            i = 0;
    }

    return uj;
}

std::string MyCipher::decode(const std::string& ciphertext){
    std::string::const_iterator begin = ciphertext.begin();
    std::string::const_iterator end = ciphertext.end();
    std::string uj;
    int i = 0, j = 0;
    while (begin != end){
        if (*begin != ' ' && (int(*begin) < 97 || int(*begin) > 122))
            throw "X079FB";

        if (*begin == ' ')
            uj.push_back(' ');
        else if (-int(key[i]) + 97 - j + int(*begin) - offset < 97)
            uj.push_back(((26-abs((-int(key[i]) - j + int(*begin) - offset) % 26)) % 26) + 97);
        else
            uj.push_back(-int(key[i]) + 97 - j + int(*begin) - offset);

        ++i;
        ++j;
        ++begin;

        if (i >= int(key.size()))
            i = 0;
    }

    return uj;
}

Cipher* MyCipher::clone() const{
    return new MyCipher(*this);
}

/// CipherQueue függvények
void CipherQueue::add(Cipher* cipher){
    ciphers.push_back(cipher);
}

std::string CipherQueue::encode(const std::string& message){
    std::vector<Cipher*>::iterator begin = ciphers.begin();
    std::vector<Cipher*>::iterator end = ciphers.end();
    std::string uj = message;

    while (begin != end){
        uj = (*begin++)->encode(uj);
    }

    return uj;
}

std::string CipherQueue::decode(const std::string& ciphertext){
    std::vector<Cipher*>::iterator end = ciphers.begin();
    --end;
    std::vector<Cipher*>::iterator begin = ciphers.end();
    --begin;
    std::string uj = ciphertext;

    while (begin != end){
        uj = (*begin--)->decode(uj);
    }

    return uj;
}

Cipher* CipherQueue::clone() const{
    CipherQueue* uj = new CipherQueue;
    uj->ciphers = this->ciphers;
    for (size_t i = 0; i < this->ciphers.size(); ++i)
        uj->ciphers[i] = this->ciphers[i]->clone();
    return uj;
}

CipherQueue::~CipherQueue(){
    for (size_t i = 0; i < ciphers.size(); ++i)
        delete ciphers[i];
}