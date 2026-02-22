#include "DES.h"
#include "permutation.h"
#include "des_utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <bitset>
using namespace std;

string encryption(string plaintext, vector<string> keys) { //takes in 64 bit plaintext and 16 48-bit keys, returns 64 bit ciphertext

    string newPlaintext = "";
    for (int i = 0; i < 64; i++) { //initial permutation

        newPlaintext += plaintext[IP[i] - 1];
    }

    string L = newPlaintext.substr(0, 32); //initialize L and R
    string R = newPlaintext.substr(32, 32);

    for (int round = 0; round < 16; round++) { //begin des

        string key = keys[round]; //get subkey for this round


        string lastL = L; // store and replace L
        L = R; 

        string expanded; //expand box
        for (int i = 0; i < 48; i++) {

            expanded += R[E[i] - 1 ];
        }

        string xor1 = ""; //xor with key
        for (int i = 0; i < 48; i++ ) {

            xor1 += char(((expanded[i] - '0') ^ (key[i] - '0')) + '0'); 
        }

        string sboxed= ""; //sbox output

        for (int i = 0; i < 8; i++) { //for each s box} 

            string sixbits = xor1.substr(i*6, 6); //get 6 bits

            int row = (sixbits[0] - '0') * 2 + (sixbits[5] - '0'); //calculate row and column, convert binary to decimal
            int col = (sixbits[1] - '0') * 8 + (sixbits[2] - '0') * 4 + (sixbits[3] - '0') * 2 + (sixbits[4] - '0');

            int sboxval = SBOXMAP[i][row*16 + col]; //get sbox value (64 index array notation)

            bitset<4> bits(sboxval); //convert back to binary 
            sboxed += bits.to_string(); //add to output
        }

        string permuted = ""; //p box
        for (int i = 0; i < 32; i++) {

            permuted += sboxed[P[i] - 1];
        }

        for (int i = 0; i < 32; i++) { // R = Last L XORed with permuted sbox output

            R[i] = char((((permuted[i] - '0') ^ (lastL[i] - '0')) + '0')); //perform xor then get back to binary string and append to R
        }

    }
    
    string preoutput = R + L; 
    
    string ciphertext = ""; //final permutation
    for (int i = 0; i < 64; i++) {

        ciphertext += preoutput[FP[i] - 1];
    }

    return ciphertext;
}

string decryption(string encrypted, vector<string> keys) {
    
}
