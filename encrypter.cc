/* Sample code showing how to encrypt 64-bit values.
 * Based on
 * 		https://code.google.com/p/privatedatacommunicationprotocol/
 * 		https://code.google.com/p/privatedatacommunicationprotocol/downloads/detail?name=64bitdecrypter-v1.0.1.tgz
 * 
 *  
 * 
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
*/

#include <endian.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <sys/time.h>
#include <iostream>
#include <string>

#include "modp_b64w.h" // websafe base64 encode
#include <algorithm> // std::replace()

typedef int                 int32;
typedef long long           int64;
typedef unsigned int        uint32;
typedef unsigned long long  uint64;
typedef unsigned char       uchar;

// The following sizes are all in bytes.
const int32 kInitializationVectorSize = 16;
const int32 kCiphertextSize = 8;
const int32 kSignatureSize = 4;
const int32 kEncryptedValueSize = kInitializationVectorSize + kCiphertextSize + kSignatureSize;
const int32 kKeySize = 32;  // size of SHA-1 HMAC keys.
const int32 kHashOutputSize = 20;  // size of SHA-1 hash output.

using namespace std;

// Prototypes
string Encrypt(int64 price, const string& encryption_key, const string& integrity_key);
inline uint64 ntohll(uint64 host_int);
	
int main(int argc, char* argv[]) {
	if (argc != 2) {
		cout << "Usage: " << argv[0] << " price" << endl;
		return 1;
	}
	
	// Encryption and integrity keys from https://code.google.com/p/privatedatacommunicationprotocol/
	const char kEncryptionKey[] = {
		0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6,
		0xb7, 0x5d, 0xa5, 0x20, 0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b,
		0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07
	};
	const char kIntegrityKey[] = {
		0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62,
		0xed, 0x2a, 0x4c, 0xd2, 0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a,
		0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92
	};
	string encryption_key(kEncryptionKey, kKeySize);
	string integrity_key(kIntegrityKey, kKeySize);
	
	int64 price = atoi(argv[1]);
	string price_enc = Encrypt(price,encryption_key,integrity_key);
	
	cout << "Price (raw):\t\t" << price << endl;
	cout << "Price (encrypted):\t" << price_enc << endl;
}

string Encrypt(int64 price, const string& encryption_key, const string& integrity_key) {
	// Price
	price = ntohll(price); // Reverse endianness (if necessary)
	uchar* price_byte = (uchar*)&price; // Convert it to "byte"
		
	// Get current time data
	struct timeval tv;
	gettimeofday(&tv, NULL);
	
	int64 msec = tv.tv_sec;
	int64 usec = tv.tv_usec;

	msec = ntohll(msec); // Reverse endianness (if necessary)
	usec = ntohll(usec);
	
	msec = msec >> 4*8;
	usec = usec >> 4*8;
	
	// Initialization vector setup
	uchar* initialization_vector = (uchar*)calloc(1,kInitializationVectorSize);	
	memcpy(initialization_vector,&msec,kInitializationVectorSize/4); // Fill the first 4 bytes of IV with msec
	memcpy(initialization_vector+kInitializationVectorSize/4,&usec,kInitializationVectorSize/4); // Fill the second 4 bytes of IV with usec
	
	// HMAC creation
	uint32 pad_size = kHashOutputSize;
	uchar encryption_pad[kHashOutputSize];
	
	if (!HMAC(EVP_sha1(), encryption_key.data(), encryption_key.length(), initialization_vector, kInitializationVectorSize, encryption_pad, &pad_size)) {
			cerr << "Error: encryption HMAC failed" << endl;
			return "";
	}
	
	// Price is encrypted using: pad (first 8 bytes only) <xor> price
	char encprice[kCiphertextSize];
	for (int i=0; i<kCiphertextSize; i++) {
		encprice[i] = encryption_pad[i] ^ price_byte[i];
	}	
	
	// Signature (is hmac of concatenated price and init vector and integrity key)
	uint32 integrity_hash_size = kSignatureSize;
	unsigned char integrity_hash[integrity_hash_size];
	const int32 kOutputMessageSize = kCiphertextSize + kInitializationVectorSize;
	unsigned char output_message[kOutputMessageSize];
	// Concatenate price and init vector with memcpy
	memcpy(output_message, price_byte, kCiphertextSize);
	memcpy(output_message + kCiphertextSize, initialization_vector, kInitializationVectorSize);
	
	if (!HMAC(EVP_sha1(), integrity_key.data(), integrity_key.length(), output_message, kOutputMessageSize, integrity_hash, &integrity_hash_size)) {
		cerr << "Error: encryption HMAC failed" << endl;
		return "";
	}
	
	// Final message are concatenated values of init vector, encrypted price and signature encoded as websafe base64
	uchar final_msg[kEncryptedValueSize];
	memcpy(final_msg, initialization_vector,kInitializationVectorSize);
	memcpy(final_msg+kInitializationVectorSize, &encprice,kCiphertextSize);
	memcpy(final_msg+kInitializationVectorSize+kCiphertextSize, &integrity_hash,kKeySize);

	char obuf[100];
	modp_b64w_encode(obuf, (const char*)final_msg, (size_t)kEncryptedValueSize); 
	std::string output = string(obuf);
	std::replace( output.begin(), output.end(), '.','=');
	
	return output;
}

inline uint64 ntohll(uint64 host_int) {
#if defined(__LITTLE_ENDIAN)
  return static_cast<uint64>(ntohl(static_cast<uint32>(host_int >> 32))) |
      (static_cast<uint64>(ntohl(static_cast<uint32>(host_int))) << 32);
#elif defined(__BIG_ENDIAN)
  return host_int;
#else
#error Could not determine endianness.
#endif
};
