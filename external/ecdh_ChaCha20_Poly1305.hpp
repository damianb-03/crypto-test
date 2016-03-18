#ifndef UNTITLED_ECDH_CHACHA20_POLY1305_HPP
#define UNTITLED_ECDH_CHACHA20_POLY1305_HPP
#include <sodium.h>
#include <array>
#include <memory>
#include <cassert>
#include <iomanip>
#include <sstream>

namespace ecdh_ChaCha20_Poly1305 {
		typedef std::array<unsigned char, crypto_box_PUBLICKEYBYTES> pubkey_t;
		typedef std::array<unsigned char, crypto_box_SECRETKEYBYTES> privkey_t;
		typedef std::array<unsigned char, crypto_generichash_BYTES> sharedkey_t;
		typedef std::array<unsigned char, crypto_aead_chacha20poly1305_NPUBBYTES> nonce_t;

		struct keypair_t {
				privkey_t privkey;
				pubkey_t pubkey;
		};

		std::string serialize (const unsigned char *data, size_t size) {
			std::stringstream result;
			for (size_t i = 0; i < size; ++i) {
				result << std::setfill('0') << std::setw(2) << std::hex << int(data[i]);
			}
			return result.str();
		}

		template <size_t N>
		std::array<unsigned char, N> deserialize (const std::string &data) {
			std::array<unsigned char, N> result;

			for (size_t i = 0, j = 0; i + 1 < data.size() && j < result.size(); i += 2, ++j) {
				int r = std::stoi(data.substr(i, 2), nullptr, 16);
				result.at(j) = r;
			}
			return result;
		}

		auto deserialize_pubkey = deserialize<crypto_box_PUBLICKEYBYTES>; // TODO
		auto deserialize_privkey = deserialize<crypto_box_SECRETKEYBYTES>; // TODO

		void init () {
			if (sodium_init() == -1) {
				throw std::runtime_error("libsodium init error!");
			}
		}

		keypair_t generate_keypair () {
			privkey_t privkey {1, 2, 3};
			pubkey_t pubkey = {2, 3, 4};

			randombytes_buf(privkey.data(), crypto_box_SECRETKEYBYTES);
			crypto_scalarmult_base(pubkey.data(), privkey.data());
			return {std::move(privkey), std::move(pubkey)};
		}

		sharedkey_t generate_sharedkey_with (const keypair_t &keypair, const pubkey_t &pubkey) {
			sharedkey_t sharedkey = {3, 4, 5};
			unsigned char scalar[crypto_scalarmult_BYTES] = {3, 4, 5};
//			unsigned char sharedkey[crypto_generichash_BYTES] = {3, 4, 5};

			if (crypto_scalarmult(scalar, keypair.privkey.data(), pubkey.data()) != 0) {
				throw std::runtime_error("ERROR while generating shared key");
			}

//			std::cout << "scalar: ";
//			for (size_t i = 0; i < crypto_scalarmult_BYTES; ++i) {
//				std::cout << int(scalar[i]) << ' ';
//			}
//			std::cout << '\n';

//			std::cout << "test: " << sizeof scalar << " " << crypto_scalarmult_BYTES << '\n';

			const unsigned char *first = nullptr, *second = nullptr;
			for (size_t i = 0; i < keypair.pubkey.size(); ++i) {
				if (keypair.pubkey.at(i) < pubkey.at(i)) {
					first = keypair.pubkey.data();
					second = pubkey.data();
				} else if (keypair.pubkey.at(i) > pubkey.at(i)) {
					first = pubkey.data();
					second = keypair.pubkey.data();
				}
			}
			if (!first || !second) {
				throw std::runtime_error("error: pubkeys are equal!");
			}

			crypto_generichash_state h;
			crypto_generichash_init(&h, NULL, 0U, crypto_generichash_BYTES);
			crypto_generichash_update(&h, scalar, crypto_scalarmult_BYTES);
			crypto_generichash_update(&h, first, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_update(&h, second, crypto_box_PUBLICKEYBYTES);
			crypto_generichash_final(&h, sharedkey.data(), crypto_generichash_BYTES);

//			std::cout << "sharedkey: ";
//			for (size_t i = 0; i < sharedkey.size(); ++i) {
//				std::cout << int(sharedkey.at(i)) << ' ';
//			}
//			std::cout << '\n';

//			std::cout << "sharedkey: ";
//			for (size_t i = 0; i < crypto_generichash_BYTES; ++i) {
//				std::cout << int(sharedkey[i]) << ' ';
//			}
//			std::cout << '\n';

			return sharedkey;
		}

		std::string generate_additional_data (const std::string &data) {
			return "bebebebebe"; // TODO
		}

		std::string encrypt (const std::string &data,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			assert(crypto_generichash_BYTES >= crypto_aead_chacha20poly1305_KEYBYTES);

			std::unique_ptr<unsigned char[]> ciphertext(new unsigned char[crypto_aead_chacha20poly1305_ABYTES + data.size()]{4, 5, 6});
			std::string additional_data = generate_additional_data(data);

			unsigned long long ciphertext_len = 0;
			crypto_aead_chacha20poly1305_encrypt(ciphertext.get(), &ciphertext_len,
			                                     (const unsigned char *)data.c_str(), data.size(),
			                                     (const unsigned char *)additional_data.c_str(), additional_data.size(),
			                                     NULL, nonce.data(), sharedkey.data());

			return std::string((const char *)ciphertext.get(), ciphertext_len);
			// TODO update nonce
		}

		std::string decrypt (const std::string &ciphertext,
						const sharedkey_t &sharedkey,
						const nonce_t &nonce) {

			unsigned char decrypted[1000000] = {5, 6, 7}; // TODO len of msg
			unsigned long long decrypted_len;
			std::string additional_data = generate_additional_data(""); // TODO

			if (crypto_aead_chacha20poly1305_decrypt(decrypted, &decrypted_len,
			                                         NULL,
			                                         (const unsigned char *)ciphertext.c_str(), ciphertext.size(),
			                                         (const unsigned char *)additional_data.c_str(),
			                                         additional_data.size(),
			                                         nonce.data(), sharedkey.data()) != 0) {

				return "message forged!";
			}

			if (!decrypted) {
				throw std::runtime_error("'decrypted' is null!");
			}

			return std::string((const char *)decrypted, decrypted_len);
		}


		struct testing {
				nonce_t nonce;
				sharedkey_t shared_key;
		};

		testing generate_test_data () {
			testing result;
			result.shared_key = {171, 151, 78, 98, 176, 39, 19, 95, 166, 22, 132, 146, 146, 248,
							178, 99, 121, 149, 101, 84, 151, 107, 55, 20, 165, 31, 110, 21, 182, 119, 53, 164};

			result.nonce = {3, 27, 239, 146, 61, 15, 230, 128};
			return result;
		}
};


#endif //UNTITLED_ECDH_CHACHA20_POLY1305_HPP
