#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <memory>
#include <fstream>
#include <signal.h>
#include "external/ecdh_ChaCha20_Poly1305.hpp"
#include "external/c_UDPasync.hpp"

std::fstream logger("./log", std::ios_base::trunc | std::ios_base::in | std::ios_base::out);
std::atomic<bool> end;

void start_recieving (c_UDPasync &connection, const ecdh_ChaCha20_Poly1305::testing &data) {
	while (!end) {
		if (connection.has_messages()) {
			std::string msg = connection.pop_message();
			std::string decrypted = ecdh_ChaCha20_Poly1305::decrypt(msg, data.shared_key, data.nonce);

			logger << "--------- NEW MESSAGE:\n";
			logger << "encrypted: ";
			for (char c : msg) {
				logger << int(c) << ' ';
			}
			logger << "\ndecrypted: ";
			for (char c : decrypted) {
				logger << int(c) << ' ';
			}
			logger << "  -->   " << decrypted << "\n\n";

			std::cout << decrypted << endl << "#> ";
			std::cout.flush();
		}

		std::this_thread::yield();
	}
}

void handle_sending (c_UDPasync &connection, const ecdh_ChaCha20_Poly1305::testing &data) {
	std::string msg;

	while (!end) {
		std::cout << "#> ";
		std::getline(std::cin, msg);
		std::string encrypted = ecdh_ChaCha20_Poly1305::encrypt(msg, data.shared_key, data.nonce);

		logger << "--------- MESSAGE SENT:\n";
		logger << "encrypted: ";
		for (char c : encrypted) {
			logger << int(c) << ' ';
		}
		logger << "\ndecrypted: ";
		for (char c : msg) {
			logger << int(c) << ' ';
		}
		logger << "  -->   " << msg << "\n\n";

		connection.send(encrypted);
		std::this_thread::yield();
	}
}

int main (int argc, char **argv) {
	if (argc < 2) {
		std::cout << "error\n";
		return 0;
	}

	end = false;
	signal(SIGINT, [] (int) {
			logger << "aborting...";
			end = true;
			logger.close();
	});

	std::string ipv6_addr = std::string(argv[1]);

	logger << "connected with " << ipv6_addr << '\n';


	ecdh_ChaCha20_Poly1305::init();
	c_UDPasync connection(ipv6_addr, 12325, 12325);

	auto test_data = ecdh_ChaCha20_Poly1305::generate_test_data();

	logger << "sharedkey: ";
	for (auto &&c: test_data.shared_key) {
		logger << int(c) << ' ';
	}
	logger << "\nnonce: ";
	for (auto &&c: test_data.nonce) {
		logger << int(c) << ' ';
	}
	logger << "\n\n";

	std::thread receive(start_recieving, std::ref(connection), std::ref(test_data));
	std::thread send(handle_sending, std::ref(connection), std::ref(test_data));
	receive.join();
	send.join();
	return 0;
}
