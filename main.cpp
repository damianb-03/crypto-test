#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <memory>
#include <fstream>
#include <signal.h>
#include <future>
#include "external/ecdh_ChaCha20_Poly1305.hpp"
#include "external/c_UDPasync.hpp"
#include "external/c_TCPasync.hpp"

std::fstream logger("./log", std::ios_base::trunc | std::ios_base::in | std::ios_base::out);
std::atomic<bool> stop_process;

void start_recieving (c_UDPasync &connection,
				const ecdh_ChaCha20_Poly1305::sharedkey_t &shared_key,
				const ecdh_ChaCha20_Poly1305::nonce_t &nonce) {

	while (!stop_process) {
		if (connection.has_messages()) {
			std::string msg = connection.pop_message();
			std::string decrypted = ecdh_ChaCha20_Poly1305::decrypt(msg, shared_key, nonce);

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

void handle_sending (c_UDPasync &connection,
				const ecdh_ChaCha20_Poly1305::sharedkey_t &shared_key,
				const ecdh_ChaCha20_Poly1305::nonce_t &nonce) {

	std::string msg;

	while (!stop_process) {
		std::cout << "#> ";
		std::getline(std::cin, msg);
		std::string encrypted = ecdh_ChaCha20_Poly1305::encrypt(msg, shared_key, nonce);

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


void generate_config (const std::string &filename) {
	std::fstream config(filename, std::ios_base::trunc | std::ios_base::in | std::ios_base::out);
	if (!config.good()) {
		throw std::runtime_error("error while opening a file: " + filename);
	}

	auto keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
	config << ecdh_ChaCha20_Poly1305::serialize(keypair.pubkey.data(), keypair.pubkey.size());
	config << '\n';
	config << ecdh_ChaCha20_Poly1305::serialize(keypair.privkey.data(), keypair.privkey.size());
}

ecdh_ChaCha20_Poly1305::keypair_t load_keypair (const std::string &filename) {
	std::ifstream config(filename, std::ios_base::out);
	if (!config.good()) {
		throw std::runtime_error("error while opening a file: " + filename);
	}

	ecdh_ChaCha20_Poly1305::keypair_t result;
	std::string input;

	std::getline(config, input);
	result.pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(input);

	std::getline(config, input);
	result.privkey = ecdh_ChaCha20_Poly1305::deserialize_privkey(input);
	config.close();
	return result;
}

ecdh_ChaCha20_Poly1305::nonce_t do_handshake (const std::string &ipv6_addr,
				const ecdh_ChaCha20_Poly1305::pubkey_t &pubkey,
				c_UDPasync &connection) {

	std::cout << "handshake started...\n";
	logger << "handshake started...\n";
	auto handshake_keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
	std::atomic<bool> stop_thread(false);

	auto serialized_handshake_pubkey = ecdh_ChaCha20_Poly1305::serialize(handshake_keypair.pubkey.data(), handshake_keypair.pubkey.size());
	auto exec = [&] () {
			connection.send(serialized_handshake_pubkey); // TODO
			while (!stop_thread) {
				if (connection.has_messages()) {
					auto msg = connection.pop_message();
					if (msg.size() == crypto_box_PUBLICKEYBYTES * 2) {
						return msg;
					}
				}
				if (stop_process) {
					throw std::runtime_error("aborting handshake");
				}
				std::this_thread::yield();
			}
			throw std::runtime_error("handshake failed");
	};

	auto handle = std::async(std::launch::async, exec);

	if (handle.wait_for(std::chrono::seconds(15)) == std::future_status::timeout) {
		stop_thread = true;
		handle.get();
	} else {
		if (!handle.valid()) {
			throw std::runtime_error("handshake failed");
		}

		auto handshake_pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(handle.get());
		auto result = ecdh_ChaCha20_Poly1305::generate_nonce_with(handshake_keypair, handshake_pubkey);
		std::cout << "done\n";
		logger << "done\n";
		return result;
	}
	throw std::runtime_error("handshake failed");
}

ecdh_ChaCha20_Poly1305::nonce_t tcp_do_handshake(c_TCPasync &connection,
												 c_TCPcommand &cmd,
												 std::chrono::seconds wait = std::chrono::seconds(20)) {

	auto hshake_keypair = ecdh_ChaCha20_Poly1305::generate_keypair();
	auto serialized_hshake_pubkey = ecdh_ChaCha20_Poly1305::serialize(hshake_keypair.pubkey.data(),
																	  hshake_keypair.pubkey.size());
	cmd.set_response(serialized_hshake_pubkey);
	connection.add_cmd(cmd);
	std::this_thread::sleep_for(wait/10);	// wait for establish a connection
	connection.send_cmd_request(protocol::handshake);

	std::string handle;
	int attempts = 5;
	do {
		if(cmd.has_message()) {
			handle = cmd.pop_message();
			break;
		} else {
			std::cout << "Attempt: " << attempts << " waiting for response" << std::endl;
			std::this_thread::sleep_for(wait/10);
		}
		if(attempts == 0) {
			throw std::runtime_error("Fail to get handshake response in wait time");
		}
		attempts--;
	} while(true);

	auto hshake_pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(handle);
	auto result_nonce = ecdh_ChaCha20_Poly1305::generate_nonce_with(hshake_keypair, hshake_pubkey);

	return result_nonce;
}

void do_prehandshake (c_UDPasync &connection) { // TODO
	std::atomic<bool> stop(false);
	logger << "connecting...\n";
	std::cout << "connecting...\n";

	auto exec = [&] () {
			connection.send("");
			while (!connection.has_messages() && !stop) {
				connection.send("");
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
				if (stop_process) {
					throw std::runtime_error("aborting prehandshake");
				}
			}

			std::this_thread::sleep_for(std::chrono::seconds(1));
			connection.send("");
	};

	auto handle = std::async(std::launch::async, exec);
	if (handle.wait_for(std::chrono::seconds(15)) == std::future_status::timeout) {
		stop = true;
		handle.get();
	} else {
		if (!handle.valid()) {
			throw std::runtime_error("unable to connect");
		}
		handle.get();
		return;
	}
	throw std::runtime_error("unable to connect");
}

void connect (const std::string &ipv6_addr,
				const ecdh_ChaCha20_Poly1305::pubkey_t &pubkey,
				const ecdh_ChaCha20_Poly1305::keypair_t &keypair) { // TODO

    ecdh_ChaCha20_Poly1305::sharedkey_t shared_key = ecdh_ChaCha20_Poly1305::generate_sharedkey_with(keypair, pubkey);
    ecdh_ChaCha20_Poly1305::nonce_t nonce;

    std::cout << "#> Set your local port: ";
    unsigned short local_port = get_port();
    std::cout << "#> Set target server port: ";
    unsigned short server_port = get_port();

	c_TCPasync tcp_connection(ipv6_addr, server_port, local_port);
	c_TCPcommand handshake_cmd(protocol::handshake);
	nonce = tcp_do_handshake(tcp_connection, handshake_cmd);

	//ecdh_ChaCha20_Poly1305::nonce_t nonce = do_handshake(ipv6_addr, pubkey, udp_connection);	//old

    std::cout << "\nsharedkey: ";
    logger << "sharedkey: ";
	for (auto &&c: shared_key) {
		logger << int(c) << ' ';
        std::cout << int(c) << ' ';
    }
    logger << "\nnonce: ";
    std::cout << "\nnonce: ";
    for (auto &&c: nonce) {
		logger << int(c) << ' ';
        std::cout << int(c) << ' ';
    }
	logger << "\n\n";
    std::cout << "\n\n";

	c_UDPasync udp_connection(ipv6_addr, server_port, local_port);
	do_prehandshake(udp_connection);

    std::cout << "UDPasync: connected with " << ipv6_addr << " on port " << server_port << '\n';
    logger << "UDPasync: connected with " << ipv6_addr << " on port " << server_port << '\n';


    std::thread receive(start_recieving, std::ref(udp_connection), std::ref(shared_key), std::ref(nonce));
    std::thread send(handle_sending, std::ref(udp_connection), std::ref(shared_key), std::ref(nonce));
	receive.join();
	send.join();
}

void debug () {
	std::cout << "DEBUG MODE\n";
	std::string ipv6_addr, pubkey, config_filename;
	std::cin >> ipv6_addr >> pubkey >> config_filename;
	auto keypair = load_keypair(config_filename);
	connect(ipv6_addr, ecdh_ChaCha20_Poly1305::deserialize_pubkey(pubkey), keypair);
}

void init () {
	stop_process = false;
	signal(SIGINT, [] (int) {
			stop_process = true;
			logger << "aborting...";
			logger.close();
	});

	ecdh_ChaCha20_Poly1305::init();
}

void start (int argc, char **argv) {
	if (argc < 2) {
		//		std::cout << "type --help to show help\n";
		//		return;
		debug();
	}

	init();
	std::string command = std::string(argv[1]);

	if (command == "--help") {
		std::cout << "--help                                       show this help\n";
		std::cout << "--connect [ipv6] [pubkey] [config filename]  connect to [ipv6]\n";
		std::cout << "--gen-conf [config filename]                 generate keypair and save to [config filename]\n";

	} else if (command == "--connect") {
		if (argc < 5) {
			std::cout << "type --help to show help\n";
			return;
		}
		std::string ipv6_addr = std::string(argv[2]);
		ecdh_ChaCha20_Poly1305::pubkey_t pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(std::string(argv[3]));
		std::string config_filename = std::string(argv[4]);
		auto keypair = load_keypair(config_filename);
		connect(ipv6_addr, pubkey, keypair);

	} else if (command == "--gen-conf") {
		if (argc < 3) {
			std::cout << "type --help to show help\n";
			return;
		}
		std::string filename = std::string(argv[2]);
		generate_config(filename);

	} else if (command == "--debug") {
		debug();

	} else {
		std::cout << "type --help to show help\n";
	}
}

int main (int argc, char **argv) {
    try {
		start(argc, argv);
	} catch (std::exception &exc) {
		std::cout << exc.what() << '\n';
		logger << exc.what() << '\n';
	} catch (...) {
		std::cout << "internal error\n";
		logger << "internal error\n";
	}
	return 0;
}
