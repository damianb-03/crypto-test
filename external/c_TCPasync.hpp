#ifndef C_UDP_NETWORK_HPP
#define C_UDP_NETWORK_HPP

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include "ecdh_ChaCha20_Poly1305.hpp"
#include <boost/asio.hpp>

#define DBG_MTX(X,Y) do{X.lock();std::cout<< __func__<<":\t\t "<<Y<<std::endl;X.unlock();}while(0)

using namespace boost::asio;

extern unsigned short get_port();

class c_TCPasync {
  public:
    c_TCPasync (int port = 30000);

    int get_server_port ();

    /// connection test
    bool wait_for_connection (const std::string &ip_addres, std::chrono::seconds wait, int port = 30000);

    ecdh_ChaCha20_Poly1305::nonce_t do_handshake (const std::string &ip_address, int port = 30000);

    ~c_TCPasync();
  private:
    /// hendshake data
    ecdh_ChaCha20_Poly1305::keypair_t m_handshake_keypair;
    bool handshake_ok = false;

    const int server_port;
    io_service m_io_service;
    ip::tcp::socket client_socket;
    ip::tcp::socket server_socket;
    ip::tcp::acceptor m_acceptor;
    void create_server ();

    // protocol functions
    std::string get_handshake_response (ip::tcp::socket &socket_);
    void send_handshake_request (ip::tcp::socket &socket);
    void send_handshake_response (ip::tcp::socket &socket);

    void server_read (ip::tcp::socket socket_);

    std::atomic<bool> m_stop_flag;

    enum { max_length = 1024 };
    char data_[max_length];

    std::vector<std::thread> m_threads;
    void threads_maker (unsigned);
    std::mutex dbg_mtx;
};

#endif // C_UDP_NEWTORK_HPP
