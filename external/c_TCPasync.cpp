#include "c_TCPasync.hpp"

const unsigned short header_size = 3;
// Check if port is correct for us. If not returning default port.
unsigned short get_port() {
  try {
    unsigned short port;
    if(!(std::cin >> port)) {
        std::string msg = "Invalid port number [" + std::to_string(port) + "]";
        throw std::invalid_argument(msg);
    }
    if(port > 1025 && port < 32000) {
        return port;	// port is OK
    } else {
        std::string msg = "Invalid port number [" + std::to_string(port) + "]";
        throw std::invalid_argument(msg);
    }
  } catch (std::invalid_argument &err) {
        std::cout << err.what() << std::endl;
        std::cout << "Set to default port: 30000" << std::endl;
        return 30000;
  }
}

c_TCPasync::c_TCPasync(int port) :
                                   server_port(port),
                                   client_socket(m_io_service),
                                   server_socket(m_io_service),
                                   m_acceptor(m_io_service, ip::tcp::endpoint(ip::tcp::v6(),server_port)),
                                   m_stop_flag(false),
                                   m_handshake_keypair(ecdh_ChaCha20_Poly1305::generate_keypair()) {

    create_server();
    threads_maker(2);
}

int c_TCPasync::get_server_port() {
    return server_port;
}

bool c_TCPasync::wait_for_connection(const std::string &ip_address, std::chrono::seconds wait, int port) {
    DBG_MTX(dbg_mtx, "* check connection *");

    boost::system::error_code ec;
    ip::address addr = ip::address::from_string(ip_address, ec);

    if (!addr.is_v6()) {
        std::string msg = addr.to_string();
        msg += ec.message() + " : is not valid IPv6 address";
        throw std::invalid_argument(msg);
    }
    ip::tcp::endpoint server_endpoint(addr, port);

    ip::tcp::socket socket_(m_io_service);

    int attempts = 5;
    do {
        socket_.connect(server_endpoint, ec);
        std::this_thread::sleep_for(wait/5);
        if(ec) {
            DBG_MTX(dbg_mtx, "attempt " << attempts << " fail to connct");
            if(attempts == 0) {
                return 1;	// fail to connect in wait time
            }
        } else {
            DBG_MTX(dbg_mtx, "connect with " << ip_address << " success");
            break;
        }

    } while(!ec);
    socket_.close();
    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////// networking

ecdh_ChaCha20_Poly1305::nonce_t c_TCPasync::do_handshake(const std::string &ip_address, int port) {

    boost::system::error_code ec;
    ip::address addr = ip::address::from_string(ip_address, ec);
    if (!addr.is_v6()) {
        std::string msg = addr.to_string();
        msg += ec.message()+" : is not valid IPv6 address";
        throw std::invalid_argument(msg);
    }
    ip::tcp::endpoint server_endpoint(addr, port);

    ip::tcp::socket socket_(m_io_service);
    socket_.connect(server_endpoint, ec);
    if (ec) {
        DBG_MTX(dbg_mtx,"EC = " << ec);
        throw std::runtime_error("do_handshake -- fail to connect");
    }

    DBG_MTX(dbg_mtx, "Do handshake: getting sender public key");
    send_handshake_request(socket_);
    std::string handshake_packet(get_handshake_response(socket_));

    while(!handshake_ok) {
        std::this_thread::yield();
    }

    ecdh_ChaCha20_Poly1305::pubkey_t handshake_pubkey = ecdh_ChaCha20_Poly1305::deserialize_pubkey(handshake_packet);

    DBG_MTX(dbg_mtx, "handshake packet: " << handshake_packet);
    //std::cout << "handshake pubkey: " << handshake_pubkey << std::endl;

    auto result = ecdh_ChaCha20_Poly1305::generate_nonce_with(m_handshake_keypair, handshake_pubkey);

    socket_.close();
    return result;
}

std::string c_TCPasync::get_handshake_response(ip::tcp::socket &socket_) {

    assert(socket_.is_open());
    boost::system::error_code ec;

    char header[header_size];
    // DBG_MTX(dbg_mtx, "read header"); // dbg
    size_t pkresp = socket_.read_some(buffer(header, header_size), ec);
    // DBG_MTX(dbg_mtx, "get handshake response: " << pkresp << ":[" << header[0]
    //																 << header[1]
    //        														 << header[2] << "]");
    assert(pkresp == header_size);

    size_t pub_key_size = 4;
    uint32_t key_size = 0;
    size_t recieved_bytes = socket_.read_some(buffer(&key_size, pub_key_size), ec);
    DBG_MTX(dbg_mtx, "size:" << recieved_bytes << ":[" <<key_size << "]");

    assert(recieved_bytes == pub_key_size);

    const std::unique_ptr<char[]> pub_key_data(new char[key_size]);

    DBG_MTX(dbg_mtx, "read public key data");
    recieved_bytes = socket_.read_some(buffer(pub_key_data.get(), key_size), ec);
    assert(recieved_bytes == key_size);

    std::string pub_key(pub_key_data.get(), key_size);
    return pub_key;
}

void c_TCPasync::send_handshake_request(ip::tcp::socket &socket) {

    DBG_MTX(dbg_mtx, "send handshake request");
    assert(socket.is_open());
    boost::system::error_code ec;
    char handshake_send_req[header_size] = {'h','r','q'};
    size_t sendbytes = socket.write_some(boost::asio::buffer(handshake_send_req, 3),ec);
    //DBG_MTX(dbg_mtx, "hrq: " << sendbytes << ":[" << handshake_send_req[0]
    //                                              << handshake_send_req[1]
    //                                              << handshake_send_req[2] << "]");
}

void c_TCPasync::send_handshake_response(ip::tcp::socket &socket) {

    DBG_MTX(dbg_mtx, "send handshake response");
    assert(socket.is_open());
    boost::system::error_code ec;
    char header[header_size] = {'h', 'r','s'};
    // DBG_MTX(dbg_mtx, "hs_resp: send header"); // dbg
    socket.write_some(buffer(header, header_size), ec);

    auto packet = ecdh_ChaCha20_Poly1305::serialize(m_handshake_keypair.pubkey.data(),
                                                    m_handshake_keypair.pubkey.size());

    uint32_t packet_size = packet.size();
    // DBG_MTX(dbg_mtx,"hs_resp: send public key size" << "[" << packet_size << "]"); // dbg
    socket.write_some(boost::asio::buffer(&packet_size, 4), ec);

    DBG_MTX(dbg_mtx,"hs_resp: send public key data" << "[" << packet << "]");
    socket.write_some(boost::asio::buffer(packet.c_str(), packet_size), ec);
    DBG_MTX(dbg_mtx,"end of handshake response");

    handshake_ok = true;
}

//////////////////////////////////////////////////////////////////////////////////////////////////// networking

void c_TCPasync::create_server() {
    while (m_io_service.stopped() && !m_stop_flag) {
        std::this_thread::yield();
    }
    if (m_stop_flag) {
        DBG_MTX(dbg_mtx, "stop flag, return");
        return;
    }
    assert(m_io_service.stopped() == false);
    m_acceptor.async_accept(server_socket,
                            [this](boost::system::error_code ec) {
                                // DBG_MTX(dbg_mtx,"async lambda"); // dbg
                                if(!ec) {
                                    // DBG_MTX(dbg_mtx,"do read start"); // dbg
                                    this->server_read(std::move(server_socket));
                                } else {
                                    DBG_MTX(dbg_mtx,"EC = " << ec);
                                }
                                this->create_server();
                            });
}

void c_TCPasync::server_read(ip::tcp::socket socket_) {
    DBG_MTX(dbg_mtx, "START");
    assert(socket_.is_open());
    boost::system::error_code ec;
    DBG_MTX(dbg_mtx,"server read");
    while (!ec && !m_stop_flag) {
        char header[header_size] = {0, 0, 0};
        socket_.read_some(buffer(header, header_size), ec);
        // if hendshake packet request detected
        if (header[0] == 'h' && header[1] == 'r' && header[2] == 'q') {
            send_handshake_response(socket_);
        }
    }
    socket_.close();
}

//////////////////////////////////////////////////////////////////////////////////////////////////// networking

c_TCPasync::~c_TCPasync() {
    m_stop_flag = true;
    m_io_service.stop();
    for (auto &t : m_threads) {
        t.join();
    }
}

void c_TCPasync::threads_maker(unsigned num) {
    m_threads.reserve(num);
    for (unsigned i = 0; i < num; ++i) {
        // DBG_MTX(dbg_mtx,"make " << i << " thread"); // dbg
        m_threads.emplace_back([this](){
            while (!m_stop_flag)
            {
                this->m_io_service.reset();
                this->m_io_service.run();
            }
            // DBG_MTX(dbg_mtx, "end of thread"); // dbg
        });
    }
}
