//
// client.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <thread>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <mutex>
#include <condition_variable>

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;



enum { max_length = 1024 };

class client
{
public:
  client(boost::asio::io_context& io_context,
      boost::asio::ssl::context& context,
      const tcp::resolver::results_type& endpoints)
    : socket_(io_context, context),
      handshake_completed_(false)
  {
    socket_.set_verify_mode(boost::asio::ssl::verify_peer);
    socket_.set_verify_callback(
        std::bind(&client::verify_certificate, this, _1, _2));

    connect(endpoints);
  }

  void send_request_from_main(char* str, size_t length){
    send_request(str, length);
  }
private:
  bool verify_certificate(bool preverified,
      boost::asio::ssl::verify_context& ctx)
  {
    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
    std::cout << "Verifying " << subject_name << "\n";

    return preverified;
  }

  void connect(const tcp::resolver::results_type& endpoints)
  {
    boost::asio::async_connect(socket_.lowest_layer(), endpoints,
        [this](const boost::system::error_code& error,
          const tcp::endpoint& /*endpoint*/)
        {
          if (!error)
          {
            handshake();
          }
          else
          {
            std::cout << "Connect failed: " << error.message() << "\n";
          }
        });
  }

  void handshake()
  {
    socket_.async_handshake(boost::asio::ssl::stream_base::client,
        [this](const boost::system::error_code& error)
        {
          if (!error)
          {
            handshake_completed_ = true;
            //send_request();
            start_receiving_heartbeat();
          }
          else
          {
            std::cout << "Handshake failed: " << error.message() << "\n";
          }
        });
  }

  void send_request(char* str, size_t length)
  {
    // std::cout << "Enter message: ";
    // std::cin.getline(request_, max_length);
    // size_t request_length = std::strlen(request_);
    //bool flag = false;
    //size_t request_length;
    
    boost::asio::async_write(socket_,
        boost::asio::buffer(str, length),
        [this](const boost::system::error_code& error, std::size_t length)
        {
          if (!error)
          {
            //receive_response(length);
            // send_request();
          }
          else
          {
            std::cout << "Write failed: " << error.message() << "\n";
          }
        });
  }

  void receive_response(std::size_t length)
  {
    boost::asio::async_read(socket_,
        boost::asio::buffer(reply_, length),
        [this](const boost::system::error_code& error, std::size_t length)
        {
          if (!error)
          {
            // std::cout << "Reply: ";
            // std::cout.write(reply_, length);
            // std::cout << "\n";
            //send_request();
          }
          else
          {
            std::cout << "Read failed: " << error.message() << "\n";
          }
        });
  }

  void start_receiving_heartbeat()
  {
    //std::cout<<"started"<<std::endl;
    boost::asio::async_read(socket_,
        boost::asio::buffer(heartbeat_, 10), 
        [this](const boost::system::error_code& error, std::size_t length)
        {
          if (!error)
          {
            std::cout.write(heartbeat_, length);
            std::cout << "\n";
            start_receiving_heartbeat(); 
          }
          else
          {
            std::cout << "Heartbeat failed: " << error.message() << "\n";
          }
        });
  }

  boost::asio::ssl::stream<tcp::socket> socket_;
  char request_[max_length];
  char reply_[max_length];
  char heartbeat_[10]; // Buffer to store heartbeat messages
  bool handshake_completed_;
  std::thread heartbeat_thread_; // Thread for receiving heartbeat messages
};


int main(int argc, char* argv[])
{
  try
  {
    if (argc != 3)
    {
      std::cerr << "Usage: client <host> <port>\n";
      return 1;
    }

    boost::asio::io_context io_context;
    char message[max_length];
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(argv[1], argv[2]);

    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    ctx.load_verify_file("../../cert/ssi.crt");//"ca.pem");
    //ctx.set_verify_mode(boost::asio::ssl::verify_none);

    client c(io_context, ctx, endpoints);
    std::future<void> input_thread = std::async(std::launch::async, [&]() {
      while(true){
      //std::cout << "Enter message: ";
      std::cin.getline(message, max_length);
      //flag = true;
      size_t request_length = std::strlen(message);

      c.send_request_from_main(message, request_length);
      }
    });
    io_context.run();

   
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
