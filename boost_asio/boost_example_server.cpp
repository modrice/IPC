//
// server.cpp
// ~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
using boost::asio::ip::tcp;

class session : public std::enable_shared_from_this<session>
{
public:
  session(tcp::socket socket, boost::asio::ssl::context& context)
    : socket_(std::move(socket), context), heartbeat_timer_(socket.get_executor()) 
  {
  }

  void start()
  {
    do_handshake();
    start_heartbeat();
  }

private:
  void do_handshake()
  {
    auto self(shared_from_this());
    socket_.async_handshake(boost::asio::ssl::stream_base::server, 
        [this, self](const boost::system::error_code& error)
        {
          if (!error)
          {
            do_read();
          }
        });
  }

  void do_read()
  {
    auto self(shared_from_this());
    socket_.async_read_some(boost::asio::buffer(data_),
        [this, self](const boost::system::error_code& ec, std::size_t length)
        {
          if (!ec)
          {
            std::cout << "Echo: ";
            std::cout.write(data_, length);
            std::cout << "\n";
            //do_write(length);
            do_read();
          }
        });
  }

  void do_write(std::size_t length)
  {
    auto self(shared_from_this());
    boost::asio::async_write(socket_, boost::asio::buffer(data_, length),
        [this, self](const boost::system::error_code& ec,
          std::size_t /*length*/)
        {
          if (!ec)
          {
            do_read();
          }
        });
  }


  void start_heartbeat()
  {
    auto self(shared_from_this());
    heartbeat_timer_.expires_from_now(boost::posix_time::seconds(3));

    heartbeat_timer_.async_wait([this, self](const boost::system::error_code& error)
        {
            if (!error)
            {
                start_heartbeat();
                send_heartbeat(error);
            }
        });
  }

  void send_heartbeat(const boost::system::error_code& /*error*/)
  {
    if (!socket_.lowest_layer().is_open())
      return;
    std::cout<<"send heartbaet"<<std::endl;
    boost::asio::async_write(socket_, boost::asio::buffer("heartbeat\n", 10),
        [this](const boost::system::error_code& /*ec*/, std::size_t /*length*/)
        {
          //start_heartbeat();
        });
  }


  boost::asio::ssl::stream<tcp::socket> socket_;
  char data_[1024];
  boost::asio::deadline_timer heartbeat_timer_;
};

class server
{
public:
  server(boost::asio::io_context& io_context, unsigned short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
      context_(boost::asio::ssl::context::sslv23)
  {
    context_.set_options(
        boost::asio::ssl::context::default_workarounds
        | boost::asio::ssl::context::no_sslv2
        | boost::asio::ssl::context::single_dh_use);
    context_.set_password_callback(std::bind(&server::get_password, this));
    context_.use_certificate_chain_file("../../cert/ssi.crt");//"server.pem");
    context_.use_private_key_file("../../cert/ssi.key",boost::asio::ssl::context::pem);//"server.pem", boost::asio::ssl::context::pem);
    context_.use_tmp_dh_file("../../cert/ssi.dh2048");//"dh2048.pem");
   // _timer.expires_at(boost::posix_time::pos_infin);
    do_accept();
  }

private:
  std::string get_password() const
  {
    return "test";
  }

  void do_accept()
  {
    //std::cout<<"a waith accept"<<std::endl;
    acceptor_.async_accept(
        [this](const boost::system::error_code& error, tcp::socket socket)
        {
          if (!error)
          {
            //std::cout<<"accepted"<<std::endl;
            std::make_shared<session>(std::move(socket), context_)->start();

          }

          do_accept();
        });
  }

  tcp::acceptor acceptor_;
  boost::asio::ssl::context context_;
};

int main(int argc, char* argv[])
{
  try
  {
    if (argc != 2)
    {
      std::cerr << "Usage: server <port>\n";
      return 1;
    }

    boost::asio::io_context io_context;

    using namespace std; // For atoi.
    server s(io_context, atoi(argv[1]));

    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}
