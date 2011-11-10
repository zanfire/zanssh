/******************************************************************************
 * Copyright 2011 Matteo Valdina
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/

#include "zSocketTCPServer.h"

#include "zLogger.h"
#include "zSocketAddress.h"
#include "zSocketTCPConnection.h"
#include "zSocketAddressIPv4.h"
#include "zSocketAddressIPv6.h"
#include "zSocketTCPServerListener.h"

#include <errno.h>
#include <netinet/in.h>

zSocketTCPServer::zSocketTCPServer(void) : zSocketTCP(), zRunnable() {
  _thread = new zThread(this);
}


zSocketTCPServer::~zSocketTCPServer(void) {
}


zSocketBase::SocketError zSocketTCPServer::listen() {
  //cat /proc/sys/net/core/somaxconn
  int result = ::listen(_desc, 128);
  return result == 0 ? SOCKET_OK : SOCKET_ERROR_GENERIC;
}


zSocketTCPConnection* zSocketTCPServer::accept(void) {
  sockaddr fromAddr;
  socklen_t fromAddrLen;
  int res = ::accept(_desc, &fromAddr, &fromAddrLen);
  if (res >= 0) {
   if (_bindAddress->getType() == zSocketAddress::ADDRESS_TYPE_IPv4) {
      sockaddr_in* addr = (sockaddr_in*)&fromAddr;
      zSocketAddressIPv4 zaddr(*addr);
      return new zSocketTCPConnection(this, &zaddr);
    }
    else {
      sockaddr_in6* addr = (sockaddr_in6*)&fromAddr;
      zSocketAddressIPv6 zaddr(addr->sin6_addr);
      return new zSocketTCPConnection(this, &zaddr);
    }
  }
  return NULL;
}


int zSocketTCPServer::run(void* param) {

  /*zSocketBase::SocketError error = _serverSocket.listen();
  if (error != zSocketBase::SOCKET_OK) {
    _logger->fatal("listen failed!");
   }

  while (true) {
    zSocketTCPConnection* connection = _serverSocket.accept();
    if (connection == NULL) {
      _logger->warn("Socket accept is failed due to an unspecified error condition.")
    }
    else {
      //
      SSHTransport* transport = new SSHTransport(connection);
      transport->initialize();
      _activeTransports.append(transport);
    }
  }*/

  return 0;
}
