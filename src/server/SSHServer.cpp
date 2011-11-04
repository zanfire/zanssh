/******************************************************************************
 * Copyright 2009-2011 Matteo Valdina
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

#include "SSHServer.h"

#include "zLogger.h"
#include "zSocketTCPConnection.h"
#include "SSHTransport.h"

SSHServer::SSHServer(void) : zRunnable(), _thread(this) {
  _logger = zLogger::getLogger("SSHServer");
}


SSHServer::~SSHServer(void) {
}


SSHServer* SSHServer::createSSHServer(zSocketAddress const& bindAddress) {
  zLogger* logger = zLogger::getLogger("SSHServer");
  SSHServer* server = new SSHServer();
  zSocketBase::SocketError error = server->_serverSocket.bindTo(bindAddress);
  if (error == zSocketBase::SOCKET_OK) {
    return server;
  }

  logger->error("Failed to create SSH server due the follow error: %s.", zSocketBase::getErrorDescription(error));
  return NULL;
}


void SSHServer::start(void) {
  _thread.start();
}


void SSHServer::stop(void) {

}


int SSHServer::run(void* param) {
  zSocketBase::SocketError error = _serverSocket.listen();
  if (error != zSocketBase::SOCKET_OK) {
    _logger->fatal("listen failed!");
   }

  while (_canRun) {
    zSocketTCPConnection* connection = _serverSocket.accept();

    if (connection == NULL) {
      _logger->debug("connection null!");
    }
    else {
      SSHTransport* transport = new SSHTransport(connection);
      transport->initialize();
      _activeTransports.append(transport);
    }
  }

  return 0;
}
