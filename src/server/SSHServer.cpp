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
#include "zThread.h"


SSHServer::SSHServer(void) : zObject(), zSocketTCPServerListener() {
  _logger = zLogger::getLogger("SSHServer");
  _serverSocket.setListener(this);
}


SSHServer::~SSHServer(void) {
  stop();
  // TODO: Clean-up of SSHTransactions.
  _serverSocket.setListener(NULL);
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
  _serverSocket.startListen();
}


void SSHServer::stop(void) {
  _serverSocket.stopListen();
}


void SSHServer::onAccept(zSocketTCPConnection* connection) {
  SSHTransport* transport = new SSHTransport(connection, true);
  _transports.append(transport);
}
