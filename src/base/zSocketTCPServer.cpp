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
#include "zThread.h"
#include "zScopeMutex.h"
#include "zSocketAddress.h"
#include "zSocketTCPConnection.h"
#include "zSocketAddressIPv4.h"
#include "zSocketAddressIPv6.h"
#include "zSocketTCPServerListener.h"
#include "zSocketTCPClient.h"

#include <errno.h>
#include <netinet/in.h>

zSocketTCPServer::zSocketTCPServer(void) : zSocketTCP(), zRunnable() {
  _listener = NULL;
  _mustStop = false;
  _socketListening = false;
  _thread = new zThread(this);
}


zSocketTCPServer::~zSocketTCPServer(void) {
  setListener(NULL);
  stopListen();
}


void zSocketTCPServer::setListener(zSocketTCPServerListener* listener) {
  zScopeMutex scope(_mtx);
  if (_listener != NULL) _listener->releaseReference();
  _listener = listener;
  if (_listener != NULL) _listener->acquireReference();
}


zSocketBase::SocketError zSocketTCPServer::startListen() {
  int res = -1;
  if (!_socketListening) {
    //cat /proc/sys/net/core/somaxconn
    res = ::listen(_desc, 128);
    if (res == 0) _socketListening = true;
  }
  if (!_thread->isRunning()) _thread->start(NULL);
  return res == 0 ? SOCKET_OK : SOCKET_ERROR_GENERIC;
}


zSocketBase::SocketError zSocketTCPServer::stopListen() {
  if (!_thread->isRunning()) {
    _mustStop = true;
    shutdown(_desc, SHUT_RDWR);
    _thread->stop();
  }
  return _socketListening ? SOCKET_OK : SOCKET_ERROR_GENERIC;
}


zSocketTCPConnection* zSocketTCPServer::accept(void) {
  sockaddr fromAddr;
  socklen_t fromAddrLen;
  int res = ::accept(_desc, &fromAddr, &fromAddrLen);
  if (res >= 0) {
    //zSocketTCPClient* client =
    return new zSocketTCPConnection(new zSocketTCPClient((SOCKET_DESC)res, _bindAddress, fromAddr, fromAddrLen));
  }
  return NULL;
}


int zSocketTCPServer::run(void* param) {
  _mtx.lock();
  if (_listener != NULL) _listener->onStartListening();
  _mtx.unlock();

  while (!_mustStop) {
    // Blocking.
    zSocketTCPConnection* connection = accept();
    if (connection == NULL) {
      //_logger->warn("Socket accept is failed due to an unspecified error condition.");
      continue;
    }

    _mtx.lock();
    if (_listener != NULL) _listener->onAccept(connection);
    _mtx.unlock();
    connection->releaseReference();
  }
  _mtx.lock();
  if (_listener != NULL) _listener->onStopListening();
  _mtx.unlock();

  return 0;
}
