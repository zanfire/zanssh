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

#include "zSocketTCPConnection.h"

#include "zLogger.h"
#include "zThread.h"
#include "zScopeMutex.h"
#include "zSocketTCPClient.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

zSocketTCPConnection::zSocketTCPConnection(zSocketTCPClient* socket) : zObject(), zRunnable() {
  _socket = socket;
  _socket->acquireReference();

  _mustStop = false;
  _thread = new zThread(this);
  _thread->start(NULL);
}


zSocketTCPConnection::~zSocketTCPConnection(void) {
  setListener(NULL);
  _thread->stop();
  _socket->releaseReference();
}


void zSocketTCPConnection::setListener(zSocketTCPConnectionListener* listener) {
  zScopeMutex scope(_mtx);
  if (_listener != NULL) _listener->releaseReference();
  _listener = listener;
  if (_listener != NULL) _listener->acquireReference();
}


int zSocketTCPConnection::writeBytes(unsigned char* buffer, int bufferSize) {
  int res = send(_socket->getDescriptor(), buffer, bufferSize, 0);
    if (res == -1) {
      if (EADDRINUSE)
      zLogger::getLogger("base")->info("Failed errno %d.", errno);
    }
    return res;
}


void zSocketTCPConnection::stop(void) {
  _socket->close();
}


int zSocketTCPConnection::run(void* param) {
  unsigned char buffer[64 * 1024];

  while (!_mustStop) {
    int readBytes = recv(_socket->getDescriptor(), buffer, sizeof(buffer), 0);
    if (readBytes > 0) {
      zScopeMutex scope(_mtx);
      if (_listener != NULL) _listener->onIncomingData(buffer, readBytes);
    }
    else {
      // Handle error.
      zLogger::getLogger("base")->info("Failed errno %d.", errno);

      //EAGAIN or EWOULDBLOCK
      //EBADF  The argument sockfd is an invalid descriptor.
      //ECONNREFUSED
      //EFAULT The receive buffer pointer(s) point outside the process's address space.
      //EINTR  The receive was interrupted by delivery of a signal before any data were available; see signal(7).
      //EINVAL Invalid argument passed.
      //ENOMEM Could not allocate memory for recvmsg().
      //ENOTCONN
      //ENOTSOCK
    }
  }
  return 0;
}
