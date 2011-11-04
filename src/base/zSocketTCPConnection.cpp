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

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

zSocketTCPConnection::zSocketTCPConnection(SOCKET_DESC desc,
    zSocketAddress* localAddr, zSocketAddress* remoteAddr) {
  _desc = desc;
  _localAddr = localAddr->clone();
  _remoteAddr = remoteAddr->clone();
}


zSocketTCPConnection::~zSocketTCPConnection(void) {
  _localAddr->releaseReference();
  _remoteAddr->releaseReference();
}


int zSocketTCPConnection::writeBytes(unsigned char* buffer, int bufferSize) {
  int res = send(_desc, buffer, bufferSize, 0);
    if (res == -1) {
      zLogger::getLogger("base")->info("Failed errno %d.", errno);
    }
    return res;
}


int zSocketTCPConnection::readBytes(unsigned char* buffer, int bufferSize) {
  int res = recv(_desc, buffer, bufferSize, 0);
  if (res == -1) {
    zLogger::getLogger("base")->info("Failed errno %d.", errno);
  }
  return res;
}
