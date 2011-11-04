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

#ifndef SOCKETTCPCONNECTION_H__
#define SOCKETTCPCONNECTION_H__

#include "global.h"
#include "zSocketTCP.h"


class zSocketAddress;

class zSocketTCPConnection : public zObject {
protected:
  SOCKET_DESC _desc;
  zSocketAddress* _localAddr;
  int _localPort;
  zSocketAddress* _remoteAddr;
  int _remotePort;

public:
  zSocketTCPConnection(SOCKET_DESC desc, zSocketAddress* localAddr, zSocketAddress* remoteAddr);

  virtual ~zSocketTCPConnection(void);

  int writeBytes(unsigned char* buffer, int bufferSize);
  int readBytes(unsigned char* buffer, int bufferSize);

  bool isValid(void) { return true; }
};

#endif // SOCKETTCPCONNECTION_H__
