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

#include "zSocketTCPClient.h"

#include "zSocketAddressIPv4.h"
#include "zSocketAddressIPv6.h"


zSocketTCPClient::zSocketTCPClient(SOCKET_DESC desc, zSocketAddress* localAddress, sockaddr const& fromAddr, socklen_t fromAddrLen) : zSocketTCP() {
  _desc = desc;
  // TODO: wrong!!
  _bindAddress = localAddress->clone();
  if (localAddress->getType() == zSocketAddress::ADDRESS_TYPE_IPv4) {
    sockaddr_in* addr = (sockaddr_in*)&fromAddr;
    _remoteAddress = new zSocketAddressIPv4(*addr);
  }
  else {
    sockaddr_in6* addr = (sockaddr_in6*)&fromAddr;
    _remoteAddress = new zSocketAddressIPv6(addr->sin6_addr);
  }
}


zSocketTCPClient::~zSocketTCPClient(void) {
}

