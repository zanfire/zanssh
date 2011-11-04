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

#include "zSocketAddressIPv4.h"

#include "zStringBuffer.h"

#include <string.h>
#include <arpa/inet.h>


zSocketAddressIPv4::zSocketAddressIPv4(uint32_t address, uint16_t port) : zSocketAddress(ADDRESS_TYPE_IPv4) {
  memset(&_sockaddr, 0x0, sizeof(sockaddr_in));
  _sockaddr.sin_family = AF_INET;
  _sockaddr.sin_addr.s_addr = htonl(address);
  _sockaddr.sin_port = htons(port);
}


zSocketAddressIPv4::zSocketAddressIPv4(sockaddr_in const& addr) : zSocketAddress(ADDRESS_TYPE_IPv4) {
  memset(&_sockaddr, 0x0, sizeof(sockaddr_in));
  _sockaddr.sin_family = AF_INET;
  _sockaddr.sin_addr = addr.sin_addr;
  _sockaddr.sin_port = addr.sin_port;
}

zSocketAddressIPv4::~zSocketAddressIPv4(void) {
}

zSocketAddress* zSocketAddressIPv4::clone(void) const {
  return new zSocketAddressIPv4(_sockaddr);
}

sockaddr* zSocketAddressIPv4::getSocketAddr(void) const {
  return (sockaddr*)&_sockaddr;
}


zString zSocketAddressIPv4::getAddressAsString(void) const {

  char dst[1024];
  char const* res = inet_ntop(AF_INET, (void*)&(_sockaddr.sin_addr), dst, 1024);
  if (res != NULL) {
    zStringBuffer strb;
    strb.append(res);
    strb.append(':');
    strb.append(ntohs(_sockaddr.sin_port));
    return strb.toString();
  }
  return zString("");
}
