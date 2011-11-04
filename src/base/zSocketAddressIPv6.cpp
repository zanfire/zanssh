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

#include "zSocketAddressIPv6.h"

#include <string.h>
#include <arpa/inet.h>


zSocketAddressIPv6::zSocketAddressIPv6(in6_addr address) : zSocketAddress(ADDRESS_TYPE_IPv6) {
  memset(&_sockaddr, 0x0, sizeof(sockaddr_in6));
  _sockaddr.sin6_family = AF_INET6;
  _sockaddr.sin6_addr = address;
}


zSocketAddressIPv6::~zSocketAddressIPv6(void) {
}

zSocketAddress* zSocketAddressIPv6::clone(void) const {
  return new zSocketAddressIPv6(_sockaddr.sin6_addr);
}

sockaddr* zSocketAddressIPv6::getSocketAddr(void) const {
  return (sockaddr*)&_sockaddr;
}


zString zSocketAddressIPv6::getAddressAsString(void) const {

  char dst[1024];
  char const* res = inet_ntop(AF_INET6, (void*)&(_sockaddr.sin6_addr), dst, 1024);
  if (res != NULL) {
    return zString(res);
  }
  return zString("");
}
