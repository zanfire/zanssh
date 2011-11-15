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

#include "zSocketAddress.h"

#include "zSocketAddressIPv4.h"
#include "zSocketAddressIPv6.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

zSocketAddress::zSocketAddress(AddressType type) {
  _type = type;
}


zSocketAddress::~zSocketAddress() {
}


zSocketAddress* zSocketAddress::createSocketAddressFromString(zString const& str, int port) {
  in_addr addr;
  int res = inet_pton(AF_INET, str.getBuffer(), &addr);
  if (res == 1) {
    return new zSocketAddressIPv4(ntohl(addr.s_addr), port);
  }
  in6_addr addr6;
  res = inet_pton(AF_INET6, str.getBuffer(), &addr6);
  if (res == 1) {
    return new zSocketAddressIPv6(addr6);
  }

  return NULL;
}
