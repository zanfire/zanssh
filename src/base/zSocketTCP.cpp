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

#include "zSocketTCP.h"
#include "zLogger.h"

#include <errno.h>


#if defined(_WIN32)
#endif

#if HAVE_SYS_SOCKET_H
  #include <sys/socket.h>
#endif

#if HAVE_SYS_TYPES_H
  #include <sys/types.h>
#endif


zSocketTCP::zSocketTCP(void) : zSocketIP(SOCKET_TYPE_TCP) {
}


zSocketTCP::~zSocketTCP(void) {
}


zSocketBase::SocketError zSocketTCP::impl_bind(void) {
  if (_desc == INVALID_DESCRIPTOR) return SOCKET_ERROR_CREATE_DESC;
  if (_bindAddress->getType() != zSocketAddress::ADDRESS_TYPE_IPv4 &&
      _bindAddress->getType() != zSocketAddress::ADDRESS_TYPE_IPv6) {
    return SOCKET_ERROR_INVALID_ADDRESS;
  }


  int res = bind(_desc, _bindAddress->getSocketAddr(), _bindAddress->getSocketAddrLen());
  if (res == 0) {
    return SOCKET_OK;
  }
  else {
    if (errno == EADDRINUSE) return SOCKET_ERROR_BINDTO_ADDRESS_ALREADY_IN_USE;
    if (errno == EACCES) return SOCKET_ERROR_BINDTO_NO_PERMISSION;
    return SOCKET_ERROR_BINDTO;
  }
}


zSocketBase::SocketError zSocketTCP::impl_create(void) {
  int domain = -1;
  if (_bindAddress->getType() == zSocketAddress::ADDRESS_TYPE_IPv4) {
    domain = AF_INET;
  }
  else if (_bindAddress->getType() == zSocketAddress::ADDRESS_TYPE_IPv6) {
    domain = AF_INET6;
  }
  else {
    return SOCKET_ERROR_INVALID_ADDRESS;
  }

  _desc = socket(domain, SOCK_STREAM, 0);
  enableReuseAddress(true);
  return SOCKET_OK;
}


zSocketBase::SocketError zSocketTCP::impl_close(void) {
  int ret = shutdown(_desc, SHUT_RDWR);
  if (ret == -1) {
    // TODO: Handle errors.
  }
  return SOCKET_OK;
}


bool zSocketTCP::enableReuseAddress(bool enable) {
  if (_desc == INVALID_DESCRIPTOR) return false;

  int on = enable ? 1 : 0;
  int ret = setsockopt(_desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

  return (ret == 0);
}
