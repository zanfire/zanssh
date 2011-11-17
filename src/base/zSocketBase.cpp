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

#include "zSocketBase.h"


zSocketBase::zSocketBase(SocketType type) : zObject() {
  _type = type;
}


zSocketBase::~zSocketBase(void) {
}


zSocketBase::SocketError zSocketBase::bindTo(zSocketAddress const& address) {
  if (_desc != INVALID_DESCRIPTOR) {
    // Destroy socket descriptor and close socket.
  }
  _bindAddress = address.clone();
  SocketError res = impl_create();
  if (res != SOCKET_OK) return res;
  if (_desc == INVALID_DESCRIPTOR) {
    return SOCKET_ERROR_CREATE_DESC;
  }

  return impl_bind();
}


zSocketBase::SocketError zSocketBase::close(void) {
  if (_desc != INVALID_DESCRIPTOR) return SOCKET_ERROR_GENERIC;

  return impl_close();
}


char const* zSocketBase::getErrorDescription(zSocketBase::SocketError error) {
  switch (error) {
    case SOCKET_OK:                                     return "No error";
    case SOCKET_ERROR_NOMEM:                            return "No sufficient memory available";
    case SOCKET_ERROR_GENERIC:                          return "Undefined error";
    case SOCKET_ERROR_CREATE_DESC:                      return "Failed to create socket";
    case SOCKET_ERROR_BINDTO:                           return "Failed bind";
    case SOCKET_ERROR_BINDTO_ADDRESS_ALREADY_IN_USE:    return "Address already in use";
    case SOCKET_ERROR_BINDTO_NO_PERMISSION:             return "No permission bind address";
    case SOCKET_ERROR_INVALID_ADDRESS:                  return "Invalid address";
    default:                                            return "Unknown error";
  }
}
