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

#ifndef ZSOCKETBASE_H__
#define ZSOCKETBASE_H__

#include "global.h"
#include "zObject.h"
#include "zSocketAddress.h"


#if defined(_WIN32)
  #define SOCKET_DESC void*
#elif HAVE_SYS_SOCKET_H
  #include <sys/socket.h>

  #define SOCKET_DESC int
#endif

#define INVALID_DESCRIPTOR -1

class zSocketBase : public zObject {
public:
  enum SocketType {
    SOCKET_TYPE_IP,   // Allow?
    SOCKET_TYPE_TCP,  //
    SOCKET_TYPE_UDP
  };

  enum SocketError {
    SOCKET_OK                     = 0,
    SOCKET_ERROR_NOMEM,
    SOCKET_ERROR_GENERIC,
    SOCKET_ERROR_CREATE_DESC,
    SOCKET_ERROR_BINDTO,
    SOCKET_ERROR_BINDTO_ADDRESS_ALREADY_IN_USE,
    SOCKET_ERROR_BINDTO_NO_PERMISSION,
    SOCKET_ERROR_INVALID_ADDRESS,
  };

protected:
  SocketType _type;
  SOCKET_DESC _desc;
  zSocketAddress* _bindAddress;

public:
  zSocketBase(SocketType type);
  virtual ~zSocketBase(void);

  SocketError bindTo(zSocketAddress const& address);

  SocketType getType(void) const { return _type; }
  SOCKET_DESC getDescriptor(void) const { return _desc; }

  static char const* getErrorDescription(SocketError error);

protected:
  virtual SocketError impl_bind(void) = 0;
  virtual SocketError impl_createSocket(SOCKET_DESC& desc) = 0;

};

#endif // ZSOCKETBASE_H__
