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

#ifndef ZSOCKETADDRESSIPv6_H__
#define ZSOCKETADDRESSIPv6_H__

#include "global.h"
#include "zSocketAddress.h"

#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

#include <netinet/in.h>


class zSocketAddressIPv6 : public zSocketAddress {
protected:
  sockaddr_in6 _sockaddr;


public:
  zSocketAddressIPv6(in6_addr address);
  virtual ~zSocketAddressIPv6(void);

  virtual zSocketAddress* clone(void) const;

  virtual sockaddr* getSocketAddr(void) const;
  virtual int getSocketAddrLen(void) const { return sizeof(_sockaddr); }

  virtual zString getAddressAsString(void) const;
};


#endif // ZSOCKETADDRESSIPv6_H__
