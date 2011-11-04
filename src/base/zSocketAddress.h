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

#ifndef ZSOCKETADDRESS_H__
#define ZSOCKETADDRESS_H__

#include "global.h"
#include "zObject.h"
#include "zString.h"

#if HAVE_INTTYPES_H
  #include <inttypes.h>
#endif

struct sockaddr;

/**
 * Astract definition of a socket address.
 */
class zSocketAddress : public zObject {
public:
  enum AddressType {
    ADDRESS_TYPE_IPv4,
    ADDRESS_TYPE_IPv6
  };

protected:
  AddressType _type;

public:
  zSocketAddress(AddressType type);
  virtual ~zSocketAddress(void);

  AddressType getType(void) { return _type; }

  virtual sockaddr* getSocketAddr(void) const = 0;
  virtual int getSocketAddrLen(void) const = 0;


  virtual zSocketAddress* clone(void) const = 0;
  virtual zString getAddressAsString(void) const = 0;

  static zSocketAddress* createSocketAddressFromString(zString const& str, int port);
};


#endif // ZSOCKETADDRESS_H__
