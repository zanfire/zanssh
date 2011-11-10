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

#ifndef SOCKETTCPCONNECTIONLISTENER_H__
#define SOCKETTCPCONNECTIONLISTENER_H__

#include "global.h"
#include "zSocketTCPConnection.h"


class zSocketTCPConnectionListener : virtual public zObject {
public:
  zSocketTCPConnectionListener(void);
  virtual ~zSocketTCPConnectionListener(void);

  virtual void onIncomingData(unsigned char* buffer, int bufferSize) = 0;
  virtual void onDisconected(void) = 0;
};

#endif // SOCKETTCPCONNECTIONLISTENER_H__
