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

#ifndef SOCKETTCP_H__
#define SOCKETTCP_H__

#include "global.h"
#include "zSocketIP.h"


class zSocketTCP : public zSocketIP {
protected:

public:
  zSocketTCP(void);
  virtual ~zSocketTCP(void);

  bool enableReuseAddress(bool enable);

protected:
  virtual SocketError impl_bind(void);
  virtual SocketError impl_create(void);
  virtual SocketError impl_close(void);
};

#endif // SOCKETTCP_H__
