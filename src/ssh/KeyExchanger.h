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

#ifndef KEYEXCHANGER_H__
#define KEYEXCHANGER_H__

#include "global.h"
#include "zObject.h"
#include "SSHMessage.h"
#include "zMutex.h"


class KeyExchangerListener;

class KeyExchanger : public zObject {
protected:
  zMutex _mtx;
  bool _isServer;
  KeyExchangerListener* _listener;

public:
  KeyExchanger(void);
  virtual ~KeyExchanger(void);

  void promoteToClient(void) { _isServer = false; }

  void setListener(KeyExchangerListener* listener);

  virtual void onReceivedSSHMessage(SSHMessage const& msg) = 0;
};

#endif // KEYEXCHANGER_H__
