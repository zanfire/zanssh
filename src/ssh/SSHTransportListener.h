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

#ifndef SSHTRANSPORTLISTENER_H__
#define SSHTRANSPORTLISTENER_H__

#include "global.h"
#include "zObject.h"
#include "SSHTransport.h"

class SSHTransportListener : virtual public zObject {

public:
  SSHTransportListener(void);
  virtual ~SSHTransportListener(void);

  virtual void onMessageReceived(unsigned char const* message, int messageSize) = 0;
  virtual void onSendError(int error) = 0;
  virtual void onDisconnected(SSHTransport::SSHTransportDisconnectedReason reason) = 0;

protected:

};

#endif // SSHTRANSPORTLISTENER_H__
