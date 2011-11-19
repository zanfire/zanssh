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

#ifndef KEYEXCHANGERLISTENER_H__
#define KEYEXCHANGERLISTENER_H__

#include "global.h"
#include "zObject.h"
#include "SSHMessage.h"

class KeyExchangerListener : virtual public zObject {

public:
  KeyExchangerListener(void);
  virtual ~KeyExchangerListener(void);

  virtual void onMessageGenerated(SSHMessage const& message) = 0;
  virtual void onKeyNegotiationCompleted(void) = 0;
  virtual void onKeyNegotiationFailed(void) = 0;
};

#endif // KEYEXCHANGERLISTENER_H__
