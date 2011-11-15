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

#ifndef SSHSERVER_H_
#define SSHSERVER_H_

#include "global.h"
#include "zObject.h"
#include "zSocketAddress.h"
#include "zRunnable.h"
#include "zVector.h"
#include "zSocketTCPServer.h"
#include "zSocketTCPServerListener.h"


class zThread;
class zLogger;

class SSHServer : public zSocketTCPServerListener, virtual public zObject {
protected:
  zLogger* _logger;
  zSocketTCPServer _serverSocket;
  zVector _transports;

public:
  static SSHServer* createSSHServer(zSocketAddress const& bindAddress);

  void start(void);
  void stop(void);

  virtual void onAccept(zSocketTCPConnection* connection);

protected:
  SSHServer(void);
  virtual ~SSHServer(void);
};

#endif // SSHSERVER_H_
