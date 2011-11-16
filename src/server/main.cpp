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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "zSocketAddress.h"
#include "zSocketAddressIPv4.h"
#include "zLogger.h"
#include "SSHServer.h"

zLogger* g_logger = NULL;

void showCopyright(char* programName);
void handleInvalidArg(char* programName, char invalidArg);
void showHelp(char* programName);
zString handleAddress(char* programName, char* value);
int handlePort(char* programName, char const* value);


int main(int argc, char** argv) {
  g_logger = zLogger::getLogger("main");
  int opt;

  int localPort = -1;
  zString addressStr;
  zSocketAddress* localAddress = NULL;

  while ((opt = getopt(argc, argv, "hva:p:")) != -1) {
    switch (opt) {
    case 'h':
      showHelp(argv[0]);
      exit(EXIT_SUCCESS);
      break;
    case 'v':
      showCopyright(argv[0]);
      exit(EXIT_SUCCESS);
      break;
    case 'a':
      addressStr = handleAddress(argv[0], optarg);
      break;
    case 'p':
      localPort = handlePort(argv[0], optarg);
      break;
    default:
      handleInvalidArg(argv[0], opt);
      exit(EXIT_FAILURE);
    }
  }

  showCopyright(argv[0]);

  if (localPort <= 0) {
    localPort = 22;
  }
  g_logger->info("Configured local port to %d", localPort);

  if (addressStr.getLength() == 0) {
    addressStr = "127.0.0.1";
  }

  localAddress = zSocketAddressIPv4::createSocketAddressFromString(addressStr, localPort);
  g_logger->info("Configured local address to %s", localAddress->getAddressAsString().getBuffer());



  SSHServer* server = SSHServer::createSSHServer(*localAddress);
  if (server == NULL) {
    g_logger->fatal("Failed to create SSH server.");
    exit(EXIT_FAILURE);
  }

  server->start();

  printf("Press 'q' to terminate process.\n");
  char c = 0;
  while ((c = getchar()) != 'q') {
    // Nope
  }
  server->stop();
  return 0;
}


void showCopyright(char* programName) {
  printf("%s server version %s\n", programName, PACKAGE_VERSION);
  printf("Copyright 2009-2011 Matteo Valdina (bugs: %s)\n", PACKAGE_BUGREPORT);
}


void handleInvalidArg(char* programName, char invalidArg) {
  printf("Try '%s -h' for more information.\n", programName);
}


void showHelp(char* programName) {
  printf("Usage: %s [OPTION]...\n", programName);
  printf("TODO: descriptions.\n");
  printf("  -a ADDRESS  local address\n");
  printf("  -p PORT     local port\n");
  printf("  -v          output version information and exit\n");
  printf("\n");
  printf("Report %s bugs to %s.\n", programName, PACKAGE_BUGREPORT);
}


zString handleAddress(char* programName, char* value) {
  return zString(value);
}


int handlePort(char* programName, char const* value) {

  char* endptr;
  errno = 0; // To distinguish success/failure after call.
  int intValue = strtol(value, &endptr, 10);
  if ((errno == ERANGE && (intValue == LONG_MAX || intValue == LONG_MIN))
      || (errno != 0 && intValue == 0) || (*endptr != 0)) {
    g_logger->error("Invalid local port, (argument %s).", value);
    return -1;
  }
  return intValue;
}
