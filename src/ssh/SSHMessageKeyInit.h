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

#ifndef SSHMESSAGEKEYINIT_H__
#define SSHMESSAGEKEYINIT_H__

#include "SSHMessage.h"

#include "zString.h"
#include "zVectorString.h"


#define SSH_MSG_KEXINIT_COOKIE_SIZE 16

/*
 *  byte SSH_MSG_KEXINIT
 *  byte[16] cookie (random bytes)
 *  name-list kex_algorithms
 *  name-list server_host_key_algorithms
 *  name-list encryption_algorithms_client_to_server
 *  name-list encryption_algorithms_server_to_client
 *  name-list mac_algorithms_client_to_server
 *  name-list mac_algorithms_server_to_client
 *  name-list compression_algorithms_client_to_server
 *  name-list compression_algorithms_server_to_client
 *  name-list languages_client_to_server
 *  name-list languages_server_to_client
 *  boolean first_kex_packet_follows
 *  uint32 0 (reserved for future extension)
 */
class SSHMessageKeyInit : public SSHMessage {

public:
  SSHMessageKeyInit(unsigned char* buffer, int bufferSize);
  virtual ~SSHMessageKeyInit(void);

  //
  // Setter
  //

  // name-list kex_algorithms
  bool setKexAlgorithms(zVectorString const& v);
  // name-list server_host_key_algorithms
  bool setServerHostKeyAlgorithms(zVectorString const& v);
  // name-list encryption_algorithms_client_to_server
  bool setEncryptionAlgorithmsClientToServer(zVectorString const& v);
  // name-list encryption_algorithms_server_to_client
  bool setEncryptionAlgorithmsServerToClient(zVectorString const& v);
  // name-list mac_algorithms_client_to_server
  bool setMacAlgorithmsClientToServer(zVectorString const& v);
  // name-list mac_algorithms_server_to_client
  bool setMacAlgorithmsServerToClient(zVectorString const& v);
  // name-list compression_algorithms_client_to_server
  bool setCompressionAlgorithmsClientToServer(zVectorString const& v);
  // name-list compression_algorithms_server_to_client
  bool setCompressionAlgorithmsServerToClient(zVectorString const& v);
  // name-list languages_client_to_server
  bool setLanguagesClientToServer(zVectorString const& v);
  // name-list languages_server_to_client
  bool setLanguagesServerToClient(zVectorString const& v);
  // boolean first_kex_packet_follows
  bool setFirstKexPacketFollows(bool v);
  // uint32 0 (reserved for future extension)
  bool setReserved(uint32_t v);

  //
  // Getter
  //

  // name-list kex_algorithms
  zVectorString getKexAlgorithms(void) const;
  // name-list server_host_key_algorithms
  zVectorString getServerHostKeyAlgorithms(void) const;
  // name-list encryption_algorithms_client_to_server
  zVectorString getEncryptionAlgorithmsClientToServer(void) const;
  // name-list encryption_algorithms_server_to_client
  zVectorString getEncryptionAlgorithmsServerToClient(void) const;
  // name-list mac_algorithms_client_to_server
  zVectorString getMacAlgorithmsClientToServer(void) const;
  // name-list mac_algorithms_server_to_client
  zVectorString getMacAlgorithmsServerToClient(void) const;
  // name-list compression_algorithms_client_to_server
  zVectorString getCompressionAlgorithmsClientToServer(void) const;
  // name-list compression_algorithms_server_to_client
  zVectorString getCompressionAlgorithmsServerToClient(void) const;
  // name-list languages_client_to_server
  zVectorString getLanguagesClientToServer(void) const;
  // name-list languages_server_to_client
  zVectorString getLanguagesServerToClient(void) const;
  // boolean first_kex_packet_follows
  bool getFirstKexPacketFollows(void) const;
  // uint32 0 (reserved for future extension)
  uint32_t getReserved(void) const;

  zString toString(void) const;
};

#endif // SSHMESSAGEKEYINIT_H__
