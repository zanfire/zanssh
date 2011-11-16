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

#include "SSHMessageKeyInit.h"

#include "zStringBuffer.h"
#include "zStringTokenizer.h"

#include "zRandom.h"

#include <arpa/inet.h>

SSHMessageKeyInit::SSHMessageKeyInit(unsigned char* buffer, int bufferSize) : SSHMessage(buffer, bufferSize) {
}


SSHMessageKeyInit::~SSHMessageKeyInit(void) {
}


void SSHMessageKeyInit::impl_initPacket(void) {
  SSHMessage::impl_initPacket();
  setMessageType(SSHMessage::SSH_MSG_KEXINIT);


  uint8_t cookie[SSH_MSG_KEXINIT_COOKIE_SIZE];
  zRandom* rand = zRandom::getSingleton();
  for (int i = 0; i < SSH_MSG_KEXINIT_COOKIE_SIZE; i++) {
    cookie[i] = rand->nextInt();
  }
  appendPayload((unsigned char*)(&cookie), SSH_MSG_KEXINIT_COOKIE_SIZE);

  char tmp[] = { 0x00, 0x00, 0x00, 0x00};
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list kex_algorithms
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list server_host_key_algorithms
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list encryption_algorithms_client_to_server
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list encryption_algorithms_server_to_client
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list mac_algorithms_client_to_server
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list mac_algorithms_server_to_client
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list compression_algorithms_client_to_server
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list compression_algorithms_server_to_client
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list languages_client_to_server
  appendPayload((unsigned char*)(&tmp), 4);
  // name-list languages_server_to_client
  appendPayload((unsigned char*)(&tmp), 4);
  // boolean first_kex_packet_follows
  appendPayload((unsigned char*)(&tmp), 1);
  // uint32 0 (reserved for future extension)
  appendPayload((unsigned char*)(&tmp), 4);

}


bool SSHMessageKeyInit::setKexAlgorithms(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  // Read current named list.
  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setServerHostKeyAlgorithms(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  // Read current named list.
  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setEncryptionAlgorithmsClientToServer(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setEncryptionAlgorithmsServerToClient(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setMacAlgorithmsClientToServer(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setMacAlgorithmsServerToClient(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setCompressionAlgorithmsClientToServer(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setCompressionAlgorithmsServerToClient(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setLanguagesClientToServer(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setLanguagesServerToClient(zVectorString const& v) {
  zString nameList = v.toString(zString(","));
  int payloadSize = -1;
  unsigned char* payload = getPayload(payloadSize);
  // types
  SSHMessage::skipBytes(1, &payload, payloadSize);
  // cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);
  SSHMessage::skipNameList(&payload, payloadSize);

  return replaceNameList(payload, nameList);
}


bool SSHMessageKeyInit::setFirstKexPacketFollows(bool v) {
  return false;
}


bool SSHMessageKeyInit::setReserved(uint32_t v) {
  return false;
}


zVectorString SSHMessageKeyInit::getKexAlgorithms(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);

  if (message != NULL && messageSize > 4) {
      zString str = zString::fromPascalString(message, messageSize, true);
      return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getServerHostKeyAlgorithms(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getEncryptionAlgorithmsClientToServer(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);


  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getEncryptionAlgorithmsServerToClient(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getMacAlgorithmsClientToServer(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getMacAlgorithmsServerToClient(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getCompressionAlgorithmsClientToServer(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);


  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);;
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getCompressionAlgorithmsServerToClient(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize > 4) {
      zString str = zString::fromPascalString(message, messageSize - 17);
      return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getLanguagesClientToServer(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);


  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


zVectorString SSHMessageKeyInit::getLanguagesServerToClient(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    // No KexAlgorimth
    return zVectorString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);


  if (message != NULL && messageSize > 4) {
    zString str = zString::fromPascalString(message, messageSize, true);
    return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


bool SSHMessageKeyInit::getFirstKexPacketFollows(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    return false;
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  if (message != NULL && messageSize >= 1) {
    return (message[0] == 0);
  }
  return false;
}


uint32_t SSHMessageKeyInit::getReserved(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    return 0;
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);
  SSHMessage::skipNameList(&message, messageSize);

  SSHMessage::skipBytes(1, &message, messageSize);


  if (message != NULL && messageSize == 4) {
    return ntohl(((uint32_t*)message)[0]);
  }
  return 0;

  return 0;
}


zString SSHMessageKeyInit::toString(void) const {
  zStringBuffer strb;
  strb.append(SSHPacket::toString());
  strb.appendFormatted("Kex algorithms: [ %s ]\n", getKexAlgorithms().toString(", ").getBuffer());
  strb.appendFormatted("Server host key algorithms: [ %s ]\n", getServerHostKeyAlgorithms().toString(", ").getBuffer());
  strb.appendFormatted("Encryption Algorithms Client To Server: [ %s ]\n", getEncryptionAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Encryption Algorithms Server To Client: [ %s ]\n", getEncryptionAlgorithmsServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("Mac Algorithms Client To Server: [ %s ]\n", getMacAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Mac Algorithms Server To Client: [ %s ]\n", getMacAlgorithmsServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("Compression Algorithms Client To Server: [ %s ]\n", getCompressionAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Compression Algorithms Server To Client: [ %s ]\n", getCompressionAlgorithmsServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("Languages Client To Server: [ %s ]\n", getLanguagesClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Languages Server To Client: [ %s ]\n", getLanguagesServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("first_kex_packet_follows: [ %s ]\n", getFirstKexPacketFollows() ? "true" : "false");
  strb.appendFormatted("Reserved: [ %d ]\n", getReserved());
  return strb.toString();
}
