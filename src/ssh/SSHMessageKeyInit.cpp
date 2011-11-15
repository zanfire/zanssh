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

#include <arpa/inet.h>

SSHMessageKeyInit::SSHMessageKeyInit(unsigned char* buffer, int bufferSize) : SSHMessage(buffer, bufferSize) {
}


SSHMessageKeyInit::~SSHMessageKeyInit(void) {
}


bool SSHMessageKeyInit::setKexAlgorithms(zVectorString const& v) {
  zString kex = v.toString(zString(","));

  setPacketLength(getPacketLength() + kex.getLength() + 4);

  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    return false;
  }
  // Skip cookies.
  SSHMessage::skipBytes(SSH_MSG_KEXINIT_COOKIE_SIZE, &message, messageSize);

  return false;
}


bool SSHMessageKeyInit::setServerHostKeyAlgorithms(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setEncryptionAlgorithmsClientToServer(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setEncryptionAlgorithmsServerToClient(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setMacAlgorithmsClientToServer(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setMacAlgorithmsServerToClient(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setCompressionAlgorithmsClientToServer(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setCompressionAlgorithmsServerToClient(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setLanguagesClientToServer(zVectorString const& v) {
  return false;
}


bool SSHMessageKeyInit::setLanguagesServerToClient(zVectorString const& v) {
  return false;
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
      zString str = zString::fromPascalString(message, messageSize);
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
  SSHMessage::skipBytes(1, &message, messageSize);

  if (message != NULL && messageSize == 4) {
    return ntohl(((uint32_t*)message)[0]);
  }
  return 0;

  return 0;
}


zString SSHMessageKeyInit::toString(void) const {
  zStringBuffer strb;
  strb.appendFormatted("Kex algorithms: [ %s ]\n", getKexAlgorithms().toString(", ").getBuffer());
  strb.appendFormatted("Server host key algorithms: [ %s ]\n", getServerHostKeyAlgorithms().toString(", ").getBuffer());
  strb.appendFormatted("Encryption Algorithms Client To Server: [ %s ]\n", getEncryptionAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Encryption Algorithms Server To Client: [ %s ]\n", getEncryptionAlgorithmsServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("Mac Algorithms Client To Server: [ %s ]\n", getMacAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Compression Algorithms Client To Server: [ %s ]\n", getCompressionAlgorithmsClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Compression Algorithms Server To Client: [ %s ]\n", getCompressionAlgorithmsServerToClient().toString(", ").getBuffer());
  strb.appendFormatted("Languages Client To Server: [ %s ]\n", getLanguagesClientToServer().toString(", ").getBuffer());
  strb.appendFormatted("Languages Server To Client: [ %s ]\n", getLanguagesServerToClient().toString(", ").getBuffer());

  return strb.toString();
}
