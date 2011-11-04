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



SSHMessageKeyInit::SSHMessageKeyInit(unsigned char* buffer, int bufferSize) : SSHMessage(buffer, bufferSize) {
}


SSHMessageKeyInit::~SSHMessageKeyInit(void) {
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
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
      zString str = zString::fromPascalString(message, messageSize - 17);
      return zStringTokenizer::split(str, ",");
  }
  else {
    return zVectorString();
  }
}


bool SSHMessageKeyInit::getFirstKexPacketFollows(void) const {
  return false;
}


uint32_t SSHMessageKeyInit::getReserved(void) const {
  return 0;
}
