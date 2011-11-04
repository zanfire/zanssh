/******************************************************************************
 * Copyright 2009 Matteo Valdina
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

#ifndef ZSTRING_H__
#define ZSTRING_H__

#include "global.h"
#include "zObject.h"



#define STATIC_BUFFER_SIZE 1

class zVectorString;
class zStringBuffer;
class zBuffer;
class zBufferSegment;

/******************************************************************************
* Immutable String
******************************************************************************/
class zString : public zObject {

public:
  static zString* empty;
private:
  char _staticBuffer[STATIC_BUFFER_SIZE];
  zBuffer* _dynamicBuffer;
  int _length;

public:
  zString(void);
  zString(zBuffer* buffer);
  zString(zStringBuffer const* strb);
  zString(zString* str);
  zString(char c);
  zString(char const* str);
  zString(char const* str, int length);
  virtual ~zString(void);

  zString(const zString& obj);
  zString& operator=(const zString& rhs);

  zString substrig(int startPos, int endPos) const;
  int indexOf(zString& str, int startPos) const;
  int lastIndexOf(zString& str, int endPos) const;

  bool equals(zString const& str) const;
  int compareTo(zString const& str) const;
  
  char* getBuffer(void) const;
  int getLength(void) const { return _length; }

  static zString fromPascalString(unsigned char const* pascalString, int bufferSize, bool isInNetworkByteOrder = false);
private:
  void init(char const* str, int length);
  void copyFrom(const zString& str);
};

#endif // ZSTRING_H__
