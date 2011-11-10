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

#include "zVectorString.h"

#include "zScopeMutex.h"
#include "zMutex.h"
#include "zStringBuffer.h"

#include <stdlib.h>

zVectorString::zVectorString(bool threadSafe, int initialSize) : zVector(threadSafe, initialSize) {
}


zVectorString::~zVectorString(void) {
}

void zVectorString::append(zString const& element) {
  zScopeMutex scope(_mtx);
  insertAt(getCount(), element);
}


void zVectorString::insertAt(int index, zString const& element) {
  zScopeMutex scope(_mtx);
  zString* str = new zString(element);
  zVector::insertAt(index, str);
}


zString zVectorString::getAt(int index) const {
  zScopeMutex scope(_mtx);
  zString* ptr = getAtPtr(index);

  if (ptr != NULL) {
    return zString(ptr);
  }
  return zString();
}


zString* zVectorString::getAtPtr(int index) const {
  zScopeMutex scope(_mtx);
  return (zString*)zVector::getAt(index);
}


zString zVectorString::removeAt(int index) {
  zScopeMutex scope(_mtx);
  zString* ptr = (zString*)zVector::removeAt(index);

  if (ptr == NULL) {
    return zString();
  }
  else {
    zString str(ptr);
    delete ptr;
    return str;
  }
}


int zVectorString::contains(zString const& element) const {
  zScopeMutex scope(_mtx);
  for (int i = 0; i < _count; i++) {
    if (((zString*)_vector[i])->equals(element)) {
      return i;
    }
  }
  return -1;
}


zString zVectorString::toString(zString sep) const {
  zStringBuffer strb;
  for (int i = 0; i < _count; i++) {
    strb.append(*((zString*)_vector[i]));
    if (i < (_count - 1)) {
      strb.append(sep);
    }
  }
  return strb.toString();
}
