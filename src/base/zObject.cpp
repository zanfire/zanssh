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

#include "zObject.h"

#include "zLogger.h"

zObject::zObject() : _reference() {
}


zObject::~zObject(void) {
  if (getReferenceCount() > 1) {
    CHECK_FATAL(-1, "Deleting object that is still in use.");
  }
}


bool zObject::equals(zObject* obj) const {
  return this == obj;
}


void zObject::acquireReference(void) {
  _reference.increment();
}


void zObject::releaseReference(void) {
  _reference.decrement();
  if (getReferenceCount() == 0) {
    delete this;
  }
}
