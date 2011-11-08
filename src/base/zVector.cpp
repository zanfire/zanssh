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

#include "zVector.h"

#include <stdlib.h>

#include "zMutex.h"
#include "zScopeMutex.h"

zVector::zVector(bool threadSafe, int initialSize) : zObject() {
  _vector = (zObject**) malloc(sizeof(zObject*) * initialSize);
  _count = 0;
  _size = initialSize;
  _mtx = threadSafe ? new zMutex() : NULL;
}


zVector::~zVector(void) {
  free(_vector);
  delete _mtx;
}


zVector::zVector(const zVector& obj) {
  int initialSize = obj._size;
  _vector = (zObject**) malloc(sizeof(zObject*) * initialSize);
  _count = 0;
  _size = initialSize;
  _mtx = obj._mtx != NULL ? new zMutex() : NULL;

  copyFrom(obj);
}


zVector& zVector::operator=(zVector const& rhs) {
  zScopeMutex scope(_mtx);
  removeAll();
  if (this != &rhs) {
    copyFrom(rhs);
  }

  return *this;
}


void zVector::copyFrom(zVector const& vstr) {
  zScopeMutex scope(_mtx);
  for (int i = 0; i < vstr.getCount(); i++) {
    insertAt(i, vstr.getAt(i));
  }
}


void zVector::append(zObject* element) {
  zScopeMutex scope(_mtx);
  insertAt(getCount(), element);
}


void zVector::insertAt(int index, zObject* element) {
  zScopeMutex scope(_mtx);
  if (element == NULL) return;
  if (index < 0) return;
  if (_count == _size) {
    _size += VECTOR_SIZE_INCREMENT;
    _vector = (zObject**)realloc(_vector, _size * sizeof(zObject*));
  }
  
  for(int i = _count; i > index; i--) {
    _vector[i] = _vector[i - 1];
  }
  _vector[index] = element;
  _vector[index]->acquireReference();
  _count++;
}


zObject* zVector::removeAt(int index) {
  zScopeMutex scope(_mtx);
  if (index >= getCount()) return NULL;
  if (index < 0) return NULL;
  
  zObject* o = _vector[index];
  o->releaseReference();

  for(int i = index; i < _count -1; i++) {
    _vector[i] = _vector[i + 1];
  }
  _count--;
  return o;
}


void zVector::removeAll(void) {
  zScopeMutex scope(_mtx);

  for(int i = _count -1; i >= 0; i--) {
    _vector[i]->releaseReference();
    _vector[i] = NULL;
  }
  _count = 0;
}


zObject* zVector::getrAt(int index) const {
  zScopeMutex scope(_mtx);
  zObject* o = getAt(index);
  if (o != NULL) {
    o->acquireReference();
  }
  return o;
}


zObject* zVector::getAt(int index) const {
  zScopeMutex scope(_mtx);
  if (index < getCount()) {
    return _vector[index];
  }
  return NULL;
}


int zVector::contains(zObject* element) const {
  zScopeMutex scope(_mtx);
  for (int i = 0; i < _count; i++) {
    if (_vector[i]->equals(element)) {
      return i;
    }
  }
  return -1;
}
