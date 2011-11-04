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

#ifndef MACHANDLER_H__
#define MACHANDLER_H__

/**
 *  hmac-sha1     REQUIRED      HMAC-SHA1
 *                              (digest length = key length = 20)
 *  hmac-sha1-96  RECOMMENDED   first 96 bits of HMAC-SHA1
 *                              (digest length = 12, key length = 20)
 *  hmac-md5      OPTIONAL      HMAC-MD5
 *                              (digest length = key length = 16)
 *  hmac-md5-96   OPTIONAL      first 96 bits of HMAC-MD5
 *                              (digest length = 12, key length = 16)
 *  none          OPTIONAL      no MAC; NOT RECOMMENDED
 *
 * The "hmac-*" algorithms are described in [RFC2104]. The "*-n" MACs use only
 * the first n bits of the resulting value.
 * SHA-1 is described in [FIPS-180-2] and MD5 is described in [RFC1321].
 *
 */
class MACHandler {
public:

  enum HMAC {
    NONE            = 0x00,
    HMAC_SHA1       = 0x01,
    HMAC_SHA1_96    = 0x02,
    HMAC_MD5        = 0x04,
    HMAC_MD5_96     = 0x08
  };

public:
  MACHandler(void);
  virtual ~MACHandler(void);
};

#endif // MACHANDLER_H__
