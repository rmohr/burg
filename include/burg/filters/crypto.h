/*
 *  Copyright 2013, Roman Mohr <roman@fenkhuber.at>
 *
 *  This file is part of burg.
 *
 *  Burg is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Burg is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with burg.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef INCLUDE_BURG_CRYPTO_FILTERS_H_
#define INCLUDE_BURG_CRYPTO_FILTERS_H_

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/base32.h>

#include <string>

#include "../auth.h"
#include "../db.h"
namespace burg {
    namespace filters {

        /**
         * @brief transform a given password into sha256sum with base64
         * encoding
         */
        struct Sha256Filter {
            /**
             * @brief transforms a given password into sha256sum with base64
             * encoding
             *
             * @param str password to transform
             *
             * @return sha256sum in base64 encoding of password
             *
             */
            std::string encrypt(const std::string& str) {
                std::string digest;
                CryptoPP::SHA256 hash;

                CryptoPP::StringSource source(str, true,
                        new CryptoPP::HashFilter(hash,
                            new CryptoPP::Base64Encoder(
                                new CryptoPP::StringSink(digest), false)));
                return digest;
            }
        };

    }  // namespace filters
}  // namespace burg
#endif  // INCLUDE_BURG_CRYPTO_FILTERS_H_
