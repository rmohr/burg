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

#ifndef INCLUDE_BURG_PLAIN_FILTERS_H_
#define INCLUDE_BURG_PLAIN_FILTERS_H_

#include <string>

#include "../auth.h"
#include "../db.h"
namespace burg {
    namespace filters {

        /**
         * @brief a policy to transform a password from one from into another
         *
         * in this case the plane filters does nothing but return the unmodified
         * password.
         */
        struct PlainFilter {
            /**
             * @brief passes the given password through
             *
             * @param str password to transform
             *
             * @return unmodified password
             */
            std::string encrypt(const std::string& str) {
                return str;
            }
        };
    }  // namespace filters
}  // namespace burg
#endif  // INCLUDE_BURG_PLAIN_FILTERS_H_
