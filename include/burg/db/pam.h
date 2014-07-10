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


#ifndef INCLUDE_BURG_PAM_DB_H_
#define INCLUDE_BURG_PAM_DB_H_

#include <boost/algorithm/string.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <map>
#include <utility>
#include <string>

#include "../auth.h"
#include "../db.h"


namespace burg {
    namespace db {
        /**
         * @brief pam user database
         */
        struct PamUserDB : public UserDB {

            explicit PamUserDB(const std::string& stack_name);

            void reload();

            bool lookup(const std::string& user, const std::string& passwd);

            private:

            std::string _stack_name;

        };
    }  // namespace db
}  // namespace burg
#endif  // INCLUDE_BURG_PAM_DB_H_
