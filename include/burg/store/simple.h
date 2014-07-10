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


#ifndef INCLUDE_BURG_SIMPLE_H_
#define INCLUDE_BURG_SIMPLE_H_

#include <boost/algorithm/string.hpp>
#include <boost/thread/shared_mutex.hpp>

#include <utility>
#include <string>

#include "../auth.h"
#include "../db.h"
#include "../filters/plain.h"
namespace burg {
    namespace store {

        /**
         * @brief takes usernames/passwords and tries to authenticate users
         * agains a underlying UserDB
         *
         * @tparam Filter filter to transform a given password in an
         * appropriate form for the underlying UserDB
         */
        template < class Filter = burg::filters::PlainFilter >
            struct SimpleUserStore : public Filter, public UserStore {
                using Filter::encrypt;

                explicit SimpleUserStore(user_db_t db):_db(db) {}

                bool authenticate(const std::string& user,
                        const std::string& passwd) {
                    return _db->lookup(user, encrypt(passwd));
                }

                private:
                user_db_t _db;
            };

        /**
         * @brief takes a username and tries to retrieve the associated roles
         * from the underlying RolesDB
         */
        struct SimpleRolesStore : public RolesStore {
            explicit SimpleRolesStore(roles_db_t db);

            roles_vec_t get_roles(const std::string& user);

            private:
            roles_db_t _db;
        };
    }  // namespace store
}  // namespace burg
#endif  // INCLUDE_BURG_SIMPLE_H_
