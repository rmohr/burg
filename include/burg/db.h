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


#ifndef INCLUDE_BURG_DB_H_
#define INCLUDE_BURG_DB_H_

#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>

namespace burg {
    struct UserDB {
        virtual ~UserDB() {}

        virtual void reload() = 0;

        virtual bool lookup(const std::string& user,
                const std::string& passwd) = 0;
    };

    typedef std::vector<std::string> roles_t_vec;
    typedef boost::shared_ptr<roles_t_vec> roles_vec_t;

    struct RolesDB {
        virtual ~RolesDB() {}

        virtual void reload() = 0;

        virtual roles_vec_t lookup(const std::string& user) = 0;
    };

    struct UserStore {
        virtual bool authenticate(const std::string& user,
                const std::string& passwd) = 0;
    };

    struct RolesStore {
        virtual roles_vec_t get_roles(const std::string& user) = 0;
    };

    typedef boost::shared_ptr<UserStore> user_store_t;
    typedef boost::shared_ptr<RolesStore> roles_store_t;

    typedef boost::shared_ptr<UserDB> user_db_t;
    typedef boost::shared_ptr<RolesDB> roles_db_t;
}  // namespace burg

#endif  // INCLUDE_BURG_DB_H_

