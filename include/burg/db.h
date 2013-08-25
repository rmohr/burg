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

    /**
     * @brief Interface for in memory databases
     *
     * every kind of user/password database which is loaded once at startup and
     * is located in the server memory should inherit from this interface. As
     * it provides a reload() method to allow the reload of the database, the
     * database inherited from this interface should be threadsave.
     * FileUserDB provides a reference implementation.
     */
    struct UserDB {
        virtual ~UserDB() {}

        /**
         * @brief extension point for reload in a specific database
         * implementation
         *
         * the intention of the method is to allow the reload of the database
         * when for example SIGHUP occures. As an application might be
         * multithreaded, the whole derived class must be threadsave.
         */
        virtual void reload() = 0;

        /**
         * @brief checks if the user/password pair exists in the database
         *
         * if the password is plain or encrypted at this point depends on the
         * used protocol and the SimpleUserStore which uses this database.
         *
         * @param user the unique identifier of the user
         * @param passwd the password of the user
         *
         * @return true if user/password matches, false otherwise
         */
        virtual bool lookup(const std::string& user,
                const std::string& passwd) = 0;
    };

    typedef std::vector<std::string> roles_t_vec;
    typedef boost::shared_ptr<roles_t_vec> roles_vec_t;

    /**
     * @brief Interface for in memory databases
     *
     * every kind of user/roles database which is loaded once at startup and
     * is located in the server memory should inherit from this interface. As
     * it provides a reload() method to allow the reload of the database, the
     * database inherited from this interface should be threadsave.
     * FileRolesDB provides a reference implementation.
     */
    struct RolesDB {
        virtual ~RolesDB() {}

        /**
         * @brief extension point for reload in a specific database
         * implementation
         *
         * the intention of the method is to allow the reload of the database
         * when for example SIGHUP occures. As an application might be
         * multithreaded, the whole derived class must be threadsave.
         */
        virtual void reload() = 0;

        /**
         * @brief looks up the roles of provided users and returns them
         *
         * @param user the user of whom the roles are to search for
         *
         * @return the associated roles of the user
         */
        virtual roles_vec_t lookup(const std::string& user) = 0;
    };

    /**
     * @brief Interface which stands between a SimpleAuthenticator and a concrete
     * authentication information retriving system.
     *
     * if you want to implement new ways of retriving authentication
     * information (e.g. LDAP, MySQL, ...) aside from FileUserDB this is the
     * right interface to implement.
     *
     */
    struct UserStore {
        /**
         * @brief authenticat a user via a unique identifier and a password
         *
         * @param user the unique identifier of the user
         * @param passwd the password of the user
         *
         * @return true if user/password matches, false otherwise

         */
        virtual bool authenticate(const std::string& user,
                const std::string& passwd) = 0;
    };

    /**
     * @brief Interface which stands between a SimpleAuthorizer and a concrete
     * authorization information retriving system.
     *
     * if you want to implement new ways of retriving authorization
     * information (e.g. LDAP, MySQL, ...) aside from FileRolesDB this is the
     * right interface to implement.
     */
    struct RolesStore {
        /**
         * @brief retrieve the roles associatet with a user
         *
         * @param user the unique identifier of the user
         *
         * @return a vector of roles associated with the user
         */
        virtual roles_vec_t get_roles(const std::string& user) = 0;
    };

    typedef boost::shared_ptr<UserStore> user_store_t;
    typedef boost::shared_ptr<RolesStore> roles_store_t;

    typedef boost::shared_ptr<UserDB> user_db_t;
    typedef boost::shared_ptr<RolesDB> roles_db_t;
}  // namespace burg

#endif  // INCLUDE_BURG_DB_H_

