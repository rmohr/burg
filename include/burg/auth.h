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


#ifndef INCLUDE_BURG_AUTH_H_
#define INCLUDE_BURG_AUTH_H_

#include <boost/shared_ptr.hpp>
#include <string>
#include <vector>

namespace burg {

    struct Permission;
    typedef boost::shared_ptr<Permission> permission_t;

    /**
     * @brief Interface for everything thats a permission.
     *
     * When a permission type implements this interface it can be used
     * by every implementation of the security token interface Token.
     */
    struct Permission {
        virtual ~Permission() {}

        /**
         * @brief Indicates weather the given Permission argument is satisfied
         *        by this permission.
         *
         * @param other_permission TODO
         *
         * @return true if satisfied, otherwise false
         */
        virtual bool satisfies(permission_t other_permission) = 0;


        /**
         * @brief Alpahnumerical identifiere
         *
         * @return returns an alphanumerical identifier of this permission
         */
        virtual std::string id() = 0;
    };

    typedef std::vector<permission_t> permission_vec_t;

    struct Token {
        virtual ~Token() {}

        virtual bool authenticated() = 0;

        virtual bool has_permission(permission_t perm) = 0;

        virtual void set_permissions(permission_vec_t permissions) = 0;

        virtual std::string  encrypt(const std::string& raw_data) = 0;

        virtual std::string  decrypt(const std::string& raw_data) = 0;

        virtual std::string  id() = 0;
    };

    typedef boost::shared_ptr<Token> token_t;

    struct Authenticator {
        enum auth_s {AUTH_CONTINUE = 255, AUTH_SUCCESS = 254,
            AUTH_REJECT = 253};

        virtual ~Authenticator() {}

        virtual auth_s authenticate(const std::string& raw_token) = 0;

        virtual std::string get_response() = 0;

        virtual token_t get_token() = 0;
    };

    typedef boost::shared_ptr<Authenticator> auth_t;

    struct Authorizer {
        virtual ~Authorizer() {}

        virtual void set_permissions(token_t token) = 0;
    };

    typedef boost::shared_ptr<Authorizer> autz_t;

}  // namespace burg
#endif  // INCLUDE_BURG_AUTH_H_
