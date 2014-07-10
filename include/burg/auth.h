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
     * @brief Interface for everything thats a Permission.
     *
     * When a permission type implements this interface it can be used
     * by every implementation of the security token interface Token.
     */
    struct Permission {
        virtual ~Permission() {}

        /**
         * @brief Indicates weather the given Permission argument is satisfied
         * by this permission.
         *
         * @param other_permission permission to compare with
         *
         * @return true if satisfied, otherwise false
         */
        virtual bool satisfies(permission_t other_permission) = 0;


        /**
         * @brief Alpahnumerical identifier
         *
         * @return an alphanumerical identifier of this permission
         */
        virtual std::string id() = 0;
    };

    typedef std::vector<permission_t> permission_vec_t;

    /**
     * @brief Interface for everything thats an authentication or authorization
     * Token.
     */
    struct Token {
        virtual ~Token() {}

        /**
         * @brief Indicates if a users authentication is still valid.
         *
         * good extension point for tokens which should only be valid for a
         * specific time period.
         *
         * @return true if still authenticated, false otherwise
         */
        virtual bool authenticated() = 0;

        /**
         * @brief indicates whether an authenticated user has a specific
         * permission.
         *
         * @param perm permission to check for
         *
         * @return true if permission granted, false otherwise
         */
        virtual bool has_permission(permission_t perm) = 0;

        /**
         * @brief tell the Token which permissions its user has.
         *
         * @param permissions permissions the authenticated user has.
         */
        virtual void set_permissions(permission_vec_t permissions) = 0;

        /**
         * @brief can be used to encrypt data if a security layer has been
         * negotiated by the Authorizer which created this token.
         *
         * @param raw_data the raw data to encrypt
         *
         * @return encrypted version of raw_data
         */
        virtual std::string  encrypt(const std::string& raw_data) = 0;

        /**
         * @brief can be used to decrypt data if a security layer has been
         * negotiated by the Authorizer which created this token.
         *
         * @param raw_data the raw data to decrypt
         *
         * @return decrypted version of raw_data
         *
         */
        virtual std::string  decrypt(const std::string& raw_data) = 0;

        /**
         * @brief Alpahnumerical identifier
         *
         * @return an alphanumerical identifier of the associated user
         */
        virtual std::string  id() = 0;
    };

    typedef boost::shared_ptr<Token> token_t;

    /**
     * @brief Interface for everything thats an Authenticator
     *
     * an Authenticator is a stateful object. This means that every connecting
     * client needs its own Authenticator until the authentication process has
     * completed. Therefore a factory method exists in SimpleAuthenticator, to
     * make spawning authenticators more convenient. After an authentication
     * has finished, the Authenticator can be reused by another connection. If
     * you want tu support a new authentication and/or encryption mechanism
     * (e.g. SASL, GSSAPI, ... ) with this framework, the first step is to
     * implement your own Authenticator.
     */
    struct Authenticator {
        /**
         * @enum auth_s
         * @brief current state of the authentication process
         */
        enum auth_s {
            AUTH_CONTINUE = 255, /**< information from the client is needed*/
            AUTH_SUCCESS = 254, /**< authentication was successful*/
            AUTH_REJECT = 253 /**< authentication failed*/
        };

        virtual ~Authenticator() {}

        /**
         * @brief call when the authentication for a fresh connection is
         * initiated, or when new information for continuing the authentication
         * process arrived.
         *
         * @param raw_token autentication information from the client, this
         * contains either the data sent with the authentication process
         * initiation, or the data sent by a callback request of the server to
         * continue the authentication process.
         *
         * @return indicates the authentication state
         */
        virtual auth_s authenticate(const std::string& raw_token) = 0;

        /**
         * @brief call when authenticate() returns Authenticator::AUTH_CONTINUE.
         *
         * The data return by this method needs to be sent back to the client
         * to retrieve some more information that the authentication process
         * can go on.
         *
         * @return the response which needs to be sent to the client
         */
        virtual std::string get_response() = 0;


        /**
         * @brief call when authenticate() returns Authenticator::AUTH_SUCCESS.
         *
         * @return the new security Token of the successfully logged in user.
         */
        virtual token_t get_token() = 0;
    };

    typedef boost::shared_ptr<Authenticator> auth_t;

    /**
     * @brief Interface of everything which should be used as an authorization
     * information provider in the framework
     */
    struct Authorizer {
        virtual ~Authorizer() {}

        /**
         * @brief looks up and sets the appropriate Permission%s for the
         * provided security Token
         *
         * @param token the security Token for which the Permission%s to search for
         */
        virtual void set_permissions(token_t token) = 0;
    };

    typedef boost::shared_ptr<Authorizer> autz_t;

}  // namespace burg
#endif  // INCLUDE_BURG_AUTH_H_
