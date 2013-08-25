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


#ifndef INCLUDE_BURG_SIMPLE_AUTH_H_
#define INCLUDE_BURG_SIMPLE_AUTH_H_
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>

#include <utility>

#include <string>
#include <vector>

#include "./auth.h"
#include "./db.h"

namespace burg {
    namespace simple {
        /**
         * @brief simplest possible token which just passes through data when
         * calling encrypt() or decrypt()
         */
        struct SimpleToken : public Token {
            explicit SimpleToken(const std::string& identifier);

            bool authenticated();

            bool has_permission(permission_t perm);

            void set_permissions(permission_vec_t permissions);

            std::string encrypt(const std::string& raw_data);

            std::string decrypt(const std::string& raw_data);

            std::string id();

            private:
            permission_vec_t _permissions;
            std::string _identifier;
        };

        /**
         * @brief represents simple roles like 'admin' or 'user'
         */
        struct Role : Permission {
            explicit Role(const std::string& id);

            bool satisfies(permission_t other_permission);

            std::string id();

            private:
            std::string _id;
        };

        struct SimpleAuthenticator;

        typedef boost::shared_ptr<SimpleAuthenticator> simple_auth_t;

        /**
         * @brief base for username/password based Authenticator%s
         */
        struct SimpleAuthenticator : public Authenticator {
            explicit SimpleAuthenticator(user_store_t store);

            virtual auth_s authenticate(const std::string& raw_token) = 0;

            virtual std::string get_response() = 0;

            virtual token_t get_token() = 0;

            virtual auth_t create() = 0;

            protected:
            user_store_t _store;
        };

        struct SimpleAuthorizer;

        typedef boost::shared_ptr<SimpleAuthorizer> simple_autz_t;

        /**
         * @brief base for username/role based Authorizers%s
         */
        struct SimpleAuthorizer : public Authorizer {
            explicit SimpleAuthorizer(roles_store_t store);

            virtual void set_permissions(token_t token) = 0;

            protected:
            roles_store_t _store;
        };


        /**
         * @brief policy for username and password extraction from a string in
         * the format 'username,password'
         */
        struct CSVRegex {
            /**
             * @brief extracts usernames and passwords with the formant
             * 'username,password'
             *
             * @param raw_token
             *
             * @return a username,password pair
             */
            std::pair<std::string, std::string>
                extract(const std::string& raw_token) {
                std::vector<std::string> strs;
                boost::split(strs, raw_token, boost::is_any_of(","));
                return std::make_pair(strs[0], strs[1]);
            }
        };

        /**
         * @brief extracts username and password from provided data
         * and tries to authenticate the user
         *
         * extracts username and password from provided data and tries
         * to authenticate the user agains a underlying implementation of
         * UserStore
         *
         * @tparam Regex a policy for extraction of username and password
         * information from the provided data
         */
        template <class Regex = CSVRegex>
        struct SimpleRegexAuthenticator :
            public Regex, public SimpleAuthenticator {
            using Regex::extract;
            using SimpleAuthenticator::_store;

            /**
             * @brief factory method to return a new Authenticator from this
             * prototype
             *
             * the returned new Authenticator is ready to be used for a fresh
             * authentication process and contains a reference to a UserStore
             *
             * @return a fresh SimpleRegexAuthenticator
             */
            auth_t create() {
                auth_t new_auth(new SimpleRegexAuthenticator(_store));
                return new_auth;
            }

            /**
             * @brief creates a new SimpleRegexAuthenticator with a reference
             * to a RolesStore
             *
             * @param store reference to a RolesStore
             */
            explicit SimpleRegexAuthenticator(user_store_t store):
                SimpleAuthenticator(store) {}

            /**
             *  @brief this Authenticator does not support negotiation
             */
            std::string get_response() {
                throw new std::runtime_error("this should never be called.");
            }

            token_t get_token() {
                token_t token(new SimpleToken(_id));
                return token;
            }

            auth_s authenticate(const std::string& raw_token) {
                std::pair<std::string, std::string> p = extract(raw_token);
                _id = p.first;
                if (_store->authenticate(p.first, p.second)) {
                    return AUTH_SUCCESS;
                }
                    return AUTH_REJECT;
            }

            private:
            std::string _id;
        };

        /**
         * @brief a policy to extract a suitable identifier from another
         * identifier
         *
         * sometimes an identifier is not in the right fashion for lookups in a
         * RolesStore, e.g. a realm is appended before a username. Policies
         * like this deal with this problem.
         *
         */
        struct PassRegex {
            /**
             * @brief in a simple username/password system the id is already
             * suitable for a RolesStore, so just return the unmodified id
             *
             * @param id
             *
             * @return unmodified id
             */
            std::string extract(const std::string& id) {
                return id;
            }
        };

        /**
         * @brief retrieves the permissions of a user associated with a
         * security Token from a underlying RolesStore.
         *
         * @tparam Regex a policy to map/extract the correct information an
         * identifier returned by Token::id()
         */
        template <class Regex = PassRegex>
        struct SimpleRegexAuthorizer : public Regex, public SimpleAuthorizer {
            using Regex::extract;
            explicit SimpleRegexAuthorizer(roles_store_t store):
                SimpleAuthorizer(store) {}

            void set_permissions(token_t token) {
                std::string id = extract(token->id());
                burg::roles_vec_t roles = _store->get_roles(id);
                permission_vec_t permissions;

                BOOST_FOREACH(std::string role, *roles) {
                    permission_t permission(new Role(role));
                    permissions.push_back(permission);
                }
                token->set_permissions(permissions);
            };
        };
    }  // namespace simple
}  // namespace burg
#endif  // INCLUDE_BURG_SIMPLE_AUTH_H_
