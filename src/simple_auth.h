#ifndef __BURG_SIMPLE_AUTH_H_
#define __BURG_SIMPLE_AUTH_H_
#include "auth.h"
#include "db.h"
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <utility>

namespace burg {
    namespace simple {
        struct SimpleToken : public Token {

            SimpleToken(const std::string& identifier);

            bool authenticated();

            bool has_permission(permission_t perm);

            void set_permissions( permission_vec_t permissions);

            std::string encode(const std::string& raw_data);

            std::string decode(const std::string& raw_data);

            std::string id();

            private:

            permission_vec_t _permissions;
            std::string _identifier;
        };

        struct Role : Permission {

            Role(const std::string& id);

            bool satisfies(permission_t other_permission);

            std::string id();

            private:

            std::string _id;
        };

        struct SimpleAuthenticator;

        typedef boost::shared_ptr<SimpleAuthenticator> simple_auth_t;

        struct SimpleAuthenticator : public Authenticator {

            SimpleAuthenticator(user_store_t store);

            virtual auth_s authenticate(const std::string& raw_token) = 0;

            virtual std::string get_response() = 0;

            virtual token_t get_token() = 0;

            virtual auth_t create() = 0;

            protected:

            user_store_t _store;

        };

        struct SimpleAuthorizer;

        typedef boost::shared_ptr<SimpleAuthorizer> simple_autz_t;

        struct SimpleAuthorizer : public Authorizer {

            SimpleAuthorizer(roles_store_t store);

            virtual void set_permissions(token_t token) = 0;

            protected:

            roles_store_t _store;
        };


        struct CSVRegex {
            std::pair<std::string, std::string> extract(const std::string& raw_token){
                std::vector<std::string> strs;
                boost::split(strs, raw_token, boost::is_any_of(","));
                return std::make_pair(strs[0], strs[1]);
            }
        };

        template <class Regex = CSVRegex>
        struct SimpleRegexAuthenticator : public Regex, public SimpleAuthenticator {

            using Regex::extract;
            using SimpleAuthenticator::_store;


            auth_t create() {
                auth_t new_auth(new SimpleRegexAuthenticator(_store));
                return new_auth;
            }

            SimpleRegexAuthenticator(user_store_t store):
                SimpleAuthenticator(store){}

            std::string get_response(){
                throw new std::runtime_error("this should never be called.");
            }

            token_t get_token(){
                token_t token(new SimpleToken(_id));
                return token;
            }

            auth_s authenticate(const std::string& raw_token){
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

        struct PassRegex {

            std::string extract(const std::string& id){
                return id;
            }

        };

        template <class Regex = PassRegex>
        struct SimpleRegexAuthorizer : public Regex, public SimpleAuthorizer {
            using Regex::extract;

            SimpleRegexAuthorizer(roles_store_t store):SimpleAuthorizer(store){}

            void set_permissions(token_t token){
                std::string id = extract(token->id());
                burg::roles_vec_t roles = _store->get_roles(id);
                permission_vec_t permissions;
                BOOST_FOREACH (std::string role, *roles){
                    permission_t permission(new Role(role));
                    permissions.push_back(permission);
                }
                token->set_permissions(permissions);
            };
        };

    }
}
#endif
