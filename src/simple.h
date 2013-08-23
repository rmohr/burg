#ifndef _SIMPLE_H_
#define _SIMPLE_H_
#include "auth.h"
#include "db.h"
#include <map>
#include <boost/algorithm/string.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <utility>


namespace burg {
    namespace simple {
        struct SimpleToken : public Token {

            SimpleToken(std::string identifier);

            bool authenticated();

            bool has_permission(permission_t perm);

            void set_permissions( permission_vec_t permissions);

            std::string encode(std::string raw_data);

            std::string decode(std::string raw_data);

            std::string id();

            private:

            permission_vec_t _permissions;
            std::string _identifier;
        };

        struct Role : Permission {

            Role(std::string id);

            bool satisfies(permission_t other_permission);

            std::string id();

            private:

            std::string _id;
        };

        struct FileUserDB : public UserDB {
            
            typedef std::map<std::string, std::string> db_t;
            typedef std::map<std::string, std::string>::iterator db_it_t;

            boost::shared_mutex _mutex;

            FileUserDB(std::string file_path);

            void reload();

            bool lookup(std::string user, std::string passwd);

            private:

            void _load(std::string file_path);

            db_t  _db;
            std::string _file_path;

        };

        struct PlainEncryptor {

            std::string encrypt (std::string str){
                return str;
            }
        };

        template < class Encryptor >
            struct SimpleStore : public Encryptor, public Store {

                using Encryptor::encrypt;

                SimpleStore(user_db_t db):_db(db){};  

                bool authenticate(std::string user, std::string passwd){
                    return _db->lookup(user, encrypt(passwd));
                }

                private:

                user_db_t _db;

            };

        struct SimpleAuthenticator;

        typedef boost::shared_ptr<SimpleAuthenticator> simple_authenticator_t;

        struct SimpleAuthenticator : public Authenticator {

            SimpleAuthenticator(store_t store);

            virtual auth_s authenticate(std::string raw_token) = 0;

            virtual std::string get_response() = 0;

            virtual token_t get_token() = 0;

            virtual simple_authenticator_t create() = 0;

            protected:

            store_t _store;

        };

        struct CSVRegex {
            std::pair<std::string, std::string> extract(std::string raw_token){
                std::vector<std::string> strs;
                boost::split(strs, raw_token, boost::is_any_of(","));
                return std::make_pair(strs[0], strs[1]);
            }
        };

        template <class Regex>
        struct SimpleRegexAuthenticator : public SimpleAuthenticator {

            using Regex::extract;
            using SimpleAuthenticator::_store;


            simple_authenticator_t create() {
                simple_authenticator_t new_auth(new SimpleRegexAuthenticator(_store));
                return new_auth;
            }

            SimpleRegexAuthenticator(store_t store):
                SimpleAuthenticator(store){}

            std::string get_response(){
                throw new std::runtime_error("this should never be called.");
            }

            token_t get_token(){
                token_t token(new SimpleToken(_id));
                return token;
            }

            auth_s authenticate(std::string raw_token){
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
    }
}
#endif
