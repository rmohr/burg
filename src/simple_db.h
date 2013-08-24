#ifndef __BURG_SIMPLE_DB_H_
#define __BURG_SIMPLE_DB_H_
#include "auth.h"
#include "db.h"
#include <map>
#include <boost/algorithm/string.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <utility>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/base32.h>

namespace burg {
    namespace simple {
        struct FileUserDB : public UserDB {
            
            typedef std::map<std::string, std::string> db_t;
            typedef std::map<std::string, std::string>::iterator db_it_t;

            boost::shared_mutex _mutex;

            FileUserDB(const std::string& file_path);

            void reload();

            bool lookup(const std::string& user,const std::string& passwd);

            private:

            void _load(const std::string& file_path);

            db_t  _db;
            std::string _file_path;

        };

        struct PlainFilter {

            std::string encrypt (const std::string& str){
                return str;
            }
        };

        struct Sha256Filter {

            std::string encrypt (const std::string& str){
                std::string digest;
                CryptoPP::SHA256 hash;

                CryptoPP::StringSource source(str, true,
                        new CryptoPP::HashFilter(hash,
                            new CryptoPP::Base64Encoder (
                                new CryptoPP::StringSink(digest),false
                                )
                            ));
                return digest;
            }
        };

        template < class Filter >
            struct SimpleStore : public Filter, public Store {

                using Filter::encrypt;

                SimpleStore(user_db_t db):_db(db){};  

                bool authenticate(const std::string& user, const std::string& passwd){
                    return _db->lookup(user, encrypt(passwd));
                }

                private:

                user_db_t _db;

            };
    }
}
#endif
