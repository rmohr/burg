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

    struct FileRolesDB : public RolesDB {

        typedef std::map<std::string, roles_vec_t> db_t;
        typedef std::map<std::string, roles_vec_t>::iterator db_it_t;

        FileRolesDB(const std::string& file_path);

        void reload();

        virtual roles_vec_t lookup(const std::string& user);

        private:

        void _load(const std::string& file_path);

        db_t  _db;
        std::string _file_path;
        boost::shared_mutex _mutex;

    };

        struct FileUserDB : public UserDB {

            typedef std::map<std::string, std::string> db_t;
            typedef std::map<std::string, std::string>::iterator db_it_t;


            FileUserDB(const std::string& file_path);

            void reload();

            bool lookup(const std::string& user,const std::string& passwd);

            private:

            void _load(const std::string& file_path);

            db_t  _db;
            std::string _file_path;
            boost::shared_mutex _mutex;

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

        template < class Filter = PlainFilter >
            struct SimpleUserStore : public Filter, public UserStore {

                using Filter::encrypt;

                SimpleUserStore(user_db_t db):_db(db){}

                bool authenticate(const std::string& user, const std::string& passwd){
                    return _db->lookup(user, encrypt(passwd));
                }

                private:

                user_db_t _db;

            };

        struct SimpleRolesStore : public RolesStore {

            SimpleRolesStore(roles_db_t db);

            roles_vec_t get_roles(const std::string& user);

            private:
                roles_db_t _db;
        };
    }
}
#endif
