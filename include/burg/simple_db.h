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


#ifndef INCLUDE_BURG_SIMPLE_DB_H_
#define INCLUDE_BURG_SIMPLE_DB_H_

#include <boost/algorithm/string.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <cryptopp/base32.h>

#include <map>
#include <utility>
#include <string>

#include "./auth.h"
#include "./db.h"
namespace burg {
    namespace simple {

        /**
         * @brief a file based roles database
         *
         * the structure of the database file is
         * @code
         * roles =
         * (
         *     ("username", ("role1", "role2") ),
         *     ("fritz", ("admin", "user") )
         * );
         * @endcode
         */
        struct FileRolesDB : public RolesDB {
            typedef std::map<std::string, roles_vec_t> db_t;
            typedef std::map<std::string, roles_vec_t>::iterator db_it_t;

            explicit FileRolesDB(const std::string& file_path);

            void reload();

            virtual roles_vec_t lookup(const std::string& user);

            private:
            void _load(const std::string& file_path);

            db_t  _db;
            std::string _file_path;
            boost::shared_mutex _mutex;
        };

        /**
         * @brief a file based user/password database
         *
         * the structure of the database file is
         * @code
         * users =
         * (
         *     ("username", "password")
         *     ("fritz", "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=")
         * );
         * @endcode
         */
        struct FileUserDB : public UserDB {
            typedef std::map<std::string, std::string> db_t;
            typedef std::map<std::string, std::string>::iterator db_it_t;

            explicit FileUserDB(const std::string& file_path);

            void reload();

            bool lookup(const std::string& user, const std::string& passwd);

            private:
            void _load(const std::string& file_path);

            db_t  _db;
            std::string _file_path;
            boost::shared_mutex _mutex;
        };

        /**
         * @brief a policy to transform a password from one from into another
         *
         * in this case the plane filter does nothing but return the unmodified
         * password.
         */
        struct PlainFilter {
            /**
             * @brief passes the given password through
             *
             * @param str password to transform
             *
             * @return unmodified password
             */
            std::string encrypt(const std::string& str) {
                return str;
            }
        };

        /**
         * @brief transform a given password into sha256sum with base64
         * encoding
         */
        struct Sha256Filter {
            /**
             * @brief transforms a given password into sha256sum with base64
             * encoding
             *
             * @param str password to transform
             *
             * @return sha256sum in base64 encoding of password
             *
             */
            std::string encrypt(const std::string& str) {
                std::string digest;
                CryptoPP::SHA256 hash;

                CryptoPP::StringSource source(str, true,
                        new CryptoPP::HashFilter(hash,
                            new CryptoPP::Base64Encoder(
                                new CryptoPP::StringSink(digest), false)));
                return digest;
            }
        };

        /**
         * @brief takes usernames/passwords and tries to authenticate users
         * agains a underlying UserDB
         *
         * @tparam Filter filter to transform a given password in an
         * appropriate form for the underlying UserDB
         */
        template < class Filter = PlainFilter >
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
    }  // namespace simple
}  // namespace burg
#endif  // INCLUDE_BURG_SIMPLE_DB_H_
