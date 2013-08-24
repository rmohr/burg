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


#include <simple_auth.h>
#include <boost/foreach.hpp>

#include <string>

namespace burg {

    namespace simple {

        SimpleToken::SimpleToken(const std::string& identifier):
            _identifier(identifier) {}

        bool SimpleToken::authenticated() {
            return true;
        }

        bool SimpleToken::has_permission(permission_t perm) {
            BOOST_FOREACH(permission_t _perm, _permissions) {
                if (perm->satisfies(_perm)) {
                    return true;
                }
            }
            return false;
        }

        void SimpleToken::set_permissions(permission_vec_t permissions) {
            _permissions = permissions;
        }

        std::string SimpleToken::encode(const std::string& raw_data) {
            return raw_data;
        }

        std::string SimpleToken::decode(const std::string& raw_data) {
            return raw_data;
        }

        std::string SimpleToken::id() {
            return _identifier;
        }


        Role::Role(const std::string& id) : _id(id) {}

        bool Role::satisfies(permission_t other_permission) {
            if (id() == other_permission->id()) {
                return true;
            } else {
                return false;
            }
        }

        std::string Role::id() {
            return _id;
        }

        SimpleAuthenticator::SimpleAuthenticator(user_store_t store):
            _store(store) {}


        SimpleAuthorizer::SimpleAuthorizer(roles_store_t store):
            _store(store) {}
    }  // namespace simple
}  // namespace burg
