#include "simple_auth.h"
#include <boost/foreach.hpp>

namespace burg{

    namespace simple {

        SimpleToken::SimpleToken(const std::string& identifier) : _identifier(identifier){};

        bool SimpleToken::authenticated(){
            return true;
        }

        bool SimpleToken::has_permission(permission_t perm){
            BOOST_FOREACH(permission_t _perm, _permissions){
                if (perm->satisfies(_perm)){
                    return true;
                }
            }
            return false;
        }

        void SimpleToken::set_permissions(permission_vec_t permissions){
            _permissions = permissions;
        }

        std::string SimpleToken::encode(const std::string& raw_data){
            return raw_data;
        }

        std::string SimpleToken::decode(const std::string& raw_data){
            return raw_data;
        }

        std::string SimpleToken::id(){
            return _identifier;
        }


        Role::Role(const std::string& id) : _id(id){};

        bool Role::satisfies(permission_t other_permission){
            if (id() == other_permission->id()) {
                return true;
            } else {
                return false;
            }
        }

        std::string Role::id(){
            return _id;
        }

        SimpleAuthenticator::SimpleAuthenticator(user_store_t store):_store(store){};


        SimpleAuthorizer::SimpleAuthorizer(roles_store_t store):_store(store){};


    }
}
