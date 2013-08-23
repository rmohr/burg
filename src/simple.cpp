#include "simple.h"
#include "util.h"
#include <boost/foreach.hpp>
#include <libconfig.h++> 
#include <crypt.h>
#include <stdexcept>

namespace burg{

    namespace simple {

        SimpleToken::SimpleToken(std::string identifier) : _identifier(identifier){};

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

        std::string SimpleToken::encode(std::string raw_data){
            return raw_data;
        }

        std::string SimpleToken::decode(std::string raw_data){
            return raw_data;
        }

        std::string SimpleToken::id(){
            return _identifier;
        }


        Role::Role(std::string id) : _id(id){};

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

        FileUserDB::FileUserDB(std::string file_path):_file_path(file_path){
            _load(_file_path);
        }

        void FileUserDB::_load(std::string file_path){
            using namespace libconfig;

            Config cfg;
            util::read_cfg(cfg, file_path);

            _db.clear();
            const Setting &root = cfg.getRoot();
            if (root.exists("users")){
                Setting& store = root["users"];
                for (int x = 0; x < store.getLength(); x++){
                    std::string user = store[x][0];
                    std::string passwd = store[x][1];
                    _db[user] = passwd;
                }
            }
        }

        void FileUserDB::reload() {
            boost::unique_lock< boost::shared_mutex > lock(_mutex);
            _load(_file_path);
        }

        bool FileUserDB::lookup(std::string user, std::string passwd) {
            boost::shared_lock< boost::shared_mutex > lock(_mutex);
            db_it_t it = _db.find(user);
            if (it != _db.end() && it->second == passwd){
                return true;
            }
            return false;
        }

        SimpleAuthenticator::SimpleAuthenticator(store_t store):_store(store){};


    }
}
