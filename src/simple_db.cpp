#include "simple_db.h"
#include "util.h"
#include <libconfig.h++> 
#include <crypt.h>
#include <stdexcept>

namespace burg{

    namespace simple {

        FileUserDB::FileUserDB(const std::string& file_path):_file_path(file_path){
            _load(_file_path);
        }

        void FileUserDB::_load(const std::string& file_path){
            using namespace libconfig;

            Config cfg;
            burg::util::read_cfg(cfg, file_path);

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

        bool FileUserDB::lookup(const std::string& user, const std::string& passwd) {
            boost::shared_lock< boost::shared_mutex > lock(_mutex);
            db_it_t it = _db.find(user);
            if (it != _db.end() && it->second == passwd){
                return true;
            }
            return false;
        }



        FileRolesDB::FileRolesDB(const std::string& file_path):_file_path(file_path){
            _load(_file_path);
        }

        void FileRolesDB::_load(const std::string& file_path){
            using namespace libconfig;

            Config cfg;
            burg::util::read_cfg(cfg, file_path);

            _db.clear();
            const Setting &root = cfg.getRoot();
            if (root.exists("roles")){
                Setting& store = root["roles"];
                for (int x = 0; x < store.getLength(); x++){
                    std::string user = store[x][0];
                    Setting& roles = store[x][1];
                    roles_vec_t vec(new roles_t_vec());
                    for (int y = 0; y < roles.getLength(); y++){
                        vec->push_back(roles[y]);
                    }
                    _db[user] = vec;
                }
            }
        }

        void FileRolesDB::reload() {
            boost::unique_lock< boost::shared_mutex > lock(_mutex);
            _load(_file_path);
        }

        roles_vec_t FileRolesDB::lookup(const std::string& user) {
            boost::shared_lock< boost::shared_mutex > lock(_mutex);
            db_it_t it = _db.find(user);
            if (it != _db.end()){
                return it->second;
            }
            return roles_vec_t(new roles_t_vec());
        }

        SimpleRolesStore::SimpleRolesStore(roles_db_t db):_db(db){}

        roles_vec_t SimpleRolesStore::get_roles(const std::string& user){
            return _db->lookup(user);
        }

    }

}
