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

        bool FileUserDB::lookup(const std::string& user, const std::string& passwd) {
            boost::shared_lock< boost::shared_mutex > lock(_mutex);
            db_it_t it = _db.find(user);
            if (it != _db.end() && it->second == passwd){
                return true;
            }
            return false;
        }
    }
}
