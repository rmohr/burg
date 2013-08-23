#ifndef __BURG_DB_H_
#define __BURG_DB_H_

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp> 

namespace burg {
    struct UserDB {

        virtual ~UserDB(){};

        virtual void reload() = 0;

        virtual bool lookup(std::string user, std::string passwd) = 0;

    };

    typedef std::vector<std::string> roles_t_vec;

    struct RoleDB {

        virtual ~RoleDB(){};

        virtual void reload() = 0;

        virtual roles_t_vec lookup(std::string user) = 0;
    };

    struct Store {

        virtual bool authenticate(std::string user, std::string passwd) = 0;

    };

    typedef boost::shared_ptr<Store> store_t;

    typedef boost::shared_ptr<UserDB> user_db_t;
}

#endif

