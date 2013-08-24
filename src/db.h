#ifndef __BURG_DB_H_
#define __BURG_DB_H_

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp> 

namespace burg {
    struct UserDB {

        virtual ~UserDB(){};

        virtual void reload() = 0;

        virtual bool lookup(const std::string& user, const std::string& passwd) = 0;

    };

    typedef std::vector<std::string> roles_t_vec;
    typedef boost::shared_ptr<roles_t_vec> roles_vec_t;

    struct RolesDB {

        virtual ~RolesDB(){};

        virtual void reload() = 0;

        virtual roles_vec_t lookup(const std::string& user) = 0;
    };

    struct Store {

        virtual bool authenticate(const std::string& user, const std::string& passwd) = 0;

    };

    typedef boost::shared_ptr<Store> store_t;

    typedef boost::shared_ptr<UserDB> user_db_t;
    typedef boost::shared_ptr<RolesDB> roles_db_t;
}

#endif

