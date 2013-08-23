#ifndef __BURG_AUTH_H_
#define __BURG_AUTH_H_
#include <boost/shared_ptr.hpp> 
#include <vector>

namespace burg {

    struct Permission;
    typedef boost::shared_ptr<Permission> permission_t;

    struct Permission {

        virtual ~Permission(){};

        virtual bool satisfies(permission_t other_permission) = 0;

        virtual std::string id() = 0;

    };

    typedef std::vector<permission_t> permission_vec_t;

    struct Token {

        virtual ~Token(){};

        virtual bool authenticated() = 0;

        virtual bool has_permission(permission_t perm) = 0;

        virtual void set_permissions( permission_vec_t permissions) = 0;

        virtual std::string  encode(std::string raw_data) = 0;

        virtual std::string  decode(std::string raw_data) = 0;

        virtual std::string  id() = 0;
    };

    typedef boost::shared_ptr<Token> token_t;

    struct Authenticator {

        enum auth_s {AUTH_CONTINUE=1, AUTH_SUCCESS=2, AUTH_REJECT=2};

        virtual ~Authenticator(){};

        virtual auth_s authenticate(std::string raw_token) = 0;

        virtual std::string get_response() = 0;

        virtual token_t get_token() = 0;

    };

    typedef boost::shared_ptr<Authenticator> authenticator_t;

    struct Guard {

        virtual ~Guard(){};

        virtual permission_vec_t get_permissions(token_t token) = 0;
    };

    typedef boost::shared_ptr<Guard> guard_t;

}
#endif
