#include "simple_db.h"
#include "simple_auth.h"
#include <iostream>
#include <boost/foreach.hpp>

int main(int argc, char** argv){
    burg::token_t token = burg::token_t(new burg::simple::SimpleToken("roman"));
    burg::permission_t permission = burg::permission_t(new burg::simple::Role("admin"));

    std::cout << token->id() << std::endl;
    std::cout << permission->satisfies(permission) << std::endl;

    burg::user_db_t user_db = burg::user_db_t(new burg::simple::FileUserDB("./db.cfg"));
    std::cout << user_db->lookup("roman", "hallo") << std::endl;
    std::cout << user_db->lookup("roma", "hallo") << std::endl;
    std::cout << user_db->lookup("roman", "hall") << std::endl;

    burg::roles_db_t roles_db = burg::roles_db_t(new burg::simple::FileRolesDB("./db.cfg"));
    burg::roles_vec_t roles = roles_db->lookup("roman");

    BOOST_FOREACH(std::string role, *roles){
        std::cout << role << std::endl;
    }
    roles = roles_db->lookup("roma");

    BOOST_FOREACH(std::string role, *roles){
        std::cout << role << std::endl;
    }


    using namespace burg::simple;
    burg::user_store_t store = burg::user_store_t(new SimpleUserStore<Sha256Filter>(user_db));
    std::cout << store->authenticate("roman", "hallo") << std::endl;
    std::cout << store->authenticate("roma", "hallo") << std::endl;
    std::cout << store->authenticate("roman", "hall") << std::endl;

    burg::roles_store_t roles_store = burg::roles_store_t(new SimpleRolesStore(roles_db));
    roles = roles_store->get_roles("roman");
    BOOST_FOREACH(std::string role, *roles){
        std::cout << role << std::endl;
    }
    simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(store));
    burg::auth_t auth = factory->create();

    if (burg::Authenticator::AUTH_SUCCESS == auth->authenticate("roma,hallo")){
        std::cout << auth->get_token()->id() << std::endl;
    } else {
        std::cout << "failed" << std::endl;
    }

    burg::autz_t autz = burg::autz_t(new SimpleRegexAuthorizer<PassRegex>(roles_store));

    if (burg::Authenticator::AUTH_SUCCESS == auth->authenticate("roman,hallo")){
        burg::token_t token = auth->get_token();
        std::cout << token->id() << std::endl;
        autz->set_permissions(token);
        burg::permission_t p1 = burg::permission_t (new Role("lala"));
        std::cout << token->has_permission(permission) << std::endl;
        std::cout << token->has_permission(p1) << std::endl;
    } else {
        std::cout << "failed" << std::endl;
    }

    return 0;
}
