#include "simple.h"
#include <iostream>
int main(int argc, char** argv){
    burg::token_t token = burg::token_t(new burg::simple::SimpleToken("roman"));
    burg::permission_t permission = burg::permission_t(new burg::simple::Role("admin"));

    std::cout << token->id() << std::endl;
    std::cout << permission->satisfies(permission) << std::endl;

    burg::user_db_t user_db = burg::user_db_t(new burg::simple::FileUserDB("./db.cfg"));
    std::cout << user_db->lookup("roman", "hallo") << std::endl;
    std::cout << user_db->lookup("roma", "hallo") << std::endl;
    std::cout << user_db->lookup("roman", "hall") << std::endl;

    using namespace burg::simple;
    burg::store_t store = burg::store_t(new SimpleStore<Sha256Filter>(user_db));
    std::cout << store->authenticate("roman", "hallo") << std::endl;
    std::cout << store->authenticate("roma", "hallo") << std::endl;
    std::cout << store->authenticate("roman", "hall") << std::endl;

    simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(store));
    burg::auth_t auth = factory->create();

    if (burg::Authenticator::AUTH_SUCCESS == auth->authenticate("roma,hallo")){
        std::cout << auth->get_token()->id() << std::endl;
    } else {
        std::cout << "failed" << std::endl;
    }

    if (burg::Authenticator::AUTH_SUCCESS == auth->authenticate("roman,hallo")){
        std::cout << auth->get_token()->id() << std::endl;
    } else {
        std::cout << "failed" << std::endl;
    }

    return 0;
}
