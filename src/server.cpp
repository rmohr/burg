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
    return 0;
}
