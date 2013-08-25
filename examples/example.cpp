#include <stdio.h>
#include <burg/simple_db.h>
#include <burg/simple_auth.h>
#include <cstdlib>
#include <string>
#include <iostream>

using ::burg::simple::FileUserDB;
using ::burg::simple::FileRolesDB;

using ::burg::simple::SimpleUserStore;
using ::burg::simple::SimpleRolesStore;
using ::burg::simple::Sha256Filter;

using ::burg::simple::SimpleRegexAuthorizer;
using ::burg::simple::SimpleRegexAuthenticator;
using ::burg::simple::PassRegex;
using ::burg::simple::CSVRegex;

using ::burg::simple::Role;


int main(int argc, char** argv){

    if (argc != 5){
        std::cerr << "USAGE: ./example USER PASSWD ROLE DB_PATH" << std::endl;
        return EXIT_FAILURE;
    }

    std::string user(argv[1]);
    std::string passwd(argv[2]);
    std::string rolename(argv[3]);
    std::string db_path(argv[4]);

    // create a role from the rolename
    burg::permission_t role( new Role(rolename));

    // the library is design to get raw char[] messages, not already
    // preprocessed usernames and passwords, so 'simulate' a message from an
    // arbitrary protocol which can be handled by CSVRegex.
    std::string msg = user + "," + passwd;

    // load the user database wich stores passwords as sha256sum in base64
    // format. This database is threadsave, to make concurrent access and
    // database reloads possible.
    burg::user_db_t user_db = burg::user_db_t(new FileUserDB(db_path));

    // load the roles database which holds an array of roles for each user.
    // This database is threadsave, to make concurrent access and
    // database reloads possible.
    burg::roles_db_t roles_db = burg::roles_db_t(new FileRolesDB(db_path));

    // create the user store wich converts the plain password into the
    // corresponding sha256sum. The store abstracts the concrete database away
    burg::user_store_t user_store = burg::user_store_t(
            new SimpleUserStore<Sha256Filter>(user_db));

    // an Authenticator is a stateful object. This means that every connecting
    // client needs its own Authenticator until the authentication process has
    // completed. Therefore a factory method exists, to make spawning
    // authenticators more convenient. After an authentication has finished,
    // the Authenticator can be reused by another connection.
    burg::simple::simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(user_store));
    burg::auth_t auth = factory->create();

    // create a roles store wich stands between the roles database and the
    // Authorizer. The store would be the right spot to implement an LDAP
    // handler, or something similar.
    burg::roles_store_t roles_store = burg::roles_store_t(
            new SimpleRolesStore(roles_db));

    // looking up roles is normally not a stateful task. Therefore there is no
    // factory method for the Authorizer.
    burg::autz_t autz = burg::autz_t(
            new SimpleRegexAuthorizer<PassRegex>(roles_store));

    // start the authentication process.
    burg::Authenticator::auth_s state = auth->authenticate(msg);

    if (state == burg::Authenticator::AUTH_REJECT){
        // authentication failed
        std::cout << "Sorry, no such user or password." << std::endl;
    } else if ( state == burg::Authenticator::AUTH_SUCCESS){
        // authenticaiton was successfull
        std::cout << "Successfully logged in '" << user << "'." << std::endl;

        // retrieve the authentication token.
        burg::token_t token = auth->get_token();

        // load the roles of the authenticated user
        autz->set_permissions(token);

        // test if the authenticated user has the requested permissions
        if (token->has_permission(role)) {
            std::cout << "You have '" << role->id() << "' permissions."
                << std::endl;
        } else {
            std::cout << "Sorry, you do not have '" << role->id()
                << "' permissions." << std::endl;
        }

    } else {
        std::cerr << "This authentication state is not handled by this "
            << "program." << std::endl;
        return EXIT_FAILURE;
    }

return EXIT_SUCCESS;
}
