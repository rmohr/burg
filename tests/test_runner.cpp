#include "burg/simple_db.h"
#include "burg/simple_auth.h"
#include <iostream>
#include <boost/foreach.hpp>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "mock.h"

using ::testing::Return;
using ::testing::_;
using ::testing::InSequence;

int main(int argc, char** argv){
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(basicTests, token) {
    burg::token_t token = burg::token_t(new burg::simple::SimpleToken("roman"));
    ASSERT_EQ(token->id(), "roman");
}

TEST(basicTests, permissions) {
    burg::permission_t permission = burg::permission_t(new burg::simple::Role("admin"));
    burg::permission_t permission1 = burg::permission_t(new burg::simple::Role("user"));
    ASSERT_TRUE (permission->satisfies(permission));
    ASSERT_FALSE (permission->satisfies(permission1));
    ASSERT_FALSE (permission1->satisfies(permission));
}

TEST(basicTests, databases) {
    using namespace burg::simple;
    burg::user_db_t user_db = burg::user_db_t(new FileUserDB("./db.cfg"));
    burg::roles_db_t roles_db = burg::roles_db_t(new FileRolesDB("./db.cfg"));

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";

    ASSERT_FALSE(user_db->lookup("roman", plain));

    ASSERT_TRUE(user_db->lookup("roman", encrypted));
    
    burg::roles_vec_t roles = roles_db->lookup("roman");
    std::vector<std::string> expected_roles;
    expected_roles.push_back("admin");
    expected_roles.push_back("user");
    EXPECT_THAT(expected_roles, ::testing::ContainerEq(*roles));

}


TEST(mockTests, user_stores) {

    using namespace burg::simple;
    MockUserDB* sha_user_db_ptr = new MockUserDB();
    MockUserDB* plain_user_db_ptr = new MockUserDB();
    burg::user_db_t sha_user_db(sha_user_db_ptr);
    burg::user_db_t plain_user_db(plain_user_db_ptr);
    burg::user_store_t sha_user_store = burg::user_store_t(new SimpleUserStore<Sha256Filter>(sha_user_db));
    burg::user_store_t plain_user_store = burg::user_store_t(new SimpleUserStore<PlainFilter>(plain_user_db));

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";

    EXPECT_CALL(*sha_user_db_ptr, lookup("roman", _)).WillOnce(Return(false));
    EXPECT_CALL(*plain_user_db_ptr, lookup("roman", _)).WillOnce(Return(false));
    EXPECT_CALL(*sha_user_db_ptr, lookup("roman", encrypted)).WillOnce(Return(true));
    EXPECT_CALL(*plain_user_db_ptr, lookup("roman", plain)).WillOnce(Return(true));

    EXPECT_TRUE(sha_user_store->authenticate("roman", plain));
    EXPECT_FALSE(sha_user_store->authenticate("roman", encrypted));

    EXPECT_TRUE(plain_user_store->authenticate("roman", plain));
    EXPECT_FALSE(plain_user_store->authenticate("roman", encrypted));
}

TEST(mockTests, roles_stores) {

    using namespace burg::simple;
    MockRolesDB* roles_db_ptr = new MockRolesDB();
    burg::roles_db_t roles_db(roles_db_ptr);
    burg::roles_store_t roles_store = burg::roles_store_t(new SimpleRolesStore(roles_db));


    burg::roles_vec_t empty(new burg::roles_t_vec());
    burg::roles_vec_t full(new burg::roles_t_vec());
    full->push_back("admin");
    full->push_back("user");

    EXPECT_CALL(*roles_db_ptr, lookup(_)).WillOnce(Return(empty));
    EXPECT_CALL(*roles_db_ptr, lookup("roman")).WillOnce(Return(full));

    EXPECT_THAT(*empty, ::testing::ContainerEq(*(roles_store->get_roles("anonymous"))));
    EXPECT_THAT(*full, ::testing::ContainerEq(*(roles_store->get_roles("roman"))));
}


TEST(fullChainTests, simpleTest) {

    using namespace burg::simple;
    burg::user_db_t user_db = burg::user_db_t(new FileUserDB("./db.cfg"));
    burg::roles_db_t roles_db = burg::roles_db_t(new FileRolesDB("./db.cfg"));

    burg::user_store_t store = burg::user_store_t(new SimpleUserStore<Sha256Filter>(user_db));
    burg::roles_store_t roles_store = burg::roles_store_t(new SimpleRolesStore(roles_db));

    simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(store));
    burg::auth_t auth = factory->create();

    ASSERT_EQ (burg::Authenticator::AUTH_REJECT, auth->authenticate("roma,hallo"));
    ASSERT_EQ (burg::Authenticator::AUTH_REJECT, auth->authenticate("roman,hllo"));
    ASSERT_EQ (burg::Authenticator::AUTH_SUCCESS, auth->authenticate("roman,hallo"));
    burg::token_t token = auth->get_token();

    burg::autz_t autz = burg::autz_t(new SimpleRegexAuthorizer<PassRegex>(roles_store));
    autz->set_permissions(token);
    burg::permission_t perm_yes = burg::permission_t(new burg::simple::Role("admin"));
    burg::permission_t perm_no = burg::permission_t(new burg::simple::Role("blub"));

    ASSERT_TRUE( token->has_permission(perm_yes));
    ASSERT_FALSE( token->has_permission(perm_no));
}

void lala( int basicTests, int simpleTest) {
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
}
