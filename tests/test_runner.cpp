/*
 *  Copyright 2013, Roman Mohr <roman@fenkhuber.at>
 *
 *  This file is part of burg.
 *
 *  Burg is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Burg is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with burg.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pwd.h>

#include <boost/foreach.hpp>

#include <burg/db/libconfig.h>
#include <burg/auth/simple.h>
#include <burg/store/simple.h>
#include <burg/db/pam.h>
#include <burg/filters/crypto.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <iostream>
#include <string>
#include <vector>
#include "./mock.h"

using ::testing::Return;
using ::testing::_;
using ::testing::InSequence;

using ::burg::filters::Sha256Filter;
using ::burg::filters::PlainFilter;
using ::burg::db::FileUserDB;
using ::burg::db::FileRolesDB;
using ::burg::store::SimpleUserStore;
using ::burg::store::SimpleRolesStore;
using ::burg::auth::SimpleRegexAuthenticator;
using ::burg::auth::SimpleRegexAuthorizer;
using ::burg::auth::CSVRegex;
using ::burg::auth::PassRegex;
using ::burg::auth::simple_auth_t;
using ::burg::auth::Role;

int main(int argc, char** argv) {
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(basicTests, token) {
    burg::token_t token = burg::token_t(new burg::auth::SimpleToken("roman"));
    ASSERT_EQ(token->id(), "roman");
}

TEST(basicTests, permissions) {
    burg::permission_t permission = burg::permission_t(
            new Role("admin"));
    burg::permission_t permission1 = burg::permission_t(
            new Role("user"));
    ASSERT_TRUE(permission->satisfies(permission));
    ASSERT_FALSE(permission->satisfies(permission1));
    ASSERT_FALSE(permission1->satisfies(permission));
}

TEST(basicTests, libconfig_db) {
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

TEST(basicTests, pam_db) {
    if (getpwnam("test") == NULL || getuid() != 0) return;
    burg::user_db_t pam_db = burg::user_db_t(new burg::db::PamUserDB("passwd"));
    ASSERT_TRUE(pam_db->lookup("test", "test"));
    ASSERT_FALSE(pam_db->lookup("test1", "test"));
    ASSERT_FALSE(pam_db->lookup("test", "test1"));
    ASSERT_FALSE(pam_db->lookup("test1", "test1"));
}


TEST(mockTests, user_stores) {
    MockUserDB* sha_user_db_ptr = new MockUserDB();
    MockUserDB* plain_user_db_ptr = new MockUserDB();
    burg::user_db_t sha_user_db(sha_user_db_ptr);
    burg::user_db_t plain_user_db(plain_user_db_ptr);
    burg::user_store_t sha_user_store = burg::user_store_t(
            new SimpleUserStore<Sha256Filter>(sha_user_db));
    burg::user_store_t plain_user_store = burg::user_store_t(
            new SimpleUserStore<PlainFilter>(plain_user_db));

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";

    EXPECT_CALL(*sha_user_db_ptr, lookup("roman", _)).WillOnce(Return(false));
    EXPECT_CALL(*plain_user_db_ptr, lookup("roman", _)).WillOnce(Return(false));
    EXPECT_CALL(*sha_user_db_ptr, lookup("roman", encrypted))
        .WillOnce(Return(true));
    EXPECT_CALL(*plain_user_db_ptr, lookup("roman", plain))
        .WillOnce(Return(true));

    EXPECT_TRUE(sha_user_store->authenticate("roman", plain));
    EXPECT_FALSE(sha_user_store->authenticate("roman", encrypted));

    EXPECT_TRUE(plain_user_store->authenticate("roman", plain));
    EXPECT_FALSE(plain_user_store->authenticate("roman", encrypted));
}

TEST(mockTests, roles_stores) {
    MockRolesDB* roles_db_ptr = new MockRolesDB();
    burg::roles_db_t roles_db(roles_db_ptr);
    burg::roles_store_t roles_store = burg::roles_store_t(
            new SimpleRolesStore(roles_db));


    burg::roles_vec_t empty(new burg::roles_t_vec());
    burg::roles_vec_t full(new burg::roles_t_vec());
    full->push_back("admin");
    full->push_back("user");

    EXPECT_CALL(*roles_db_ptr, lookup(_)).WillOnce(Return(empty));
    EXPECT_CALL(*roles_db_ptr, lookup("roman")).WillOnce(Return(full));

    EXPECT_THAT(*empty,
            ::testing::ContainerEq(*(roles_store->get_roles("anonymous"))));
    EXPECT_THAT(*full,
            ::testing::ContainerEq(*(roles_store->get_roles("roman"))));
}


TEST(fullChainTests, simpleTest) {
    burg::user_db_t user_db = burg::user_db_t(new FileUserDB("./db.cfg"));
    burg::roles_db_t roles_db = burg::roles_db_t(new FileRolesDB("./db.cfg"));

    burg::user_store_t store = burg::user_store_t(
            new SimpleUserStore<Sha256Filter>(user_db));
    burg::roles_store_t roles_store = burg::roles_store_t(
            new SimpleRolesStore(roles_db));

    simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(store));
    burg::auth_t auth = factory->create();

    ASSERT_EQ(burg::Authenticator::AUTH_REJECT,
            auth->authenticate("roma,hallo"));
    ASSERT_EQ(burg::Authenticator::AUTH_REJECT,
            auth->authenticate("roman,hllo"));
    ASSERT_EQ(burg::Authenticator::AUTH_SUCCESS,
            auth->authenticate("roman,hallo"));
    burg::token_t token = auth->get_token();

    burg::autz_t autz = burg::autz_t(
            new SimpleRegexAuthorizer<PassRegex>(roles_store));
    autz->set_permissions(token);
    burg::permission_t perm_yes = burg::permission_t(
            new Role("admin"));
    burg::permission_t perm_no = burg::permission_t(
            new Role("blub"));

    ASSERT_TRUE(token->has_permission(perm_yes));
    ASSERT_FALSE(token->has_permission(perm_no));
}
