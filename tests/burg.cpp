/*
 *  Copyright 2013, Roman Mohr <user123@fenkhuber.at>
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

#include <burg/auth/simple.h>
#include <burg/store/simple.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <iostream>
#include <string>
#include <vector>
#include "./mock.h"

using ::testing::Return;
using ::testing::_;
using ::testing::InSequence;

using ::burg::filters::PlainFilter;
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
    burg::token_t token = burg::token_t(new burg::auth::SimpleToken("user123"));
    ASSERT_EQ(token->id(), "user123");
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

TEST(filters, plain) {
    PlainFilter filter;

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";
    ASSERT_EQ(filter.encrypt(plain), plain);
    ASSERT_EQ(filter.encrypt(encrypted), encrypted);
}


TEST(stores, user) {
    MockUserDB* plain_user_db_ptr = new MockUserDB();
    burg::user_db_t plain_user_db(plain_user_db_ptr);
    burg::user_store_t plain_user_store = burg::user_store_t(
            new SimpleUserStore<PlainFilter>(plain_user_db));

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";

    EXPECT_CALL(*plain_user_db_ptr, lookup("user123", _)).WillOnce(Return(false));
    EXPECT_CALL(*plain_user_db_ptr, lookup("user123", plain))
        .WillOnce(Return(true));

    EXPECT_TRUE(plain_user_store->authenticate("user123", plain));
    EXPECT_FALSE(plain_user_store->authenticate("user123", encrypted));
}

TEST(stores, roles) {
    MockRolesDB* roles_db_ptr = new MockRolesDB();
    burg::roles_db_t roles_db(roles_db_ptr);
    burg::roles_store_t roles_store = burg::roles_store_t(
            new SimpleRolesStore(roles_db));

    burg::roles_vec_t empty(new burg::roles_t_vec());
    burg::roles_vec_t full(new burg::roles_t_vec());
    full->push_back("admin");
    full->push_back("user");

    EXPECT_CALL(*roles_db_ptr, lookup(_)).WillOnce(Return(empty));
    EXPECT_CALL(*roles_db_ptr, lookup("user123")).WillOnce(Return(full));

    EXPECT_THAT(*empty,
            ::testing::ContainerEq(*(roles_store->get_roles("anonymous"))));
    EXPECT_THAT(*full,
            ::testing::ContainerEq(*(roles_store->get_roles("user123"))));
}

TEST(integration, simpleTest) {
    MockRolesDB* roles_db_ptr = new MockRolesDB();
    burg::roles_db_t roles_db(roles_db_ptr);
    MockUserDB* user_db_ptr = new MockUserDB();
    burg::user_db_t user_db(user_db_ptr);

    EXPECT_CALL(*user_db_ptr, lookup(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*user_db_ptr, lookup("user123", "hallo"))
        .WillOnce(Return(true));

    burg::roles_vec_t admin_perm_vec(new burg::roles_t_vec());
    admin_perm_vec->push_back("admin");

    EXPECT_CALL(*roles_db_ptr, lookup("user123")).WillOnce(Return(admin_perm_vec));

    burg::user_store_t store = burg::user_store_t(
            new SimpleUserStore<PlainFilter>(user_db));
    burg::roles_store_t roles_store = burg::roles_store_t(
            new SimpleRolesStore(roles_db));

    simple_auth_t factory(new SimpleRegexAuthenticator<CSVRegex>(store));
    burg::auth_t auth = factory->create();

    ASSERT_EQ(burg::Authenticator::AUTH_REJECT,
            auth->authenticate("roma,hallo"));
    ASSERT_EQ(burg::Authenticator::AUTH_REJECT,
            auth->authenticate("user123,hllo"));
    ASSERT_EQ(burg::Authenticator::AUTH_SUCCESS,
            auth->authenticate("user123,hallo"));
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
