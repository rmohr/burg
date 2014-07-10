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

#include <burg/db/libconfig.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <string>
#include <vector>

using ::burg::db::FileUserDB;
using ::burg::db::FileRolesDB;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(db, libconfig) {
    burg::user_db_t user_db = burg::user_db_t(new FileUserDB("./db.cfg"));
    burg::roles_db_t roles_db = burg::roles_db_t(new FileRolesDB("./db.cfg"));

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";

    ASSERT_FALSE(user_db->lookup("user123", plain));

    ASSERT_TRUE(user_db->lookup("user123", encrypted));

    burg::roles_vec_t roles = roles_db->lookup("user123");
    std::vector<std::string> expected_roles;
    expected_roles.push_back("admin");
    expected_roles.push_back("user");
    EXPECT_THAT(expected_roles, ::testing::ContainerEq(*roles));
}

