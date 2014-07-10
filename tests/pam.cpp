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

#include <burg/db/pam.h>
#include <gtest/gtest.h>

#include <iostream>
#include <string>
#include <vector>

using ::burg::db::PamUserDB;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(db, pam) {
    if (getpwnam("test") == NULL || getuid() != 0) return;
    burg::user_db_t pam_db = burg::user_db_t(new PamUserDB("passwd"));
    ASSERT_TRUE(pam_db->lookup("test", "test"));
    ASSERT_FALSE(pam_db->lookup("test1", "test"));
    ASSERT_FALSE(pam_db->lookup("test", "test1"));
    ASSERT_FALSE(pam_db->lookup("test1", "test1"));
}


