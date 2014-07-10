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

#include <burg/filters/crypto.h>
#include <gtest/gtest.h>

using ::burg::filters::Sha256Filter;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(filters, sha256) {
    Sha256Filter filter;

    std::string encrypted = "03UdM/nNUEnErytGJzVFfk07rxMLy7h/OJ40n7rrILk=";
    std::string plain = "hallo";
    ASSERT_EQ(filter.encrypt(plain), encrypted);
}

