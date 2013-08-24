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


#ifndef TESTS_MOCK_H_
#define TESTS_MOCK_H_

#include <gmock/gmock.h>
#include <string>

#include "burg/db.h"

struct MockUserDB : public burg::UserDB {
    MOCK_METHOD0(reload, void());

    MOCK_METHOD2(lookup,
            bool(const std::string& user, const std::string& passwd));
};

struct MockRolesDB : public burg::RolesDB {
    MOCK_METHOD0(reload, void());

    MOCK_METHOD1(lookup, burg::roles_vec_t(const std::string& user));
};

struct MockUserStore : public burg::UserStore {
    MOCK_METHOD2(authenticate,
            bool(const std::string& user, const std::string& passwd));
};

struct MockRolesStore : public burg::RolesStore {
    MOCK_METHOD1(get_roles, burg::roles_vec_t(const std::string& user));
};

#endif  // TESTS_MOCK_H_
