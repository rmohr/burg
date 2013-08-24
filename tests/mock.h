#ifndef __BURG_MOCK_H_
#define __BURG_MOCK_H_

#include "gmock/gmock.h"
#include "burg/db.h"

struct MockUserDB : public burg::UserDB {

    MOCK_METHOD0(reload,void());

    MOCK_METHOD2(lookup, bool(const std::string& user, const std::string& passwd));
};

struct MockRolesDB : public burg::RolesDB {

    MOCK_METHOD0(reload,void());

    MOCK_METHOD1(lookup,burg::roles_vec_t(const std::string& user));
};

struct MockUserStore : public burg::UserStore {

    MOCK_METHOD2(authenticate, bool(const std::string& user, const std::string& passwd));

};

struct MockRolesStore : public burg::RolesStore {

    MOCK_METHOD1(get_roles,burg::roles_vec_t(const std::string& user));

};

#endif
