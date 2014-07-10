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

#include <assert.h>
#include <security/pam_appl.h>
#include <stdio.h>

#include <stdexcept>
#include <string>

#include "./db/pam.h"

#define TRY(x) ret = (x); if (ret != PAM_SUCCESS) goto finally

namespace burg {

    namespace db {

        namespace {
            int _test_conv(int num_msg, const struct pam_message **msg,
                    struct pam_response **resp, void *appdata_ptr){
                const struct pam_message* msg_ptr = *msg;
                struct pam_response * resp_ptr = NULL;
                int x = 0;
                const char* passwd = static_cast<const char*>(appdata_ptr);
                *resp = reinterpret_cast<struct pam_response*>(
                        calloc(sizeof(struct pam_response), num_msg));
                for (x = 0; x < num_msg; x++, msg_ptr++){
                    char* resp_str;
                    switch (msg_ptr->msg_style){
                        case PAM_PROMPT_ECHO_OFF:
                        case PAM_PROMPT_ECHO_ON:
                            resp[x]->resp= strdup(passwd);
                            break;

                        case PAM_ERROR_MSG:
                        case PAM_TEXT_INFO:
                            break;

                        default:
                            assert(0);

                    }
                }
                return PAM_SUCCESS;
            }
        }

        PamUserDB::PamUserDB(const std::string& stack_name):
            _stack_name(stack_name) {}

        void PamUserDB::reload() {}

        bool PamUserDB::lookup(const std::string& user,
                const std::string& passwd) {
            const char *changed_username = NULL;
            struct pam_conv conv;
            int ret;
             pam_handle_t* handle;
            conv.conv = _test_conv;
            conv.appdata_ptr = static_cast<void*>(const_cast<char*>(passwd.c_str()));

            TRY( pam_start(_stack_name.c_str(), user.c_str(), &conv, &handle ));
            TRY( pam_authenticate(handle, 0));
            TRY( pam_acct_mgmt(handle, 0));
            TRY( pam_get_item(handle, PAM_USER,(const void**) &changed_username ));
            if (changed_username != NULL && strcmp(user.c_str(), changed_username) != 0 ) {
                throw std::runtime_error("Username change by PAM is not supported.");
            }
        finally:
            pam_end(handle, ret);
            return ret == PAM_SUCCESS ? true : false;
        }

    }  // namespace db

}  // namespace burg
