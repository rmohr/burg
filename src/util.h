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


#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

#include <libconfig.h++>
#include <string>

namespace burg {
    namespace util {

        struct ConfigException:public std::exception {
            explicit ConfigException(const std::string msg):_msg(msg) {}
            ~ConfigException() throw() {}
            virtual const char* what() const throw() {
                return _msg.c_str();
            }
            private:
            std::string _msg;
        };

        void read_cfg(libconfig::Config& cfg, std::string file_path);
    }  // namespace util
}  // namespace burg
#endif  // SRC_UTIL_H_
