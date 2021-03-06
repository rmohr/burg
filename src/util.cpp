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


#include <sstream>
#include <string>
#include "./util.h"

namespace burg {
    namespace util {
        using ::libconfig::Config;
        using ::libconfig::FileIOException;
        using ::libconfig::ParseException;

        void read_cfg(Config& cfg, std::string file_path) {
            try {
                cfg.readFile(file_path.c_str());
            }
            catch(const FileIOException &fioex) {
                throw ConfigException("I/O error while reading file '"
                        + file_path);
            }
            catch(ParseException &pex) {
                std::ostringstream sstream;
                sstream << "Parse error at "<< file_path <<":" <<
                    pex.getLine() << " - " << pex.getError();
                throw ConfigException(sstream.str());
            }
        }
    }  // namespace util
}  // namespace burg
