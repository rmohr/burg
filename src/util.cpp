#include "util.h"
#include <sstream>

namespace util {
    using namespace libconfig;
    void read_cfg (Config& cfg, std::string file_path){
        try
        {
            cfg.readFile(file_path.c_str());
        }
        catch(const FileIOException &fioex)
        {
            throw ConfigException("I/O error while reading file '" + file_path);
        }
        catch(const ParseException &pex)
        {
            std::ostringstream sstream;
            sstream << "Parse error at "<< pex.getFile() <<":" <<
                pex.getLine() << " - " << pex.getError();
            throw ConfigException(sstream.str());
        }
    }
}
