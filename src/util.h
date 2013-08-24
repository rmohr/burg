#ifndef __BURG_UTIL_H_
#define __BURG_UTIL_H_
#include <libconfig.h++> 
namespace burg {
    namespace util {

        struct ConfigException:public std::exception{

            ConfigException(const std::string msg):_msg(msg){}
            ~ConfigException() throw(){};
            virtual const char* what() const throw() {
                return _msg.c_str();
            }
            private:
            std::string _msg;
        };

        void read_cfg(libconfig::Config& cfg, std::string file_path);
    }
}
#endif
