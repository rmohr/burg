#
# Copyright 2013, Roman Mohr <roman@fenkhuber.at>
#
# This file is part of burg.
#
# Burg is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Burg is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with burg.  If not, see <http://www.gnu.org/licenses/>.
#

nobase_include_HEADERS = burg/auth/simple.h burg/store/simple.h burg/filters/plain.h burg/db.h burg/auth.h

if HAVE_PAM
nobase_include_HEADERS += burg/db/pam.h
endif

if HAVE_LIBCONFIG
nobase_include_HEADERS += burg/db/libconfig.h
endif

if HAVE_CRYPTO
nobase_include_HEADERS += burg/filters/crypto.h
endif

