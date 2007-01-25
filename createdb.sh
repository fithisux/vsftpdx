#!/bin/sh

if [ "`uname -s | cut -c -6`" = CYGWIN ]; then
  ./lib/sqlite/cygwin/sqlite3 ./site.db < createdb.sql
else
  sqlite3 ./site.db < createdb.sql
fi
