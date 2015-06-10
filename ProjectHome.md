This project aims to extend the popular [vsftpd](http://vsftpd.beasts.org) FTP server by Chris Evans.

**Goals**
  * maintain the stability and security of vsftpd
  * add features to make vsftpd more suitable for closed private servers
    * virtual users stored in a [SQLite](http://www.sqlite.org) database
    * log into the database, which allows to calculate transfer stats easily
    * virtual permission system independent of filesystem permissions
    * Windows/Cygwin support (based on a patch by Jason Tishler)
  * port useful features from the discontinued OpenFTPD project to vsftpdx

**Roadmap**
  * release a first public version (very soon)
  * finish core features like the permission system (some weeks)
  * add SITE commands for server and data management (some weeks)
  * port all useful features from OpenFTPD to vsftpdx (several weeks)
  * write a web based or native admin tool (later)
  * add scripting support for Ruby, Python or Lua (later)

**Wanted**
  * coders for the core project (good C skills!)
  * coders for an web based admin tool (C, PHP, Ruby, whatever)
  * documentation writers
  * beta testers
  * comments and feature requests
  * maintainers for binary packages (deb/rpm)

**Thanks**
> Big thanks to Chris Evans for writing a great piece of software with an
> exceptionally clean design and very readable and well documented code.

**Contact**
> You can send me an email to robert.hahn at gmail.com

Robert (2007-01-25)