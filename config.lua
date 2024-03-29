-- VsftpdX example config script
--
-- This is the default config file for a private FTP server with virtual users
-- stored in a SQLite database. All database related features are enabled. Make
-- sure you create a database before starting vsftpd using the createdb.sh 
-- script.
--
-- READ THIS: This example file is NOT an exhaustive list of vsftpd options.
-- Please read the vsftpd.conf.5 manual page to get a full idea of vsftpd's
-- capabilities.
--

anonymous_enable        = NO
listen                  = YES
listen_port             = 21
--pasv_min_port         = 20000
--pasv_max_port         = pasv_min_port + 100
--pasv_address          = 123.123.123.123
run_as_launching_user   = YES

-- Scripts wont work with chroot!
chroot_local_user       = NO
local_enable            = YES
write_enable            = YES
dirmessage_enable       = YES
xferlog_enable          = YES
connect_from_port_20    = NO

script_dir              = "scripts/"
local_root              = "/cygdrive/c/temp"
ftpd_banner             = "Welcome to vsftpdx."

-- Drop priviledges (does not work on cygwin yet)
--ftp_username=dummy
--nopriv_user=dummy
--secure_chroot_dir=/cygdrive/c/temp

-- SSL configuration
ssl_enable              = NO
rsa_cert_file           = "site.pem"
allow_anon_ssl          = YES

anon_upload_enable      = YES
anon_mkdir_write_enable = YES
write_enable            = YES
hide_ids                = YES

-- FXP
pasv_enable             = YES
pasv_promiscuous        = YES
port_enable             = YES
port_promiscuous        = YES

-- Extensions
sqlite_enable           = YES
sqlite_log              = YES
sqlite_acl              = YES
ident_check_enable      = YES
stealth_mode            = YES
credit_enable           = YES
show_infoline           = YES

-- END OF CONFIGURATION --------------------------------------------------------
