#ifndef VSF_TUNABLES_H
#define VSF_TUNABLES_H

/* Configurable preferences */
/* Booleans */
extern int tunable_anonymous_enable;          /* Allow anon logins */
extern int tunable_local_enable;              /* Allow local logins */
extern int tunable_pasv_enable;               /* Allow PASV */
extern int tunable_port_enable;               /* Allow PORT */
extern int tunable_chroot_local_user;         /* Restrict local to home dir */
extern int tunable_write_enable;              /* Global enable writes */
extern int tunable_anon_upload_enable;        /* Enable STOR for anon users */
extern int tunable_anon_mkdir_write_enable;   /* MKD for anon */
extern int tunable_anon_other_write_enable;   /* APPE DELE RMD RNFR for anon */
extern int tunable_chown_uploads;             /* chown() anon uploaded files */
extern int tunable_connect_from_port_20;      /* PORT connects from port 20 */
extern int tunable_xferlog_enable;            /* Log transfers to a file */
extern int tunable_dirmessage_enable;         /* Look for + output .message */
extern int tunable_anon_world_readable_only;  /* Only serve world readable */
extern int tunable_async_abor_enable;         /* Enable async ABOR requests */
extern int tunable_ascii_upload_enable;       /* Permit ASCII upload */
extern int tunable_ascii_download_enable;     /* Permit ASCII download */
extern int tunable_one_process_model;         /* Go faster stripes ;-) */
extern int tunable_xferlog_std_format;        /* Log details like wu-ftpd */
extern int tunable_pasv_promiscuous;          /* Allow any PASV connect IP */
extern int tunable_deny_email_enable;         /* Ban a list of anon e-mails */
extern int tunable_chroot_list_enable;        /* chroot() based on list file */
extern int tunable_setproctitle_enable;       /* Try to use setproctitle() */
extern int tunable_text_userdb_names;         /* For "ls", lookup text names */
extern int tunable_ls_recurse_enable;         /* Allow ls -R */
extern int tunable_log_ftp_protocol;          /* Log FTP requests/responses */
extern int tunable_guest_enable;              /* Remap guest users */
extern int tunable_userlist_enable;           /* Explicit user allow or deny */
extern int tunable_userlist_deny;             /* Is user list allow or deny? */
extern int tunable_use_localtime;             /* Use local time or GMT? */
extern int tunable_check_shell;               /* Use /etc/shells for non-PAM */
extern int tunable_hide_ids;                  /* Show "ftp" in ls listings */
extern int tunable_listen;                    /* Standalone (no inetd) mode? */
extern int tunable_port_promiscuous;          /* Any any PORT connect IP */
extern int tunable_passwd_chroot_enable;      /* chroot() based on passwd */
extern int tunable_no_anon_password;          /* Do not ask for anon pword */
extern int tunable_tcp_wrappers;              /* Standalone: do tcp wrappers */
extern int tunable_use_sendfile;              /* Use sendfile() if we can */
extern int tunable_force_dot_files;           /* Show dotfiles without -a */
extern int tunable_listen_ipv6;               /* Standalone with IPv6 listen */
extern int tunable_dual_log_enable;           /* Log vsftpd.log AND xferlog */
extern int tunable_syslog_enable;             /* Use syslog not vsftpd.log */
extern int tunable_background;                /* Background listener process */
extern int tunable_virtual_use_local_privs;   /* Virtual user => local privs */
extern int tunable_session_support;           /* utmp, wtmp, pam_session */
extern int tunable_download_enable;           /* Can download anything? */
extern int tunable_dirlist_enable;            /* Can see any dirs? */
extern int tunable_chmod_enable;              /* Is CHMOD allowed? (local) */
extern int tunable_secure_email_list_enable;  /* Require specific anon email */
extern int tunable_run_as_launching_user;     /* Runs as launching user */
extern int tunable_no_log_lock;               /* Don't lock log files */
extern int tunable_ssl_enable;                /* Allow SSL/TLS AUTH */
extern int tunable_allow_anon_ssl;            /* Allow anonymous use of SSL */
extern int tunable_force_local_logins_ssl;    /* Require local logins use SSL */
extern int tunable_force_local_data_ssl;      /* Require local data uses SSL */
extern int tunable_sslv2;                     /* Allow SSLv2 */
extern int tunable_sslv3;                     /* Allow SSLv3 */
extern int tunable_tlsv1;                     /* Allow TLSv1 */
extern int tunable_tilde_user_enable;         /* Support e.g. ~chris */
extern int tunable_force_anon_logins_ssl;     /* Require anon logins use SSL */
extern int tunable_force_anon_data_ssl;       /* Require anon data uses SSL */
extern int tunable_mdtm_write;                /* Allow MDTM to set timestamps */
extern int tunable_lock_upload_files;         /* Lock uploading files */
extern int tunable_pasv_addr_resolve;         /* DNS resolve pasv_addr */
/* Extensions */
extern int tunable_sqlite_enable;             /* Use SQLite database */
extern int tunable_sqlite_log;                /* Use SQLite for logging */
extern int tunable_calc_crc32;                /* Calc CRC32 during transfer */
extern int tunable_ident_check_enable;        /* Check RFC1413 idents */
extern int tunable_stealth_mode;              /* Hide if remote IP is unknown */
extern int tunable_sqlite_acl;                /* Use access control lists */
extern int tunable_credit_enable;             /* Enable the credit system */
extern int tunable_show_infoline;             /* Show infoline on list */

/* Integer/numeric defines */
extern unsigned int tunable_accept_timeout;
extern unsigned int tunable_connect_timeout;
extern unsigned int tunable_local_umask;
extern unsigned int tunable_anon_umask;
extern unsigned int tunable_ftp_data_port;
extern unsigned int tunable_idle_session_timeout;
extern unsigned int tunable_data_connection_timeout;
extern unsigned int tunable_pasv_min_port;
extern unsigned int tunable_pasv_max_port;
extern unsigned int tunable_anon_max_rate;
extern unsigned int tunable_local_max_rate;
extern unsigned int tunable_listen_port;
extern unsigned int tunable_max_clients;
extern unsigned int tunable_file_open_mode;
extern unsigned int tunable_max_per_ip;
extern unsigned int tunable_trans_chunk_size;
extern unsigned int tunable_delay_failed_login;
extern unsigned int tunable_delay_successful_login;
extern unsigned int tunable_max_login_fails;
/* Extensions*/
extern unsigned int tunable_ident_check_timeout;

/* String defines */
extern const char* tunable_secure_chroot_dir;
extern const char* tunable_ftp_username;
extern const char* tunable_chown_username;
extern const char* tunable_xferlog_file;
extern const char* tunable_vsftpd_log_file;
extern const char* tunable_message_file;
extern const char* tunable_nopriv_user;
extern const char* tunable_ftpd_banner;
extern const char* tunable_banned_email_file;
extern const char* tunable_chroot_list_file;
extern const char* tunable_pam_service_name;
extern const char* tunable_guest_username;
extern const char* tunable_userlist_file;
extern const char* tunable_anon_root;
extern const char* tunable_local_root;
extern const char* tunable_banner_file;
extern const char* tunable_pasv_address;
extern const char* tunable_listen_address;
extern const char* tunable_user_config_dir;
extern const char* tunable_listen_address6;
extern const char* tunable_cmds_allowed;
extern const char* tunable_hide_file;
extern const char* tunable_deny_file;
extern const char* tunable_user_sub_token;
extern const char* tunable_email_password_file;
extern const char* tunable_rsa_cert_file;
extern const char* tunable_dsa_cert_file;
extern const char* tunable_ssl_ciphers;
extern const char* tunable_rsa_private_key_file;
extern const char* tunable_dsa_private_key_file;

#endif /* VSF_TUNABLES_H */

