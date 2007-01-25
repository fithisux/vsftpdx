-- vsftpdx database

-------------------------------------------------------------------------------
-- Drop existing tables
-------------------------------------------------------------------------------
drop table if exists vsf_meta;
drop table if exists vsf_user;
drop table if exists vsf_group;
drop table if exists vsf_member;
drop table if exists vsf_ipmask;
drop table if exists vsf_log;
drop table if exists vsf_event;
drop table if exists vsf_session;
drop table if exists vsf_section;
drop table if exists vsf_perm;

-------------------------------------------------------------------------------
-- Meta data
-------------------------------------------------------------------------------
create table vsf_meta (
  version     integer  not null,
  vstring     text     not null
);

insert into vsf_meta(version, vstring) values(1, 'vsftpdx-2.1.0');

-------------------------------------------------------------------------------
-- Users
-------------------------------------------------------------------------------
create table vsf_user (
  id             integer  primary key,
  name           text     unique not null,
  password       text     null,
  enabled        integer  not null default 1,
  c_time         text     default current_timestamp,
  c_user         text     default 'system',
  m_time         text     default current_timestamp,
  m_user         text     null,
  last_login     text     null
);

-------------------------------------------------------------------------------
-- User groups
-------------------------------------------------------------------------------
create table vsf_group (
  id          integer  primary key,
  name        text     not null
);

-------------------------------------------------------------------------------
-- Group membership
-------------------------------------------------------------------------------
create table vsf_member (
  user_id     integer  not null,
  group_id    integer  not null,
  
  primary key (user_id, group_id)
);

-------------------------------------------------------------------------------
-- Allowed IP masks for users
-------------------------------------------------------------------------------
create table vsf_ipmask (
  id          integer  primary key,
  user_id     integer  not null,
  mask        text     not null,
  ident       text     null
);

-------------------------------------------------------------------------------
-- Log
-------------------------------------------------------------------------------
create table vsf_log (
  id          integer  primary key,
  timestamp   text     default current_timestamp,
  event_id    integer  not null,
  succeeded   integer  not null,
  user        text     not null,
  remote_ip   text     null,
  pid         integer  not null,
  message     text     null,
  path        text     null,
  filesize    double   null,
  duration    double   null
);

-------------------------------------------------------------------------------
-- Log event
-------------------------------------------------------------------------------
create table vsf_event (
  id    integer  not null,
  name  text     not null,
  
  primary key (id, name)  
);


-------------------------------------------------------------------------------
-- Active sessions on the server
-------------------------------------------------------------------------------
create table vsf_session (
  id         integer    primary key,
  user_id    integer    not null,
  remote_ip  text       not null,
  login_time text       default current_timestamp
);


-------------------------------------------------------------------------------
-- Separates the filesystem of the server into multiple sections which may
-- have their own configuration and permission. The path is compared using
-- glob and all missing settings are inherited from the parent.
-------------------------------------------------------------------------------
create table vsf_section (
  id         integer    primary key,
  path       text       not null,
  name       text       null,
  ul_price   float      not null default 1.0,
  dl_price   float      not null default 1.0
);

-------------------------------------------------------------------------------
-- Permissions for a filesystem section. Each permission can have the values
-- 0 = inherit from parent, 1 = implicit allow, -1 = explicit deny
-------------------------------------------------------------------------------
create table vsf_perm (
  id          integer    primary key,
  section_id  integer    not null,
  user_id     integer    null,
  group_id    integer    null,
  file_get    integer    not null default 0,
  file_put    integer    not null default 0,
  file_resume integer    not null default 0,
  file_delete integer    not null default 0,
  file_rename integer    not null default 0,

  dir_view    integer    not null default 0,
  dir_list    integer    not null default 0,
  dir_create  integer    not null default 0,
  dir_del     integer    not null default 0,
  dir_rename  integer    not null default 0  
);


-- Log events
insert into vsf_event(id, name) values( 2, 'download');
insert into vsf_event(id, name) values( 3, 'upload');
insert into vsf_event(id, name) values( 4, 'mkdir');
insert into vsf_event(id, name) values( 5, 'login');
insert into vsf_event(id, name) values( 6, 'ftp input');
insert into vsf_event(id, name) values( 7, 'ftp output');
insert into vsf_event(id, name) values( 8, 'connection');
insert into vsf_event(id, name) values( 9, 'delete');
insert into vsf_event(id, name) values(10, 'rename');
insert into vsf_event(id, name) values(11, 'rmdir');
insert into vsf_event(id, name) values(12, 'chmod');


-- Default user
insert into vsf_user(id, name, password) values (0, 'root', 'vsftpd');
insert into vsf_group(id, name) values (0, 'siteops');
insert into vsf_member(user_id, group_id) values (0, 0);
insert into vsf_ipmask(id, user_id, mask) values (0, 0, '127.0.0.1');
insert into vsf_section(id, path, name) values (0, '/*', 'main');