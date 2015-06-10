### vsf\_user ###
|  id            | integer | primary key               | Unique ID                |
|:---------------|:--------|:--------------------------|:-------------------------|
|  name          | text    | unique not null           | Unique name              |
|  password      | text    | null                      | Password (MD5 hash)      |
|  enabled       | integer | not null default 1        | Account enabled          |
|  ul\_price      | double  | not null default 0.0      | Upload reward credit/mb  |
|  dl\_price      | double  | not null default 0.0      | Download cost credit/mb  |
|  c\_time        | text    | default current\_timestamp | Creation time            |
|  c\_user        | text    | default 'system'          | Creator                  |
|  m\_time        | text    | default current\_timestamp | Modification time        |
|  m\_user        | text    | null                      | Changer                  |
|  last\_login    | text    | null                      | Last login time          |


### vsf\_ipmask ###
|  id           | integer  | primary key               | Unique ID                |
|:--------------|:---------|:--------------------------|:-------------------------|
|  user\_id      | integer  | not null                  | User ID (FK)             |
|  mask         | text     | not null                  | IP mask (e.g. `127.0.0.*`) |
|  ident        | text     | null                      | Ident name               |


TODO: All other tables :)



