-- require "path"
require "sqlite3"

local db = sqlite3.open_memory()

result = ""

db:exec[[
  CREATE TABLE test (id INTEGER PRIMARY KEY, content);

  INSERT INTO test VALUES (NULL, 'Hello World');
  INSERT INTO test VALUES (NULL, 'Hello Lua');
  INSERT INTO test VALUES (NULL, 'Hello Sqlite3')
]]

for row in db:rows("SELECT * FROM test") do
  result = result .. row.id .. " = " .. row.content .. "\n"
end 

result = result .. 'Lua test ' .. os.date() .. '\n'
return result


