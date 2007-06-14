
-- Hook for SITE commands
function vsf_site_command(command, args)
  return 200, "Executing: " .. command .. " (" .. args .. ")"
end
