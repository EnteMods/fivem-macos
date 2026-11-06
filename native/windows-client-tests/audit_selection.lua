-- Execute original Cfx selection and original Premake traversal on a read-only tree snapshot.
local manifest_file, premake_dir, output_file = assert(arg[1]), assert(arg[2]), assert(arg[3])
local manifest = dofile(manifest_file)
local file_set, directory_set = {}, {}
for _, entry in ipairs(manifest) do
    (entry.file and file_set or directory_set)[entry.name] = true
end

function string.findlast(value, needle, plain)
    local position, next_position = nil, 1
    while true do
        local found = value:find(needle, next_position, plain)
        if not found then return position end
        position, next_position = found, found + 1
    end
end
function table.join(...)
    local result = {}
    for _, values in ipairs({...}) do
        for _, value in ipairs(values) do result[#result + 1] = value end
    end
    return result
end
path = {}
function path.normalize(value) return value:gsub("\\", "/"):gsub("/+", "/") end
function path.join(...)
    local result = ""
    for index = 1, select("#", ...) do
        local part = select(index, ...)
        if part and part ~= "" then result = result == "" and part or result .. "/" .. part end
    end
    return path.normalize(result)
end
premake = {override = function(target, name, callback)
    local base = target[name]
    target[name] = function(...) return callback(base, ...) end
end}
dofile(premake_dir .. "/src/base/path.lua")
dofile(premake_dir .. "/src/base/os.lua")

local function local_pattern(mask)
    return "^" .. mask:gsub("([%^%$%(%)%%%.%[%]%+%-%?])", "%%%1"):gsub("%*", "[^/]*") .. "$"
end
function os.matchstart(mask)
    assert(not mask:find("**", 1, true), "Original os.match must resolve recursion before low-level matchstart")
    local state = {entries = {}, position = 0}
    for _, entry in ipairs(manifest) do
        if entry.name:match(local_pattern(mask)) then state.entries[#state.entries + 1] = entry end
    end
    return state
end
function os.matchnext(state) state.position = state.position + 1; return state.entries[state.position] ~= nil end
function os.matchname(state) return state.entries[state.position].name:match("[^/]+$") end
function os.matchisfile(state) return state.entries[state.position].file end
function os.matchdone(_) end
function os.isfile(name) return file_set[path.normalize(name)] == true end
function os.isdir(name) return directory_set[path.normalize(name)] == true end

local raw_matchfiles = os.matchfiles
local glob_calls, descriptors = {}, {}
os.matchfiles = function(mask)
    local result = raw_matchfiles(mask)
    glob_calls[#glob_calls + 1] = {mask = mask, results = result}
    return result
end
local raw_open = io.open
io.open = function(name, mode)
    if name:match("build%.info$") then
        assert(not mode or mode == "r", "Descriptor writes are forbidden")
        descriptors[name] = true
    end
    return raw_open(name, mode)
end

_OPTIONS = {game = "five"}
includedirs = function(_) end
defines = function(_) end
filter = function(_) end
printf = function(...) error("Unexpected original generator diagnostic") end
local selected, current = {crypto = {}, ssl = {}}, "crypto"
files = function(values)
    for _, value in ipairs(values) do selected[current][#selected[current] + 1] = value end
end
local original = dofile("vendor/openssl_ext.lua")
local config = dofile("vendor/openssl_cfg.lua")
original.crypto_project(config)
current = "ssl"
original.ssl_project(config)

local out = assert(raw_open(output_file, "w"))
for _, group in ipairs({"crypto", "ssl"}) do
    table.sort(selected[group])
    for _, name in ipairs(selected[group]) do out:write("source\t", group, "\t", name, "\n") end
end
local ordered = {}
for name in pairs(descriptors) do ordered[#ordered + 1] = name end
table.sort(ordered)
for _, name in ipairs(ordered) do out:write("descriptor\t", name, "\n") end
for _, call in ipairs(glob_calls) do
    for _, name in ipairs(call.results) do out:write("glob\t", call.mask, "\t", name, "\n") end
end
out:close()
print("ORIGINAL_OPENSSL_LUA_SELECTION crypto=" .. #selected.crypto .. " ssl=" .. #selected.ssl)
