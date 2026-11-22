-- The sweep of the limiter's keyspace (admin-r15-1, admin-r15-4). It is run by maintain.sh as the `maint`
-- user, never by a service: it is not in internal/ratelimit/lua, whose files both services may EVALSHA.
--
-- Why it exists. The two service users hold HSET and PEXPIRE, because the limiter's scripts run them, and
-- Valkey checks a command a script calls against the caller's ACL, so the same commands are open to a
-- holder of the credential outside any script. A key pattern bounds which keys they touch and not how
-- much memory those keys use: with `maxmemory-policy noeviction` and an append-only file, a few hundred
-- HSET calls with large values (or TTL-less keys) fill the instance, every limiter write then answers OOM,
-- the FailClosed classes refuse every tenant's SMS code, and the junk survives a restart. Nothing a service
-- may do can be allowed to leave that state, so the container looks after it: what a limiter script
-- writes has a shape, and a key that does not have it is deleted.
--
-- What a key of the limiter looks like (take.lua and give.lua write nothing else):
--   - a hash with the fields `tokens` and `at` and no others, written together with PEXPIRE of at most
--     twice the longest period (MAX_TTL_MS), so a key without a lifetime, or with a longer one, was not
--     written by a script;
--   - small: the key name is a class, a subject and a period, so MAX_KEY_BYTES is generous;
--   - for the admin only, the index `ctrlz:rl:admin:index`, a sorted set of the admin's key names with the
--     same lifetime bound and a bound on its size;
--   - at most MAX_KEYS of them per service. The two services are two trust zones and each gets its own
--     budget, so the api filling its own cannot cost the admin a write. The budget times MAX_KEY_BYTES,
--     twice, plus the index, stays under the smallest maxmemory of the profiles (a test holds that).
-- Anything else under ctrlz:rl:* is deleted: a key of a service that is over its budget loses its
-- latest keys (a bucket that is deleted starts full, the same as one that expired, so this costs a flood's
-- victims their counters and nothing more).
--
-- One call does one batch, so no call holds the server for long (busy-reply-threshold is two seconds): the
-- cursor and the per-service counts travel in ARGV and in the reply, and maintain.sh calls again until the
-- cursor is back at 0. Reply: "<cursor> <api keys kept> <admin keys kept> <keys deleted>".
local MAX_KEY_BYTES = 512
local MAX_KEYS = 40000
local MAX_INDEX_MEMBERS = 40000
local MAX_INDEX_BYTES = 8388608
local MAX_TTL_MS = 1209600000
local BATCH = 2000
local API_PREFIX = 'ctrlz:rl:api:'
local ADMIN_PREFIX = 'ctrlz:rl:admin:'
local ADMIN_INDEX = 'ctrlz:rl:admin:index'

local cursor = ARGV[1]
local api = tonumber(ARGV[2])
local admin = tonumber(ARGV[3])
if cursor == nil or not string.match(cursor, '^%d+$') or api == nil or admin == nil then
  return redis.error_reply('ERR sweep: arguments are a cursor and two counts')
end

local res = redis.call('SCAN', cursor, 'MATCH', 'ctrlz:rl:*', 'COUNT', BATCH)
local deleted = 0
for _, k in ipairs(res[2]) do
  local ttl = redis.call('PTTL', k)
  if ttl ~= -2 then
    local bad = false
    local svc = nil
    if k == ADMIN_INDEX then
      svc = 'index'
    elseif string.sub(k, 1, #API_PREFIX) == API_PREFIX then
      svc = 'api'
    elseif string.sub(k, 1, #ADMIN_PREFIX) == ADMIN_PREFIX then
      svc = 'admin'
    else
      bad = true
    end
    if not bad and (ttl == -1 or ttl > MAX_TTL_MS) then bad = true end
    if not bad then
      local typ = redis.call('TYPE', k)['ok']
      if svc == 'index' then
        if typ ~= 'zset' or redis.call('ZCARD', k) > MAX_INDEX_MEMBERS
           or (redis.call('MEMORY', 'USAGE', k) or 0) > MAX_INDEX_BYTES then
          bad = true
        end
      elseif typ ~= 'hash' or redis.call('HLEN', k) > 2
         or (redis.call('MEMORY', 'USAGE', k) or 0) > MAX_KEY_BYTES then
        bad = true
      end
    end
    if not bad then
      if svc == 'api' then
        api = api + 1
        if api > MAX_KEYS then bad = true end
      elseif svc == 'admin' then
        admin = admin + 1
        if admin > MAX_KEYS then bad = true end
      end
    end
    if bad then
      redis.call('UNLINK', k)
      deleted = deleted + 1
    end
  end
end
return res[1] .. ' ' .. api .. ' ' .. admin .. ' ' .. deleted
