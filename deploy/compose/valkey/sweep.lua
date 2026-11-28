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
-- cursor is back at 0. Reply: "<cursor> <api keys kept> <admin keys kept> <keys deleted> <microseconds the
-- batch ran> <1 when the instance is over half of maxmemory, else 0>".
--
-- Why the batch reports its own time. The loop sizes the next batch and its pause from how long a batch held the
-- server, and the wall time of the valkey-cli call is not that: it holds the process start and, above all, the
-- wait in the server's queue behind other clients. A flood that loads the server would then make the sweep
-- slower exactly when it must be quick, and the pause would buy nothing (a queue wait holds no server time).
-- os.clock is what measures it: the process's CPU time, which for a script that runs alone on the main thread is
-- its length, and on a VM whose clock read traps the trapped time is part of it (checked on valkey/valkey:8.1 on
-- such a host: 20,000 PTTL in a script read 2.03 s of os.clock and 2.1 s on the wall). TIME is no use: Valkey freezes
-- it for the length of a script, so it reads 0 however long the script ran (checked the same way).
--
-- Why it reports pressure. Pacing exists so that the sweep does not cost the limiter timeouts, but when the
-- instance is over half of its maxmemory (a credential holder or an over-budget flood filled it: the legitimate
-- budget of both services is about a third of the smallest profile) it is heading for OOM, where every limiter
-- write fails, and cutting it back quickly is worth some late calls. Between half and full the limiter still
-- works, so the loop trades latency for speed only within a bound: it does not pause, and it keeps batches of
-- 200 keys unless one ran slow (over 200 ms), when the size follows the clock again.
--
-- The batch size is the caller's, the fourth argument (default 200, clamped to 50..2000). A batch is one script
-- of about five redis.call per key, and the server answers nobody while it runs, so what a batch costs the
-- limiter is its length: about a microsecond per call on an ordinary host and about 150 on a VM whose clock
-- read traps (hyperv_clocksource_tsc_page), where 2000 keys held every client for one to two seconds, past the
-- limiter's 250 ms timeout. A key count cannot be right for both hosts, so maintain.sh times each batch and
-- moves the size so that the stall follows the host's real cost.
local MAX_KEY_BYTES = 512
local MAX_KEYS = 40000
local MAX_INDEX_MEMBERS = 40000
local MAX_INDEX_BYTES = 8388608
local MAX_TTL_MS = 1209600000
local BATCH_DEFAULT = 200
local BATCH_MIN = 50
local BATCH_MAX = 2000
local API_PREFIX = 'ctrlz:rl:api:'
local ADMIN_PREFIX = 'ctrlz:rl:admin:'
local ADMIN_INDEX = 'ctrlz:rl:admin:index'

local cursor = ARGV[1]
local api = tonumber(ARGV[2])
local admin = tonumber(ARGV[3])
if cursor == nil or not string.match(cursor, '^%d+$') or api == nil or admin == nil then
  return redis.error_reply('ERR sweep: arguments are a cursor, two counts and a batch size')
end
-- A missing or unreadable size is the default and not an error, and a size outside the bounds is brought
-- inside them: the caller is our own loop, and a sweep that did not run helps nobody.
local batch = tonumber(ARGV[4])
if batch == nil then batch = BATCH_DEFAULT end
batch = math.floor(math.max(BATCH_MIN, math.min(BATCH_MAX, batch)))

local began = os.clock()
local res = redis.call('SCAN', cursor, 'MATCH', 'ctrlz:rl:*', 'COUNT', batch)
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

-- Pressure: used_memory over half of maxmemory, read after this batch's deletions. No maxmemory (0) is no
-- pressure. A line that cannot be read is no pressure either: the sweep then keeps its pace, which is the safe
-- side for the limiter and costs only speed.
local pressure = 0
local mem = redis.call('INFO', 'memory')
local used = tonumber(string.match(mem, 'used_memory:(%d+)'))
local limit = tonumber(string.match(mem, 'maxmemory:(%d+)'))
if used ~= nil and limit ~= nil and limit > 0 and used * 2 > limit then pressure = 1 end

local micros = math.max(0, math.floor((os.clock() - began) * 1000000))
return res[1] .. ' ' .. api .. ' ' .. admin .. ' ' .. deleted .. ' ' .. micros .. ' ' .. pressure
