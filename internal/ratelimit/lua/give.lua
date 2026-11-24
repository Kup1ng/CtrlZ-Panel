-- The bounds of a call (admin-r14-4). EVALSHA is allowed to both service users and the digest of this
-- file is public, so a caller that holds a service credential could otherwise send a call with any number
-- of keys and keep the server busy for as long as it likes; from the write phase on SCRIPT KILL cannot
-- stop it. The numbers are the largest the Go limiter ever sends, with room: script.go holds the same
-- constants and a test pins the two files against each other and against every class of the budget
-- registry. A call outside them is refused before anything is read or written.
local MAX_SLOTS = 8
local MAX_CAP = 100000
local MAX_PER = 604800000
local k = #KEYS
if k > MAX_SLOTS + 1 then return redis.error_reply('ERR limiter: too many keys') end
local n = k
local idx = nil
if #ARGV == 2 * (k - 1) then
  n = k - 1
  idx = KEYS[k]
elseif #ARGV ~= 2 * k then
  return redis.error_reply('ERR limiter: arguments do not match keys')
end
if n < 1 or n > MAX_SLOTS then return redis.error_reply('ERR limiter: no slot or too many') end
for i = 1, n do
  local cap = tonumber(ARGV[2 * i - 1])
  local per = tonumber(ARGV[2 * i])
  if cap == nil or per == nil or cap ~= math.floor(cap) or per ~= math.floor(per)
     or cap < 1 or cap > MAX_CAP or per < 1 or per > MAX_PER then
    return redis.error_reply('ERR limiter: capacity or period out of range')
  end
end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local longest = 0
for i = 1, n do
  local cap = tonumber(ARGV[2 * i - 1])
  local per = tonumber(ARGV[2 * i])
  local v = redis.call('HMGET', KEYS[i], 'tokens', 'at')
  local cur = tonumber(v[1])
  if cur ~= nil then
    local at = tonumber(v[2]) or now
    local elapsed = now - at
    if elapsed > 0 then cur = math.min(cap, cur + elapsed * cap / per) end
    cur = math.min(cap, cur + 1)
    redis.call('HSET', KEYS[i], 'tokens', tostring(cur), 'at', tostring(now))
    redis.call('PEXPIRE', KEYS[i], per * 2)
    if idx then
      redis.call('ZADD', idx, now + per * 2, KEYS[i])
      if per * 2 > longest then longest = per * 2 end
    end
  end
end
if idx and longest > 0 then
  redis.call('ZREMRANGEBYSCORE', idx, '-inf', now)
  redis.call('PEXPIRE', idx, longest, 'NX')
  redis.call('PEXPIRE', idx, longest, 'GT')
end
return 1
