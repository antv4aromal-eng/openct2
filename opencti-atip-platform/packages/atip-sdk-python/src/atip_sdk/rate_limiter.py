"""
Distributed Redis Token Bucket Rate Limiter
Ensures strict API quota compliance for threat intelligence feeds (VirusTotal, Shodan, etc.)
"""

import time
import asyncio
from typing import Optional
import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger(__name__)

# Atomic Lua script for Token Bucket implementation
LUA_TOKEN_BUCKET = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

-- Retrieve current state [tokens, last_update]
local data = redis.call('HMGET', key, 'tokens', 'last_updated')
local tokens = tonumber(data[1])
local last_updated = tonumber(data[2])

if not tokens then
    tokens = capacity
    last_updated = now
else
    local elapsed = math.max(0, now - last_updated)
    tokens = math.min(capacity, tokens + (elapsed * refill_rate))
    last_updated = now
end

if tokens >= cost then
    tokens = tokens - cost
    redis.call('HMSET', key, 'tokens', tokens, 'last_updated', last_updated)
    redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) * 2)
    return {1, tokens, 0}
else
    local wait_time = (cost - tokens) / refill_rate
    redis.call('HMSET', key, 'tokens', tokens, 'last_updated', last_updated)
    redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) * 2)
    return {0, tokens, wait_time}
end
"""


class RedisTokenBucketRateLimiter:
    """
    High-performance distributed rate limiter powered by Redis and Lua scripts.
    Guarantees thread-safe and process-safe concurrency across worker replicas.
    """

    def __init__(
        self,
        redis_client: Optional[aioredis.Redis],
        key: str,
        capacity: float,
        refill_rate: float,
        auto_wait: bool = True
    ):
        """
        Args:
            redis_client: Async redis client connection
            key: Redis storage key (e.g. 'ratelimit:virustotal')
            capacity: Maximum burst capacity of the token bucket
            refill_rate: Tokens replenished per second
            auto_wait: If True, acquire() sleeps until tokens become available
        """
        self.redis = redis_client
        self.key = key
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.auto_wait = auto_wait
        self._lua_sha: Optional[str] = None
        
        # Local fallback state if Redis is offline
        self._local_tokens = float(capacity)
        self._local_last_updated = time.time()
        self._local_lock = asyncio.Lock()

    async def _ensure_script(self):
        if self.redis and not self._lua_sha:
            try:
                self._lua_sha = await self.redis.script_load(LUA_TOKEN_BUCKET)
            except Exception as e:
                logger.warning("failed_to_load_lua_script_using_eval", error=str(e))

    async def acquire(self, cost: float = 1.0) -> bool:
        """
        Acquire tokens from the bucket. Blocks if auto_wait is True and rate limit is reached.
        """
        while True:
            now = time.time()
            if self.redis:
                try:
                    await self._ensure_script()
                    if self._lua_sha:
                        res = await self.redis.evalsha(
                            self._lua_sha, 1, self.key, self.capacity, self.refill_rate, cost, now
                        )
                    else:
                        res = await self.redis.eval(
                            LUA_TOKEN_BUCKET, 1, self.key, self.capacity, self.refill_rate, cost, now
                        )
                    allowed, remaining, wait_time = res[0], float(res[1]), float(res[2])
                    if allowed == 1:
                        return True
                    if not self.auto_wait:
                        return False
                    logger.debug("rate_limit_throttling", key=self.key, wait_time=wait_time)
                    await asyncio.sleep(wait_time)
                    continue
                except Exception as e:
                    logger.warning("redis_rate_limiter_error_fallback_local", error=str(e))

            # Local fallback token bucket
            async with self._local_lock:
                elapsed = max(0.0, now - self._local_last_updated)
                self._local_tokens = min(self.capacity, self._local_tokens + (elapsed * self.refill_rate))
                self._local_last_updated = now

                if self._local_tokens >= cost:
                    self._local_tokens -= cost
                    return True
                
                if not self.auto_wait:
                    return False

                wait_time = (cost - self._local_tokens) / self.refill_rate
            
            logger.debug("local_rate_limit_throttling", key=self.key, wait_time=wait_time)
            await asyncio.sleep(wait_time)
