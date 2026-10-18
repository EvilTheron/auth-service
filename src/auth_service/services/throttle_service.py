from redis.asyncio import Redis

IP_MAX_FAILURES = 20
IP_WINDOW_SECONDS = 15 * 60

ACCOUNT_FREE_ATTEMPTS = 5
ACCOUNT_COUNTER_TTL = 60 * 60
LOCK_BASE_SECONDS = 30
LOCK_MAX_SECONDS = 60 * 60


class TooManyAttemptsError(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"Retry after {retry_after}s")
        self.retry_after = retry_after


async def check_login_allowed(redis: Redis, email: str, ip: str) -> None:
    lock_ttl = await redis.ttl(f"login:lock:{email}")
    if lock_ttl > 0:
        raise TooManyAttemptsError(lock_ttl)

    ip_key = f"login:fail:ip:{ip}"
    if int(await redis.get(ip_key) or 0) >= IP_MAX_FAILURES:
        raise TooManyAttemptsError(max(await redis.ttl(ip_key), 1))


async def register_failure(redis: Redis, email: str, ip: str) -> None:
    ip_key = f"login:fail:ip:{ip}"
    account_key = f"login:fail:acct:{email}"

    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(ip_key)
        pipe.incr(account_key)
        pipe.expire(account_key, ACCOUNT_COUNTER_TTL)
        pipe.expire(ip_key, IP_WINDOW_SECONDS, nx=True)
        _, account_failures, *_ = await pipe.execute()

    if account_failures >= ACCOUNT_FREE_ATTEMPTS:
        exponent = min(account_failures - ACCOUNT_FREE_ATTEMPTS, 10)
        lock_seconds = min(LOCK_BASE_SECONDS * 2**exponent, LOCK_MAX_SECONDS)
        await redis.set(f"login:lock:{email}", "1", ex=lock_seconds)


async def register_success(redis: Redis, email: str) -> None:
    await redis.delete(f"login:fail:acct:{email}")
