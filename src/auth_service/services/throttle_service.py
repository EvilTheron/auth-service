import logging

from redis.asyncio import Redis

from auth_service.core.config import get_settings

ACCOUNT_COUNTER_TTL = 60 * 60
KNOWN_IP_TTL_SECONDS = 30 * 24 * 60 * 60
REGISTRATION_WINDOW_SECONDS = 60 * 60

logger = logging.getLogger(__name__)


class TooManyAttemptsError(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__(f"Retry after {retry_after}s")
        self.retry_after = retry_after


def _ip_key(ip: str) -> str:
    return f"login:fail:ip:{ip}"


def _known_key(email: str, ip: str) -> str:
    return f"login:known:{email}:{ip}"


def _known_failures_key(email: str, ip: str) -> str:
    return f"login:fail:known:{email}:{ip}"


async def check_login_allowed(redis: Redis, email: str, ip: str) -> None:
    if await redis.exists(_known_key(email, ip)):
        return

    settings = get_settings()
    ip_key = _ip_key(ip)
    if int(await redis.get(ip_key) or 0) >= settings.login_ip_max_failures:
        raise TooManyAttemptsError(max(await redis.ttl(ip_key), 1))

    lock_ttl = await redis.ttl(f"login:lock:{email}")
    if lock_ttl > 0:
        raise TooManyAttemptsError(lock_ttl)


async def register_failure(redis: Redis, email: str, ip: str) -> None:
    settings = get_settings()
    ip_key = _ip_key(ip)
    account_key = f"login:fail:acct:{email}"
    known_key = _known_key(email, ip)
    known_failures_key = _known_failures_key(email, ip)

    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(ip_key)
        pipe.expire(ip_key, settings.login_ip_window_seconds, nx=True)
        pipe.incr(account_key)
        pipe.expire(account_key, ACCOUNT_COUNTER_TTL)
        pipe.exists(known_key)
        _, _, account_failures, _, is_known = await pipe.execute()

    if is_known:
        async with redis.pipeline(transaction=True) as pipe:
            pipe.incr(known_failures_key)
            pipe.expire(known_failures_key, ACCOUNT_COUNTER_TTL)
            known_failures, _ = await pipe.execute()
        if known_failures >= settings.login_known_ip_max_failures:
            await redis.delete(known_key, known_failures_key)
            logger.warning("known ip trust revoked after failures: ip=%s", ip)

    if account_failures >= settings.login_account_free_attempts:
        exponent = min(account_failures - settings.login_account_free_attempts, 10)
        lock_seconds = min(
            settings.login_lock_base_seconds * 2**exponent, settings.login_lock_max_seconds
        )
        await redis.set(f"login:lock:{email}", "1", ex=lock_seconds)
        logger.warning(
            "account locked: failures=%d lock_seconds=%d ip=%s", account_failures, lock_seconds, ip
        )


async def register_success(redis: Redis, email: str, ip: str) -> None:
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(
            f"login:fail:acct:{email}", f"login:lock:{email}", _known_failures_key(email, ip)
        )
        pipe.set(_known_key(email, ip), "1", ex=KNOWN_IP_TTL_SECONDS)
        await pipe.execute()


async def check_registration_allowed(redis: Redis, ip: str) -> None:
    key = f"register:ip:{ip}"
    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(key)
        pipe.expire(key, REGISTRATION_WINDOW_SECONDS, nx=True)
        attempts, _ = await pipe.execute()
    if attempts > get_settings().registration_limit_per_hour:
        raise TooManyAttemptsError(max(await redis.ttl(key), 1))
