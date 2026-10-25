from bot.config import Config

_DEFAULTS = dict(
    bot_token="", chat_id=0, admin_ids=[], primary_list_url="P", blacklist_url="B",
    blacklist_name="bl", active_list="merged", update_interval_days=7,
    action_mode="block_notify", poll_interval_seconds=5, alert_cooldown_minutes=60,
)


def make_config(**kw) -> Config:
    return Config(**{**_DEFAULTS, **kw})
