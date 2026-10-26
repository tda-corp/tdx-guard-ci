import sentry_sdk

# ruleid: python.sentry-send-default-pii
sentry_sdk.init(dsn="https://example.invalid/1", send_default_pii=True, traces_sample_rate=0.1)

# ok: python.sentry-send-default-pii
sentry_sdk.init(dsn="https://example.invalid/1", send_default_pii=False)
