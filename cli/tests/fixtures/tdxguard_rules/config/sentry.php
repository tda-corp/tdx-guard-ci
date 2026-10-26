<?php

return [
    'dsn' => env('SENTRY_LARAVEL_DSN'),
    // ruleid: php.sentry-send-default-pii
    'send_default_pii' => true,
];
