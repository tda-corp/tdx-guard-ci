import * as Sentry from "@sentry/nextjs";

// ruleid: javascript.sentry-send-default-pii
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  sendDefaultPii: true,
  integrations: [
    // ruleid: javascript.sentry-replay-unmasked
    Sentry.replayIntegration({ maskAllText: false }),
  ],
});

// ok: javascript.sentry-send-default-pii
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  sendDefaultPii: false,
  // ok: javascript.sentry-replay-unmasked
  integrations: [Sentry.replayIntegration()],
});
