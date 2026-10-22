Let's review some of the options in the `config/jwt.php` file that we published earlier.
I won't go through all of the options here since [the file itself](https://github.com/tymondesigns/jwt-auth/blob/1.0.0-beta.2/config/config.php) is pretty well documented.

First up is:

```
'secret' => env('JWT_SECRET'),
```

Coming soon...

## Logout all devices (optional)

The logout-all-devices capability is disabled by default.

```php
'logout_all_devices_enabled' => env('JWT_LOGOUT_ALL_DEVICES_ENABLED', false),
```

When enabled, you can revoke all active tokens for a subject with one action.
Tokens issued after the cutoff continue to work normally.

You can optionally configure how long the subject revocation cutoff stays in
cache-backed storage:

```php
'logout_all_devices_ttl' => env('JWT_LOGOUT_ALL_DEVICES_TTL', null),
```

- Finite base retention is `max(ttl, refresh_ttl) + 1 + ceil(leeway / 60)` minutes.
- `logout_all_devices_ttl` can only lengthen that base retention.
- If either `ttl` or `refresh_ttl` is `null`, retention is unbounded and the
  subject cutoff is stored forever.

When retention is finite, records are written with an expiring TTL so cleanup
happens naturally through cache expiry instead of accumulating indefinitely.

## Known limitations

- Subject cutoff comparisons use second-level timestamps. A token issued in the
  same second as a logout-all action is treated as revoked.
- Revocations are cache-backed. If the cache store is cleared/flushed, stored
  subject revocation cutoffs are removed and previously revoked sessions can
  authenticate again.
