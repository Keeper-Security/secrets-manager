# TOTP

Generates a time-based one-time password code from a record's `oneTimeCode` field.

## Function demonstrated

`getTotpCode(url, unixTimeSeconds?)`: takes the `otpauth://` URL stored in a record's `oneTimeCode` field
and returns `{ code, timeLeft, period }`, or `null` if the URL isn't a valid otpauth URL.

`timeLeft` is how many seconds remain before `code` rotates; `period` is the rotation interval the URL specifies (usually 30s).
The optional `unixTimeSeconds` argument computes the code for a specific point in time instead of "now", useful for deterministic tests.

## Running

1. Replace the placeholder token in `hello.js` with a real one-time access token for your vault.
2. Make sure the vault has at least one record with a TOTP field configured.
3. `npm install`
4. `npm run run`

Expected output: the current TOTP code and time remaining, followed by the code for a fixed point in time.
