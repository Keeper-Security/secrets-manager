# Notation

Looks up a single secret value by notation instead of paging through a full `getSecrets()` result.

## Notation format

```
keeper://<record UID or title>/field/<field type>
keeper://<record UID or title>/custom_field/<field label>
keeper://<record UID or title>/file/<file name or UID>
```

The `keeper://` prefix is optional.

## Functions demonstrated

- `getNotationResults(options, notation)`: resolves a notation string to a list of values, throws if the notation is invalid or the target isn't found.
- `tryGetNotationResults(options, notation)`: same lookup, but logs and returns an empty array instead of throwing.

## Running

1. Replace the placeholder token in `hello.js` with a real one-time access token for your vault.
2. `npm install`
3. `npm run run`

Expected output: the first record's `login` field value resolved via notation, an empty-array result from `tryGetNotationResults` against a field that doesn't exist, and a caught error from `getNotationResults` against the same missing field.
