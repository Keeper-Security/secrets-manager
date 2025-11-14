# Manual Integration Tests for Rust SDK v17.1.0

These manual tests validate all new v17.1.0 features against a live Keeper environment.

## Prerequisites

1. **Keeper Account** with Secrets Manager enabled
2. **One-Time Token** from your Keeper application
3. **Test Secrets** in your vault:
   - At least one editable secret (login record)
   - At least one secret with file attachments (for link removal test)
   - Secrets with various titles (for search tests)

## Setup

Set your one-time token as an environment variable:

```bash
export KSM_TOKEN="YOUR_ONE_TIME_TOKEN_HERE"
```

Or use the token directly in test 01 (it will prompt if not set).

## Running the Tests

**Run in order** (each test builds on previous state):

### Test 1: Initialize & Get Secrets
```bash
cargo run --example 01_initialize_and_get_secrets
```

**Validates:**
- ✅ Token binding and config creation
- ✅ Secret retrieval
- ✅ DTO fields: `links`, `is_editable`, `inner_folder_uid`
- ✅ File fields: `url`, `thumbnail_url`

**Creates:** `test_config.json` (reused by other tests)

---

### Test 2: Update Secret
```bash
cargo run --example 02_update_secret
```

**Validates:**
- ✅ `update_secret()` method
- ✅ Field modification with `set_standard_field_value_mut()`
- ✅ Password update
- ✅ Verification of update

**Requires:** At least one editable secret

---

### Test 3: Password Rotation
```bash
cargo run --example 03_password_rotation
```

**Validates:**
- ✅ `update_secret_with_transaction()` with Rotation type
- ✅ `complete_transaction()` commit
- ✅ `complete_transaction()` rollback (interactive)
- ✅ UpdateTransactionType enum

**Interactive:** Will prompt to commit or rollback

---

### Test 4: Search by Title
```bash
cargo run --example 04_search_by_title
```

**Validates:**
- ✅ `get_secrets_by_title()` - all matches
- ✅ `get_secret_by_title()` - first match
- ✅ Case sensitivity
- ✅ Non-existent title handling

---

### Test 5: Update with Options
```bash
cargo run --example 05_update_with_options
```

**Validates:**
- ✅ `update_secret_with_options()` method
- ✅ `UpdateOptions` struct
- ✅ File link removal via `links_to_remove`
- ✅ `UpdatePayload.links2_remove` field

**Requires:** Secret with file attachments

**Note:** If no files found, tests with empty `links_to_remove`

---

### Test 6: Caching Function
```bash
cargo run --example 06_caching_function
```

**Validates:**
- ✅ `caching_post_function` module
- ✅ Cache save on success
- ✅ Cache file creation
- ✅ Cache load/clear operations
- ✅ `KSM_CACHE_DIR` environment variable

**Creates:** `ksm_cache.bin` (cleaned up at end)

---

## Expected Results

All tests should complete with ✅ SUCCESS messages. Any ⚠️ warnings indicate:
- Missing prerequisites (e.g., no files to test link removal)
- Unexpected behavior (needs investigation)

## Troubleshooting

**"No editable secrets found"**
- Ensure you have edit permissions on secrets
- Check `is_editable` field in test 01 output

**"No secrets with file attachments"**
- Upload a file to a secret first
- Or skip test 05 (not critical)

**"Cache not created"**
- Check write permissions in current directory
- Try setting `KSM_CACHE_DIR=/tmp` environment variable

**"Config file error"**
- Delete `test_config.json` and rerun test 01
- Check file permissions

## Cleanup

After testing:

```bash
# Remove test config
rm test_config.json

# Remove any cache files
rm ksm_cache.bin
```

## Documentation Tracking

As you run these tests, track any findings in `plans/DOC_UPDATES_NEEDED.md`:
- Features that work differently than documented
- Unclear error messages
- Missing documentation
- User experience issues

## Next Steps

After all manual tests pass:
1. Review `plans/DOC_UPDATES_NEEDED.md`
2. Update docs.keeper.io with new sections
3. Commit changes to repository
4. Publish v17.1.0 release
