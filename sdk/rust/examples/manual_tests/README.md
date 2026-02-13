# Manual Integration Tests for Rust SDK v17.1.0

These manual tests validate all v17.1.0 features against a live Keeper environment.

## Prerequisites

1. **Keeper Account** with Secrets Manager enabled
2. **One-Time Token** from your Keeper application
3. **Test Secrets** in your vault:
   - At least one editable secret (login record)
   - At least one secret with file attachments (for link removal tests)
   - Secrets with various titles (for search tests)

## Setup

Set your one-time token as an environment variable:

```bash
export KSM_TOKEN="YOUR_ONE_TIME_TOKEN_HERE"
```

Or edit the example files to use your token directly.

## Running the Tests

**Run tests in order** (some tests build on previous state):

### Test 01: Initialize & Get Secrets
```bash
cargo run --example 01_initialize_and_get_secrets
```

**Validates:**
- Token binding and config creation
- Secret retrieval
- DTO fields: `links`, `is_editable`, `inner_folder_uid`
- File fields: `url`, `thumbnail_url`

**Creates:** `test_config.json` (reused by other tests)

---

### Test 02: Update Secret
```bash
cargo run --example 02_update_secret
```

**Validates:**
- `update_secret()` method
- Field modification with `set_standard_field_value_mut()`
- Password update
- Verification of update

**Requires:** At least one editable secret

---

### Test 03: Password Rotation
```bash
cargo run --example 03_password_rotation
```

**Validates:**
- `update_secret_with_transaction()` with Rotation type
- `complete_transaction()` commit/rollback
- UpdateTransactionType enum

**Interactive:** Will prompt to commit or rollback

---

### Test 04: Search by Title
```bash
cargo run --example 04_search_by_title
```

**Validates:**
- `get_secrets_by_title()` - all matches
- `get_secret_by_title()` - first match
- Case sensitivity
- Non-existent title handling

---

### Test 05: Update with Options
```bash
cargo run --example 05_update_with_options
```

**Validates:**
- `update_secret_with_options()` method
- `UpdateOptions` struct
- File link removal via `links_to_remove`
- `UpdatePayload.links2_remove` field

**Requires:** Secret with file attachments
**Note:** If no files found, tests with empty `links_to_remove`

---

### Test 06: Caching Function
```bash
cargo run --example 06_caching_function
```

**Validates:**
- `caching_post_function` module
- Cache save on success
- Cache file creation
- Cache load/clear operations
- `KSM_CACHE_DIR` environment variable

**Creates:** `ksm_cache.bin` (cleaned up at end)

---

### Test 07: Rotation with Base64 Config
```bash
cargo run --example 07_test_rotation_base64
```

**Validates:**
- Password rotation using InMemoryKeyValueStorage
- Base64 config string initialization
- Transaction workflow with in-memory storage

**Requires:** `KSM_CONFIG` environment variable with base64 config

---

### Test 08: File Link Removal
```bash
cargo run --example 08_test_link_removal
```

**Validates:**
- Link removal functionality
- `links_to_remove` parameter behavior
- File attachment management

**Requires:** Secret with file attachments

---

### Test 09: FileRef Validation
```bash
cargo run --example 09_check_fileref
```

**Validates:**
- `fileRef` field handling
- File reference integrity
- Field consolidation

---

### Test 10: Link Removal Debug
```bash
cargo run --example 10_test_link_removal_debug
```

**Validates:**
- Detailed link removal debugging
- Transaction type auto-override (KSM-776 fix)
- Verbose logging of link removal process

---

### Test 11: Upload and Remove File
```bash
cargo run --example 11_upload_and_remove_file
```

**Validates:**
- File upload via `upload_file()`
- `KeeperFileUpload::get_file_for_upload()`
- File removal via link removal
- End-to-end file lifecycle

**Requires:** Test file to upload (create a sample file first)

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
- Or skip tests 05, 08, 10, 12 (not critical)

**"Cache not created"**
- Check write permissions in current directory
- Try setting `KSM_CACHE_DIR=/tmp`

**"Config file error"**
- Delete `test_config.json` and rerun test 01
- Check file permissions

**Compilation errors**
- Ensure Rust 1.87+ installed: `rustc --version`
- Update Rust: `rustup update`

## Cleanup

After testing:

```bash
# Remove test config
rm test_config.json

# Remove cache files
rm ksm_cache.bin
```

## Testing Tips

1. **Run tests sequentially** - Some tests depend on previous state
2. **Check output carefully** - Tests print detailed status for debugging
3. **Use your own test data** - Tests work best with real secrets you control
4. **Environment setup** - Set `RUST_LOG=debug` for verbose SDK logging

## Next Steps

After all manual tests pass:
1. Review output for any unexpected behavior
2. Verify all features work as documented
3. File issues for any bugs discovered
4. Ready for release!
