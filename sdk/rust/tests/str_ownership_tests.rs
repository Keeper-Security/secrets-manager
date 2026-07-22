// Tests for KSM-999: public-API &str/String ownership audit.
//
// Goal: prove the generalized signatures are backward-compatible (existing `String`
// callers still compile) AND add the new `&str` ergonomics — without changing behavior.

use keeper_secrets_manager_core::core::SecretsManager;
use keeper_secrets_manager_core::dto::dtos::{KeeperFile, RecordCreate};
use keeper_secrets_manager_core::dto::field_structs::KeeperField;

// Pure constructors: accept both &str and String and produce identical values
// (proves the `impl Into<String>` change didn't alter the stored value).
#[test]
fn constructors_accept_str_and_string() {
    let from_str = RecordCreate::new("login", "My Title", None);
    let from_string = RecordCreate::new(String::from("login"), String::from("My Title"), None);
    assert_eq!(from_str.record_type, from_string.record_type);
    assert_eq!(from_str.title, from_string.title);
    assert_eq!(from_str.record_type, "login");
    assert_eq!(from_str.title, "My Title");

    let f_str = KeeperField::new("password", None);
    let f_string = KeeperField::new(String::from("password"), None);
    assert_eq!(f_str.field_type, f_string.field_type);
    assert_eq!(f_str.field_type, "password");
}

// Compile-gate (never executed): every audited public method must accept BOTH a borrowed
// `&str`/`&Path` and an owned `String` argument. If a generalization regresses, this fails
// to type-check. Backward-compat for `String` callers is also exercised here.
#[allow(dead_code)]
fn _audited_methods_accept_str_and_string(sm: &mut SecretsManager, file: &mut KeeperFile) {
    // Read-only String -> impl AsRef<str>
    let _ = sm.get_notation("keeper://x/field/y");
    let _ = sm.get_notation(String::from("keeper://x/field/y"));
    let _ = sm.get_notation_result("keeper://x/field/y");
    let _ = sm.get_notation_result(String::from("keeper://x/field/y"));
    let _ = sm.create_secret("FOLDERUID", RecordCreate::new("login", "t", None));
    let _ = sm.create_secret(
        String::from("FOLDERUID"),
        RecordCreate::new("login", "t", None),
    );
    let _ = sm.update_folder("FOLDERUID", "name".to_string(), Vec::new());
    let _ = sm.update_folder(String::from("FOLDERUID"), "name".to_string(), Vec::new());

    // Stored String -> impl Into<String>
    let _ = sm.complete_transaction("RECORDUID", false);
    let _ = sm.complete_transaction(String::from("RECORDUID"), false);

    // File path String -> impl AsRef<Path> (accepts &str, String, &Path)
    let _ = file.save_to_file("out.bin");
    let _ = file.save_to_file(String::from("out.bin"));
    let _ = file.save_to_file(std::path::Path::new("out.bin"));
    let _ = file.save_file("out.bin", false);
}
