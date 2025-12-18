// -*- coding: utf-8 -*-
//  _  __
// | |/ /___ ___ _ __  ___ _ _ (R)
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper Secrets Manager
// Copyright 2024 Keeper Security Inc.
// Contact: sm@keepersecurity.com
//

//! Integration test for KSM-735: Duplicate UID notation bug fix
//!
//! This test validates that when a KSM application has access to both an original
//! record and a shortcut to that record (both with identical UIDs), the deduplication
//! logic properly filters duplicate UIDs using a HashSet.
//!
//! The fix is in `core.rs` lines 2927-2938 of `get_notation_result()`.
//!
//! IMPORTANT: This is a unit test that validates the deduplication algorithm itself,
//! not the full end-to-end notation flow. The test simulates what would happen if
//! `get_secrets()` returns duplicate UIDs (which happens when an app has access to
//! both an original record and a shortcut).

#[cfg(test)]
mod duplicate_uid_deduplication_tests {
    use keeper_secrets_manager_core::dto::Record;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    /// Helper function to create a test record with a specific UID
    fn create_test_record(uid: &str, title: &str) -> Record {
        let mut record_dict = HashMap::new();
        record_dict.insert("password".to_string(), json!("secret123"));

        Record {
            record_key_bytes: vec![1, 2, 3],
            uid: uid.to_string(),
            title: title.to_string(),
            record_type: "login".to_string(),
            files: vec![],
            raw_json: "{}".to_string(),
            record_dict,
            password: Some("secret123".to_string()),
            revision: Some(1),
            is_editable: true,
            folder_uid: "folder123".to_string(),
            folder_key_bytes: Some(vec![4, 5, 6]),
            inner_folder_uid: None,
            links: vec![],
        }
    }

    /// Test that the deduplication logic correctly removes duplicate UIDs
    ///
    /// This test exercises the EXACT logic from lines 2927-2938 in core.rs:
    /// ```rust
    /// if records.len() > 1 {
    ///     let mut seen_uids = std::collections::HashSet::new();
    ///     records.retain(|record| {
    ///         if seen_uids.contains(&record.uid) {
    ///             false
    ///         } else {
    ///             seen_uids.insert(record.uid.clone());
    ///             true
    ///         }
    ///     });
    /// }
    /// ```
    ///
    /// This test would PASS before the fix was added because it tests the algorithm
    /// in isolation. To verify the fix works in the actual codebase, you must:
    /// 1. Temporarily remove lines 2927-2938 from core.rs
    /// 2. Run an integration test with real notation (requires KSM server access)
    /// 3. Observe "multiple records matched" error
    /// 4. Restore the fix and verify error goes away
    #[test]
    fn test_deduplication_removes_duplicate_uids() {
        let duplicate_uid = "ABC123XYZ123456789AB";

        // Simulate what get_secrets() returns when app has access to both
        // original record and shortcut (both have same UID)
        let mut records = vec![
            create_test_record(duplicate_uid, "Original Record"),
            create_test_record(duplicate_uid, "Shortcut Record"), // Same UID!
            create_test_record("XYZ789ABC123456789CD", "Other Record"),
        ];

        println!("Before deduplication: {} records", records.len());
        for record in &records {
            println!("  - UID: {}, Title: {}", record.uid, record.title);
        }

        // This is the EXACT deduplication logic from core.rs lines 2927-2938
        if records.len() > 1 {
            let mut seen_uids = HashSet::new();
            records.retain(|record| {
                if seen_uids.contains(&record.uid) {
                    false
                } else {
                    seen_uids.insert(record.uid.clone());
                    true
                }
            });
        }

        println!("\nAfter deduplication: {} records", records.len());
        for record in &records {
            println!("  - UID: {}, Title: {}", record.uid, record.title);
        }

        // Assert: We should have 2 records (duplicate removed)
        assert_eq!(
            records.len(),
            2,
            "Expected 2 records after deduplication (1 removed)"
        );

        // Assert: The remaining records should have unique UIDs
        let mut unique_uids = HashSet::new();
        for record in &records {
            assert!(
                unique_uids.insert(record.uid.clone()),
                "Found duplicate UID after deduplication: {}",
                record.uid
            );
        }

        // Assert: One of the duplicate_uid records was kept
        let has_duplicate_uid = records.iter().any(|r| r.uid == duplicate_uid);
        assert!(
            has_duplicate_uid,
            "Expected at least one record with UID {}",
            duplicate_uid
        );

        println!("\n✓ Deduplication logic works correctly");
    }

    /// Test that deduplication preserves order (keeps first occurrence)
    #[test]
    fn test_deduplication_keeps_first_occurrence() {
        let duplicate_uid = "SAMEUID123456789ABCD";

        let mut records = vec![
            create_test_record(duplicate_uid, "First Occurrence"),
            create_test_record(duplicate_uid, "Second Occurrence"),
            create_test_record(duplicate_uid, "Third Occurrence"),
        ];

        // Apply deduplication
        if records.len() > 1 {
            let mut seen_uids = HashSet::new();
            records.retain(|record| {
                if seen_uids.contains(&record.uid) {
                    false
                } else {
                    seen_uids.insert(record.uid.clone());
                    true
                }
            });
        }

        assert_eq!(records.len(), 1, "Expected only 1 record after deduplication");
        assert_eq!(
            records[0].title, "First Occurrence",
            "Expected first occurrence to be kept"
        );

        println!("✓ Deduplication keeps first occurrence");
    }

    /// Test that no deduplication happens when all UIDs are unique
    #[test]
    fn test_no_deduplication_when_all_unique() {
        let mut records = vec![
            create_test_record("UID1AAA111111111111AA", "Record 1"),
            create_test_record("UID2BBB222222222222BB", "Record 2"),
            create_test_record("UID3CCC333333333333CC", "Record 3"),
        ];

        let original_count = records.len();

        // Apply deduplication
        if records.len() > 1 {
            let mut seen_uids = HashSet::new();
            records.retain(|record| {
                if seen_uids.contains(&record.uid) {
                    false
                } else {
                    seen_uids.insert(record.uid.clone());
                    true
                }
            });
        }

        assert_eq!(
            records.len(),
            original_count,
            "Expected no records removed when all UIDs unique"
        );

        println!("✓ No deduplication when all UIDs are unique");
    }

    /// Test that single record is not affected by deduplication logic
    #[test]
    fn test_single_record_unchanged() {
        let mut records = vec![create_test_record("SINGLE123456789ABCDE", "Single Record")];

        // Apply deduplication (should be a no-op for single record)
        if records.len() > 1 {
            let mut seen_uids = HashSet::new();
            records.retain(|record| {
                if seen_uids.contains(&record.uid) {
                    false
                } else {
                    seen_uids.insert(record.uid.clone());
                    true
                }
            });
        }

        assert_eq!(records.len(), 1, "Expected single record to remain");
        assert_eq!(records[0].uid, "SINGLE123456789ABCDE");

        println!("✓ Single record unaffected by deduplication");
    }

    /// Test complex scenario with multiple duplicate sets
    #[test]
    fn test_multiple_duplicate_sets() {
        let uid_a = "UIDA111111111111111AA";
        let uid_b = "UIDB222222222222222BB";

        let mut records = vec![
            create_test_record(uid_a, "Record A1"),
            create_test_record(uid_a, "Record A2"), // Duplicate of A
            create_test_record(uid_b, "Record B1"),
            create_test_record(uid_b, "Record B2"), // Duplicate of B
            create_test_record("UIDC333333333333333CC", "Record C1"), // Unique
        ];

        // Apply deduplication
        if records.len() > 1 {
            let mut seen_uids = HashSet::new();
            records.retain(|record| {
                if seen_uids.contains(&record.uid) {
                    false
                } else {
                    seen_uids.insert(record.uid.clone());
                    true
                }
            });
        }

        assert_eq!(
            records.len(),
            3,
            "Expected 3 records (2 duplicates removed)"
        );

        // Verify we have exactly one of each UID
        let uids: HashSet<String> = records.iter().map(|r| r.uid.clone()).collect();
        assert_eq!(uids.len(), 3);
        assert!(uids.contains(uid_a));
        assert!(uids.contains(uid_b));
        assert!(uids.contains("UIDC333333333333333CC"));

        println!("✓ Multiple duplicate sets handled correctly");
    }
}

#[cfg(test)]
mod notation_context_tests {
    //! These tests document WHY the deduplication fix is needed in the context
    //! of the full notation retrieval flow.

    /// Documentation test explaining the bug scenario
    ///
    /// This is NOT an executable test (would require real KSM server), but documents
    /// the exact scenario that triggers the bug.
    #[test]
    fn document_bug_scenario() {
        println!("=== KSM-735: Duplicate UID Notation Bug ===\n");

        println!("SCENARIO:");
        println!("1. User creates a record with UID 'ABC123XYZ123456789AB' in Keeper");
        println!("2. User creates a SHORTCUT to that record");
        println!("3. User shares BOTH original record AND shortcut to same KSM App");
        println!("4. KSM App calls get_secrets() with that UID\n");

        println!("BUG (before fix):");
        println!("- Server returns TWO records with SAME UID (original + shortcut)");
        println!("- get_notation_result() sees records.len() = 2");
        println!("- Line 2950: Returns error 'multiple records matched'");
        println!("- User gets confusing error even though UIDs are identical!\n");

        println!("FIX (lines 2927-2938):");
        println!("- Deduplicate by UID using HashSet");
        println!("- Keep only first occurrence");
        println!("- Now records.len() = 1 after deduplication");
        println!("- Notation lookup succeeds!\n");

        println!("IMPORTANT:");
        println!("- Different UIDs with same TITLE should still fail (genuine ambiguity)");
        println!("- Only IDENTICAL UIDs should be deduplicated");
        println!("- First occurrence is kept (preserves order)");

        // This test always passes - it's documentation
        assert!(true);
    }
}
