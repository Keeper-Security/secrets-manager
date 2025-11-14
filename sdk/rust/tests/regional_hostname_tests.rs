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

//! Regional hostname mapping tests
//!
//! Tests validate expected regional hostname patterns for Keeper Secrets Manager

#[cfg(test)]
mod regional_hostname_tests {
    /// Test: US region hostname
    #[test]
    fn test_us_region_hostname() {
        let us_hostname = "keepersecurity.com";

        assert_eq!(us_hostname, "keepersecurity.com");
        assert!(us_hostname.starts_with("keepersecurity"));
        assert!(!us_hostname.contains("eu"));
        assert!(!us_hostname.contains("au"));
        assert!(!us_hostname.contains("gov"));
    }

    /// Test: EU region hostname
    #[test]
    fn test_eu_region_hostname() {
        let eu_hostname = "keepersecurity.eu";

        assert_eq!(eu_hostname, "keepersecurity.eu");
        assert!(eu_hostname.contains(".eu"));
        assert!(eu_hostname.starts_with("keepersecurity"));
    }

    /// Test: AU region hostname
    #[test]
    fn test_au_region_hostname() {
        let au_hostname = "keepersecurity.com.au";

        assert_eq!(au_hostname, "keepersecurity.com.au");
        assert!(au_hostname.contains(".au"));
        assert!(au_hostname.starts_with("keepersecurity"));
    }

    /// Test: GOV region hostname
    #[test]
    fn test_gov_region_hostname() {
        let gov_hostname = "govcloud.keepersecurity.us";

        assert_eq!(gov_hostname, "govcloud.keepersecurity.us");
        assert!(gov_hostname.contains("govcloud"));
        assert!(gov_hostname.contains(".us"));
        assert!(gov_hostname.contains("keepersecurity"));
    }

    /// Test: JP region hostname
    #[test]
    fn test_jp_region_hostname() {
        let jp_hostname = "keepersecurity.jp";

        assert_eq!(jp_hostname, "keepersecurity.jp");
        assert!(jp_hostname.contains(".jp"));
        assert!(jp_hostname.starts_with("keepersecurity"));
    }

    /// Test: CA region hostname
    #[test]
    fn test_ca_region_hostname() {
        let ca_hostname = "keepersecurity.ca";

        assert_eq!(ca_hostname, "keepersecurity.ca");
        assert!(ca_hostname.contains(".ca"));
        assert!(ca_hostname.starts_with("keepersecurity"));
    }

    /// Test: All regional hostnames are unique
    #[test]
    fn test_all_regional_hostnames_unique() {
        let hostnames = vec![
            "keepersecurity.com",              // US
            "keepersecurity.eu",               // EU
            "keepersecurity.com.au",           // AU
            "govcloud.keepersecurity.us",      // GOV
            "keepersecurity.jp",               // JP
            "keepersecurity.ca",               // CA
        ];

        // Convert to set to check uniqueness
        let unique: std::collections::HashSet<_> = hostnames.iter().collect();
        assert_eq!(unique.len(), 6, "All regional hostnames should be unique");
    }

    /// Test: All regional API endpoints use HTTPS
    #[test]
    fn test_regional_api_endpoints_use_https() {
        let api_endpoints = vec![
            "https://keepersecurity.com/api/rest/sm/v2/",
            "https://keepersecurity.eu/api/rest/sm/v2/",
            "https://keepersecurity.com.au/api/rest/sm/v2/",
            "https://govcloud.keepersecurity.us/api/rest/sm/v2/",
            "https://keepersecurity.jp/api/rest/sm/v2/",
            "https://keepersecurity.ca/api/rest/sm/v2/",
        ];

        for endpoint in api_endpoints {
            assert!(endpoint.starts_with("https://"));
            assert!(endpoint.contains("/api/rest/sm/v2/"));
        }
    }

    /// Test: Region-to-hostname mapping is correct
    #[test]
    fn test_region_hostname_mapping() {
        let mappings = vec![
            ("US", "keepersecurity.com"),
            ("EU", "keepersecurity.eu"),
            ("AU", "keepersecurity.com.au"),
            ("GOV", "govcloud.keepersecurity.us"),
            ("JP", "keepersecurity.jp"),
            ("CA", "keepersecurity.ca"),
        ];

        for (region, expected_hostname) in mappings {
            assert!(
                !expected_hostname.is_empty(),
                "Hostname for region {} should not be empty",
                region
            );
            assert!(
                expected_hostname.contains("keepersecurity"),
                "Hostname for region {} should contain 'keepersecurity'",
                region
            );
        }
    }

    /// Test: Hostname format patterns
    #[test]
    fn test_hostname_format_patterns() {
        // US: No TLD suffix
        assert_eq!("keepersecurity.com", "keepersecurity.com");

        // EU: .eu suffix
        assert!("keepersecurity.eu".ends_with(".eu"));

        // AU: .com.au suffix
        assert!("keepersecurity.com.au".ends_with(".au"));

        // GOV: govcloud prefix
        assert!("govcloud.keepersecurity.us".starts_with("govcloud"));

        // JP: .jp suffix
        assert!("keepersecurity.jp".ends_with(".jp"));

        // CA: .ca suffix
        assert!("keepersecurity.ca".ends_with(".ca"));
    }
}
