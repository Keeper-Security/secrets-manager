#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2025 Keeper Security Inc.
# Contact: sm@keepersecurity.com

class GCPKeyConfig:
    """
    Configuration for a Google Cloud Key Management Service (KMS) key.
    
    :param resourcename: Full resource name of a key in the form
        `projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY/cryptoKeyVersions/VERSION`
    :param key_name: The name of the key
    :param key_ring: The name of the key ring
    :param project: The project ID
    :param location: The location (region or multi-region)
    :param key_version: The version of the key. If not provided, the latest version will be used.
    """
    def __init__(self, resourcename: str = None, key_name: str = None, key_ring: str = None,
                 project: str = None, location: str = None, key_version: str = None):
        if resourcename:
            parts = resourcename.split('/')
            if len(parts) < 10:
                raise ValueError("Invalid KMS resource path")
            self.project = parts[1]
            self.location = parts[3]
            self.key_ring = parts[5]
            self.key_name = parts[7]
            self.key_version = parts[9] if len(parts) > 9 else None
        else:
            self.key_name = key_name
            self.key_version = key_version
            self.key_ring = key_ring
            self.project = project
            self.location = location

    def __str__(self):
        return f"{self.key_name}, {self.key_version}"

    def to_key_name(self):
        """Returns the key name in the required KMS format."""
        return f"projects/{self.project}/locations/{self.location}/keyRings/{self.key_ring}/cryptoKeys/{self.key_name}"

    def to_resource_name(self):
        """Returns the full resource name of the KMS key."""
        return f"projects/{self.project}/locations/{self.location}/keyRings/{self.key_ring}/cryptoKeys/{self.key_name}/cryptoKeyVersions/{self.key_version}"
