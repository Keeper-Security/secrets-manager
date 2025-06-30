require_relative 'version'

module KeeperSecretsManager
  module KeeperGlobals
    # Client version prefix
    # **NOTE: 'mb' client version is NOT YET REGISTERED with Keeper servers!**
    # **TODO: Register 'mb' (Ruby) client with Keeper before production use**
    # **Currently using 'mr' which is already registered (likely Rust SDK)**
    CLIENT_VERSION_PREFIX = 'mr'.freeze  # Should be 'mb' for Ruby, but using 'mr' temporarily
    
    # Get client version
    def self.client_version
      # Use standard version format matching other SDKs
      # Java: mj17.0.0, Python: mp16.x.x, JavaScript: ms16.x.x, Go: mg16.x.x
      # Ruby should be: mb17.0.0 (but not registered yet)
      "#{CLIENT_VERSION_PREFIX}17.0.0"
    end
    
    # Keeper public keys by ID
    KEEPER_PUBLIC_KEYS = {
      '1' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '2' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '3' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '4' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '5' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '6' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '7' => 'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
      '8' => 'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ',
      '9' => 'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g',
      '10' => 'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg',
      '11' => 'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk',
      '12' => 'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY',
      '13' => 'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI',
      '14' => 'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE',
      '15' => 'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8',
      '16' => 'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c',
      '17' => 'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU'
    }.freeze

    # Keeper servers by region
    KEEPER_SERVERS = {
      'US' => 'keepersecurity.com',
      'EU' => 'keepersecurity.eu',
      'AU' => 'keepersecurity.com.au',
      'GOV' => 'govcloud.keepersecurity.us',
      'JP' => 'keepersecurity.jp',
      'CA' => 'keepersecurity.ca'
    }.freeze

    # Default server (US)
    DEFAULT_SERVER = KEEPER_SERVERS['US'].freeze
    
    # Default public key ID
    DEFAULT_KEY_ID = '7'.freeze
    
    # Logger name
    LOGGER_NAME = 'keeper_secrets_manager'.freeze
  end
end