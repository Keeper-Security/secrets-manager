package keepercommandersm

type ConfigKey string

const (
	KEY_URL           ConfigKey = "url"
	KEY_CLIENT_ID     ConfigKey = "clientId"
	KEY_CLIENT_KEY    ConfigKey = "clientKey"
	KEY_APP_KEY       ConfigKey = "appKey"
	KEY_PRIVATE_KEY   ConfigKey = "privateKey"
	KEY_BINDING_TOKEN ConfigKey = "bat"
	KEY_BINDING_KEY   ConfigKey = "bindingKey"
	KEY_SERVER        ConfigKey = "server"
)

func GetConfigKey(value string) ConfigKey {
	switch value {
	case string(KEY_URL):
		return KEY_URL
	case string(KEY_CLIENT_ID):
		return KEY_CLIENT_ID
	case string(KEY_CLIENT_KEY):
		return KEY_CLIENT_KEY
	case string(KEY_APP_KEY):
		return KEY_APP_KEY
	case string(KEY_PRIVATE_KEY):
		return KEY_PRIVATE_KEY
	case string(KEY_BINDING_TOKEN):
		return KEY_BINDING_TOKEN
	case string(KEY_BINDING_KEY):
		return KEY_BINDING_KEY
	case string(KEY_SERVER):
		return KEY_SERVER
	default:
		return ""
	}
}
