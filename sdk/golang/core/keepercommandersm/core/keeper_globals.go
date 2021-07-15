package core

const (
	// keeperCommanderSmClientId      string = "mp" + version // # TODO: use versioning when release to prod
	version                        string = "0.0.27a0"
	keeperCommanderSmClientId      string = "mp16.0.0"
	keeperServerPublicKeyRawString string = "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM"
)

var (
	keeperServers = map[string]string{
		"US":     "keepersecurity.com",
		"EU":     "keepersecurity.eu",
		"AU":     "keepersecurity.com.au",
		"US_GOV": "govcloud.keepersecurity.us",
	}
)
