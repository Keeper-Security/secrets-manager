package keepercommandersm

const (
	version                        string = "0.0.27a0"
	keeperCommanderSmClientId      string = "mg16.0.0" // Golang client ID starts with "mg" + version
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
