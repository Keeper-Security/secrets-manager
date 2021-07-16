package core

import (
	klog "keepercommandersm/core/logger"
	"net"
	"net/url"
	"os"
	"strings"
)

func GetServer(codeServer string, configStore IKeyValueStorage) string {
	serverToUse := ""
	if envServer := strings.TrimSpace(os.Getenv("KSM_SERVER")); envServer != "" {
		serverToUse = envServer
	} else if cfgServer := strings.TrimSpace(configStore.Get(KEY_SERVER)); cfgServer != "" {
		serverToUse = cfgServer
	} else if codedServer := strings.TrimSpace(codeServer); codedServer != "" {
		serverToUse = codedServer
	} else if srvToUse, found := keeperServers["US"]; found {
		serverToUse = strings.TrimSpace(srvToUse)
	}

	serverToReturn := ""
	if srv, found := keeperServers[serverToUse]; found {
		// Server key was supplied
		serverToReturn = srv
	} else {
		// Looks like an URL. Un-parsing URL to get only domain:
		serverToUse = strings.TrimSpace(serverToUse)
		serverToReturn = serverToUse

		if !strings.HasPrefix(strings.ToLower(serverToUse), "http") {
			serverToUse = "https://" + serverToUse
		}
		if u, err := url.Parse(serverToUse); err == nil && u.Host != "" {
			serverToReturn = u.Host
			if host, _, err := net.SplitHostPort(u.Host); err == nil && host != "" {
				serverToReturn = host
			}
		}
	}

	klog.Debug("Keeper server: " + serverToReturn)

	return serverToReturn
}
