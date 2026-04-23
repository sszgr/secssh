package hosttarget

import (
	"net/url"
	"strings"

	"github.com/sszgr/secssh/vault"
)

func ResolveManagedHostAlias(payload *vault.Payload, target string) string {
	if payload == nil {
		return strings.TrimSpace(target)
	}
	candidates := LookupCandidates(target)
	for _, candidate := range candidates {
		if _, ok := payload.Hosts[candidate]; ok {
			return candidate
		}
		if _, ok := payload.Machines[candidate]; ok {
			return candidate
		}
	}
	for alias, machine := range payload.Machines {
		hostName := strings.TrimSpace(machine.HostName)
		if hostName == "" {
			continue
		}
		for _, candidate := range candidates {
			if strings.EqualFold(candidate, hostName) {
				return alias
			}
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return strings.TrimSpace(target)
}

func LookupCandidates(target string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	add(target)
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, "ssh://") || strings.HasPrefix(t, "scp://") || strings.HasPrefix(t, "sftp://") {
		if u, err := url.Parse(t); err == nil {
			add(u.Hostname())
		}
	}
	if at := strings.LastIndex(t, "@"); at >= 0 {
		add(t[at+1:])
	}
	if host, _, found := strings.Cut(t, ":"); found && !strings.Contains(host, "/") {
		add(host)
		if at := strings.LastIndex(host, "@"); at >= 0 {
			add(host[at+1:])
		}
	}
	return out
}
