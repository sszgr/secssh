package secret

import "strings"

func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}
