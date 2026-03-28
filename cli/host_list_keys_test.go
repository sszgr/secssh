package cli

import (
	"reflect"
	"testing"

	"github.com/sszgr/secssh/vault"
)

func TestSortedHostListKeysUnion(t *testing.T) {
	machines := map[string]vault.HostMachine{
		"prod": {HostName: "10.0.0.1"},
	}
	connections := map[string]vault.HostConnection{
		"prod": {ConnectCount: 1},
		"db":   {ConnectCount: 3},
	}
	got := sortedHostListKeys(machines, connections)
	want := []string{"db", "prod"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
}
