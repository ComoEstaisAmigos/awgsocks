package winsys

import "testing"

func TestServiceSIDMatchesWindows(t *testing.T) {
	cases := map[string]string{
		"TrustedInstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"trustedinstaller": "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
		"AWGSocks":         "S-1-5-80-2865769778-1580442700-1829327410-1325704189-3198177760",
	}
	for name, want := range cases {
		if got := ServiceSID(name); got != want {
			t.Errorf("ServiceSID(%q) = %s, want %s", name, got, want)
		}
	}
}
