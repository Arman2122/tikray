package xrayver

import "testing"

func TestParse(t *testing.T) {
	for in, want := range map[string]string{"26.10.21": "26.10.21", "v26.1.18": "26.1.18", "v26.3.27": "26.3.27"} {
		v, err := Parse(in)
		if err != nil || v.String() != want || v.Tag() != "v"+want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, v, err, want)
		}
	}
}
func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "latest", "26.10", "26.10.21.1", "../../etc", "26.10.21/../x", "v26.x.1", " 26.10.21", "-1.2.3"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}
func TestLessAndMin(t *testing.T) {
	a, _ := Parse("26.3.27")
	b, _ := Parse("26.10.21")
	if !a.Less(b) || b.Less(a) || MinTUN.String() != "26.1.18" {
		t.Error("ordering is numeric per field, MinTUN is 26.1.18")
	}
}
func TestAssetName(t *testing.T) {
	if n, _ := AssetName("arm64"); n != "Xray-linux-arm64-v8a.zip" {
		t.Error(n)
	}
	if n, _ := AssetName("amd64"); n != "Xray-linux-64.zip" {
		t.Error(n)
	}
	if _, err := AssetName("mips"); err == nil {
		t.Error("mips accepted")
	}
}
