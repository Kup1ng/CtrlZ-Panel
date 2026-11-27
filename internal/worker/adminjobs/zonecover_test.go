package adminjobs

import "testing"

func TestNoticeKeyKeepsPartsApart(t *testing.T) {
	if noticeKey("k", "ab", "c") == noticeKey("k", "a", "bc") {
		t.Error("two states made one key")
	}
	if noticeKey("k", "a") == noticeKey("j", "a") || noticeKey("k", "a") != noticeKey("k", "a") {
		t.Error("the key does not follow its kind or is not stable")
	}
	if len(noticeKey("k")) != 64 {
		t.Error("not a sha-256 hex")
	}
}

func TestUploadCoversAnyOneCertificate(t *testing.T) {
	full := []string{"dns.example.org", "*.dns.example.org", "*.verify.dns.example.org"}
	if !uploadCovers([][]string{{"x.example.org"}, full}, "dns.example.org") || uploadCovers(nil, "dns.example.org") {
		t.Error("uploadCovers")
	}
}
