package journal

import (
	"strings"
	"testing"
	"time"
)

func TestQueries(t *testing.T) {
	good := Query{Part: "proxy", Priority: 6, SinceSeconds: 3600, Text: "http-nas", Limit: 100}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]Query{
		"a unit of its own": {Part: "../etc", Priority: 6, SinceSeconds: 60, Limit: 10},
		"a level of 9":      {Part: "sgc", Priority: 9, SinceSeconds: 60, Limit: 10},
		"a year back":       {Part: "sgc", Priority: 6, SinceSeconds: 365 * 86400, Limit: 10},
		"a line break":      {Part: "sgc", Priority: 6, SinceSeconds: 60, Limit: 10, Text: "a\nb"},
		"a strange cursor":  {Part: "sgc", Priority: 6, SinceSeconds: 60, Limit: 10, After: "--rotate"},
		"too many":          {Part: "sgc", Priority: 6, SinceSeconds: 60, Limit: 5000},
	} {
		if q.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	args := strings.Join(good.Arguments(time.Unix(1792500000, 0)), " ")
	if !strings.Contains(args, "--unit=sgc-traefik.service") || !strings.Contains(args, "--since=@1792496400") || strings.Contains(args, "http-nas") {
		t.Errorf("arguments: %s", args)
	}
}

func TestParse(t *testing.T) {
	output := `{"__CURSOR":"s=1;i=1","__REALTIME_TIMESTAMP":"1792500000000000","PRIORITY":"6","_SYSTEMD_UNIT":"sgc-traefik.service","MESSAGE":"{\"RouterName\":\"http-nas@file\",\"DownstreamStatus\":200}"}
Hint: a line journalctl writes that is not JSON
{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1792500001000000","PRIORITY":"4","_SYSTEMD_UNIT":"sgc-traefik.service","MESSAGE":[104,105,255]}
{"__CURSOR":"s=1;i=3","__REALTIME_TIMESTAMP":"1792500002000000","PRIORITY":"6","_SYSTEMD_UNIT":"sgc-traefik.service","MESSAGE":"{\"RouterName\":\"http-media@file\"}"}
`
	answer := Parse([]byte(output), Query{Text: "HTTP-NAS", Limit: 10})
	if len(answer.Entries) != 1 || answer.Cursor != "s=1;i=3" || !strings.Contains(answer.Entries[0].Message, "http-nas") {
		t.Errorf("got %+v", answer)
	}
	all := Parse([]byte(output), Query{Limit: 2})
	if len(all.Entries) != 2 || all.Entries[0].Message != "hi?" || all.Entries[0].Priority != 4 {
		t.Errorf("the newest two: %+v", all.Entries)
	}
}
