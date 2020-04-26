package plan9

import (
	"testing"

	"github.com/docker/docker/pkg/testutil/assert"
	"plan9.io"
)

func Test_unmarshaldir(t *testing.T) {
	type args struct {
		b []byte
		d plan9.Dir
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "unmarshaldir",
			args: func() (a args) {
				a.d, a.b = stat()
				return
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := unmarshaldir(tt.args.b)
			assert.DeepEqual(t, *got, tt.args.d)
		})
	}
}
