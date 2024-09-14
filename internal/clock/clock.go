package clock

import "time"

type Clock interface {
	Now() time.Time
}

type clock struct{}

var _ Clock = (*clock)(nil)

func New() *clock {
	return &clock{}
}

func (c *clock) Now() time.Time {
	return time.Now()
}
