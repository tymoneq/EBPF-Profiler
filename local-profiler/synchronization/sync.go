package synchronization

import (
	"context"
	"os/signal"
	"sync"
	"syscall"
)

type SyncStruct struct {
	Ctx context.Context
	Wg  *sync.WaitGroup
}

func CreateSignalHandling(NUMBER_OF_GO_ROUTINES int32) (*SyncStruct, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	wg.Add(int(NUMBER_OF_GO_ROUTINES))

	sync := &SyncStruct{
		Ctx: ctx,
		Wg:  &wg,
	}

	return sync, stop
}
