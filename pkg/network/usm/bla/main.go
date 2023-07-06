package main

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/common"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	hostProc string
	set      = common.StringSet{}
	m        sync.Mutex
)

func handleProcessStart(pid int) {
	exePath := filepath.Join(hostProc, strconv.FormatUint(uint64(pid), 10), "exe")

	binPath, err := os.Readlink(exePath)
	if err != nil {
		// We receive the Exec event, /proc could be slow to update
		end := time.Now().Add(10 * time.Millisecond)
		for end.After(time.Now()) {
			binPath, err = os.Readlink(exePath)
			if err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	if err != nil {
		// we can't access to the binary path here (pid probably ended already)
		// there are not much we can do, and we don't want to flood the logs
		return
	}

	m.Lock()
	defer m.Unlock()
	set.Add(binPath)
}

func main() {
	hostProc = util.HostProc()
	fmt.Println(hostProc)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ticker.C:
				m.Lock()
				dump := set.GetAll()
				set = common.StringSet{}
				m.Unlock()
				fmt.Println(strings.Join(dump, "\n"))
			}
		}
	}()

	mon := monitor.GetProcessMonitor()
	defer mon.Stop()
	fmt.Println(mon.SubscribeExec(handleProcessStart))
	mon.Initialize()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("waiting for signal")
	<-sigs
	fmt.Println("finished")
}
