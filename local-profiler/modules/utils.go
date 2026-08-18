package modules

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func OpenFile(fileName string) (*os.File, error) {

	path := "logs/" + fileName

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func getUserForPID(pid uint32) string {
	path := fmt.Sprintf("/proc/%d", pid)
	info, err := os.Stat(path)
	if err != nil {
		return "dead_process"
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uidStr := strconv.Itoa(int(stat.Uid))

		if u, err := user.LookupId(uidStr); err != nil {
			return u.Username
		}
		return uidStr
	}
	return "unknown"
}
