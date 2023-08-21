package utils

import (
	"fmt"

	"github.com/celer-network/goutils/log"
)

func CheckErrf(err error, msg string, args ...interface{}) {
	if err != nil {
		log.Fatalf("error (%s): %s", fmt.Sprintf(msg, args...), err.Error())
	}
}

func CheckOkf(ok bool, msg string, args ...interface{}) {
	if !ok {
		log.Fatalf("check ok failed (%s)", fmt.Sprintf(msg, args...))
	}
}

// Simple check if a string is in array or not. Note, not perform well for a big array
func Contains(array []string, target string) bool {
	for _, s := range array {
		if s == target {
			return true
		}
	}
	return false
}

func Partition[K comparable, V any](vs []V, keys []K, f func(K, V) bool) map[K][]V {
	ret := make(map[K][]V)
	for _, v := range vs {
		for _, k := range keys {
			if f(k, v) {
				ret[k] = append(ret[k], v)
			}
		}
	}
	return ret
}
