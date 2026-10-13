//go:build !windows

package cleanup

import "os"

func lockStore(string) (func(), error) { return func() {}, nil }

func replaceJournal(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return nil
}
