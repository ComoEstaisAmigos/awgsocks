package config

import "golang.org/x/sys/windows"

func programDataDir() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
}
