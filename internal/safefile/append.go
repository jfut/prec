// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const directoryMode = 0o750

// OpenAppend opens or creates a protected append-only regular file.
func OpenAppend(path string, perm os.FileMode) (*os.File, error) {
	return open(path, unix.O_WRONLY|unix.O_APPEND, perm)
}

// OpenLock opens or creates a protected read/write file for flock use.
func OpenLock(path string, perm os.FileMode) (*os.File, error) {
	return open(path, unix.O_RDWR, perm)
}

func open(path string, accessFlags int, perm os.FileMode) (*os.File, error) {
	if path == "" {
		return nil, errors.New("path is empty")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	dirPath, name := filepath.Split(absolutePath)
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("path does not name a file")
	}
	dirFD, err := openDirectory(dirPath)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirFD)

	flags := accessFlags | unix.O_CREAT | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fd, err := unix.Openat(dirFD, name, flags, uint32(perm.Perm()))
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			unix.Close(fd)
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", absolutePath)
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, fmt.Errorf("%s must be owned by the current user and have one link", absolutePath)
	}
	if err := unix.Fchmod(fd, uint32(perm.Perm())); err != nil {
		return nil, fmt.Errorf("chmod file: %w", err)
	}

	closeOnError = false
	return os.NewFile(uintptr(fd), absolutePath), nil
}

// openDirectory walks path from root with no-follow dirfds to block parent-path redirection.
func openDirectory(path string) (int, error) {
	dirFD, err := unix.Open("/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open root directory: %w", err)
	}
	if err := validateDirectory(dirFD); err != nil {
		unix.Close(dirFD)
		return -1, err
	}

	for _, component := range strings.Split(strings.Trim(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		nextFD, err := unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(dirFD, component, directoryMode); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(dirFD)
				return -1, fmt.Errorf("create directory %q: %w", component, mkdirErr)
			}
			nextFD, err = unix.Openat(dirFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			unix.Close(dirFD)
			return -1, fmt.Errorf("open directory %q: %w", component, err)
		}
		if err := validateDirectory(nextFD); err != nil {
			unix.Close(nextFD)
			unix.Close(dirFD)
			return -1, fmt.Errorf("directory %q: %w", component, err)
		}
		unix.Close(dirFD)
		dirFD = nextFD
	}
	return dirFD, nil
}

// validateDirectory checks ownership and write permissions, allowing root-owned sticky temporary dirs.
func validateDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("path component is not a directory")
	}
	uid := uint32(os.Geteuid())
	if stat.Uid != uid && stat.Uid != 0 {
		return errors.New("directory must be owned by the current user or root")
	}
	if stat.Mode&0o022 != 0 && !(stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0) {
		return errors.New("directory is writable by other users")
	}
	return nil
}
