package server

import "io"

type noOpWriteCloser struct {
	io.Writer
}

func (noOpWriteCloser) Close() error { return nil }
