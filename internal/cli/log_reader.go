// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright contributors to the prec project.

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

const maxLogCompressionLayers = 4
const maxLogZstdMemory = 64 * 1024 * 1024

// newLogZstdDecoder bounds memory and parallelism for compressed log input.
func newLogZstdDecoder(src io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(
		src,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxLogZstdMemory),
		zstd.WithDecoderMaxWindow(maxLogZstdMemory),
	)
}

func openLogReader(logPath string) (io.ReadCloser, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	return openLayeredLogReader(logPath, f)
}

func detectLogCompression(logPath string, hint string) (string, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	modeByMagic := detectCompressionByMagic(bufio.NewReader(f))
	if modeByMagic != logCompressionNone {
		return modeByMagic, nil
	}

	// An empty or partially written stream may not expose its frame header yet.
	normalizedHint := strings.ToLower(strings.TrimSpace(hint))
	if normalizedHint == logCompressionGzip || normalizedHint == logCompressionZstd {
		return normalizedHint, nil
	}
	return logCompressionNone, nil
}

func detectCompressionByMagic(r *bufio.Reader) string {
	peek, err := r.Peek(4)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return logCompressionNone
	}
	if len(peek) >= 2 && peek[0] == 0x1f && peek[1] == 0x8b {
		return logCompressionGzip
	}
	if len(peek) >= 4 && peek[0] == 0x28 && peek[1] == 0xb5 && peek[2] == 0x2f && peek[3] == 0xfd {
		return logCompressionZstd
	}
	return logCompressionNone
}

type compressedTailReader struct {
	mode  string
	pipeR *io.PipeReader
	pipeW *io.PipeWriter
	errCh chan error
}

func newCompressedTailReader() *compressedTailReader {
	return &compressedTailReader{}
}

func (r *compressedTailReader) Reset(mode string, onLine func([]byte)) error {
	// After copytruncate, restart decoding from the beginning of the new compressed stream.
	r.Close()
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != logCompressionGzip && mode != logCompressionZstd {
		return fmt.Errorf("unsupported compression mode: %s", mode)
	}
	pipeR, pipeW := io.Pipe()

	r.mode = mode
	r.pipeR = pipeR
	r.pipeW = pipeW
	r.errCh = make(chan error, 1)

	go func(mode string, pipeReader *io.PipeReader, errCh chan error) {
		defer close(errCh)
		defer pipeReader.Close()

		if err := decodeCompressedTailStream(mode, pipeReader, onLine); err != nil && !errors.Is(err, io.EOF) {
			errCh <- err
		}
	}(r.mode, r.pipeR, r.errCh)
	return nil
}

func decodeCompressedTailStream(mode string, src io.Reader, onLine func([]byte)) error {
	switch mode {
	case logCompressionGzip:
		br := bufio.NewReader(src)
		for {
			gzReader, err := gzip.NewReader(br)
			if err != nil {
				return err
			}
			gzReader.Multistream(false)
			if err := scanDecompressedLines(gzReader, onLine); err != nil {
				gzReader.Close()
				return err
			}
			if err := gzReader.Close(); err != nil {
				return err
			}
		}
	case logCompressionZstd:
		dec, err := newLogZstdDecoder(src)
		if err != nil {
			return err
		}
		defer dec.Close()
		return scanDecompressedLines(dec, onLine)
	default:
		return fmt.Errorf("unsupported compression mode: %s", mode)
	}
}

func scanDecompressedLines(reader io.Reader, onLine func([]byte)) error {
	scanner := bufio.NewScanner(reader)
	// Bound memory for malformed logs while allowing escaped maximum-size argv records.
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineLength)
	for scanner.Scan() {
		onLine(scanner.Bytes())
	}
	return scanner.Err()
}

func (r *compressedTailReader) Feed(chunk []byte) error {
	if len(chunk) == 0 {
		return nil
	}
	_, err := r.pipeW.Write(chunk)
	return err
}

func (r *compressedTailReader) PollError() error {
	if r.errCh == nil {
		return nil
	}
	select {
	case err, ok := <-r.errCh:
		if !ok {
			r.errCh = nil
			return nil
		}
		return err
	default:
		return nil
	}
}

func (r *compressedTailReader) Close() error {
	var firstErr error
	if r.pipeW != nil {
		if err := r.pipeW.Close(); err != nil && firstErr == nil && !errors.Is(err, io.ErrClosedPipe) {
			firstErr = err
		}
		r.pipeW = nil
	}
	if r.pipeR != nil {
		if err := r.pipeR.Close(); err != nil && firstErr == nil && !errors.Is(err, io.ErrClosedPipe) {
			firstErr = err
		}
		r.pipeR = nil
	}
	r.errCh = nil
	return firstErr
}

type readerWithCloser struct {
	reader io.Reader
	closer io.Closer
}

func (r *readerWithCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *readerWithCloser) Close() error {
	return r.closer.Close()
}

func openLayeredLogReader(logPath string, base io.ReadCloser) (io.ReadCloser, error) {
	var reader io.Reader = base
	closers := []io.Closer{base}

	for range maxLogCompressionLayers {
		bufReader := bufio.NewReader(reader)
		mode := detectCompressionByMagic(bufReader)
		if mode == logCompressionNone {
			return &readerWithCloser{
				reader: bufReader,
				closer: &stackedCloser{
					closers: closers,
				},
			}, nil
		}

		nextReader, nextCloser, err := openCompressedLogLayer(mode, bufReader)
		if err != nil {
			closeAll(closers)
			return nil, err
		}
		closers = append(closers, nextCloser)
		reader = nextReader
	}

	closeAll(closers)
	return nil, fmt.Errorf("too many compression layers in log file: %s", logPath)
}

func openCompressedLogLayer(mode string, src io.Reader) (io.Reader, io.Closer, error) {
	switch mode {
	case logCompressionGzip:
		// Unwrap logrotate gzip output so downstream code reads the original JSONL stream.
		gzReader, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		return gzReader, gzReader, nil
	case logCompressionZstd:
		// Unwrap zstd frames written by precd and pass JSONL to event decoding.
		dec, err := newLogZstdDecoder(src)
		if err != nil {
			return nil, nil, err
		}
		return dec, zstdDecoderCloser{dec: dec}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported compression mode: %s", mode)
	}
}

type stackedCloser struct {
	closers []io.Closer
}

func (c *stackedCloser) Close() error {
	return closeAll(c.closers)
}

type zstdDecoderCloser struct {
	dec *zstd.Decoder
}

func (c zstdDecoderCloser) Close() error {
	c.dec.Close()
	return nil
}

func closeAll(closers []io.Closer) error {
	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
