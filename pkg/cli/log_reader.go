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

func openLogReader(logPath string) (io.ReadCloser, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	modeBySuffix := detectCompressionBySuffix(logPath)
	if modeBySuffix == logCompressionGzip {
		return openGzipLogReader(f, f)
	}
	if modeBySuffix == logCompressionZstd {
		return openZstdLogReader(f, f)
	}

	bufReader := bufio.NewReader(f)
	modeByMagic := detectCompressionByMagic(bufReader)
	if modeByMagic == logCompressionGzip {
		return openGzipLogReader(f, bufReader)
	}
	if modeByMagic == logCompressionZstd {
		return openZstdLogReader(f, bufReader)
	}

	return &readerWithCloser{
		reader: bufReader,
		closer: f,
	}, nil
}

func detectLogCompression(logPath string, hint string) (string, error) {
	modeBySuffix := detectCompressionBySuffix(logPath)
	if modeBySuffix != logCompressionNone {
		return modeBySuffix, nil
	}

	f, err := os.Open(logPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	modeByMagic := detectCompressionByMagic(bufio.NewReader(f))
	if modeByMagic != logCompressionNone {
		return modeByMagic, nil
	}

	normalizedHint := strings.ToLower(strings.TrimSpace(hint))
	if normalizedHint == logCompressionGzip || normalizedHint == logCompressionZstd {
		return normalizedHint, nil
	}
	return logCompressionNone, nil
}

func detectCompressionBySuffix(logPath string) string {
	if strings.HasSuffix(logPath, ".gz") {
		return logCompressionGzip
	}
	if strings.HasSuffix(logPath, ".zst") {
		return logCompressionZstd
	}
	return logCompressionNone
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

func openGzipLogReader(base io.Closer, src io.Reader) (io.ReadCloser, error) {
	// Transparently decompress .gz rotated logs so they are included in list mode.
	gzReader, err := gzip.NewReader(src)
	if err != nil {
		base.Close()
		return nil, err
	}
	return &gzipLogReadCloser{
		base: base,
		gz:   gzReader,
	}, nil
}

func openZstdLogReader(base io.Closer, src io.Reader) (io.ReadCloser, error) {
	dec, err := zstd.NewReader(src)
	if err != nil {
		base.Close()
		return nil, err
	}
	return &zstdLogReadCloser{
		base: base,
		dec:  dec,
	}, nil
}

type gzipLogReadCloser struct {
	base io.Closer
	gz   *gzip.Reader
}

func (r *gzipLogReadCloser) Read(p []byte) (int, error) {
	return r.gz.Read(p)
}

func (r *gzipLogReadCloser) Close() error {
	gzErr := r.gz.Close()
	baseErr := r.base.Close()
	if gzErr != nil {
		return gzErr
	}
	return baseErr
}

type zstdLogReadCloser struct {
	base io.Closer
	dec  *zstd.Decoder
}

func (r *zstdLogReadCloser) Read(p []byte) (int, error) {
	return r.dec.Read(p)
}

func (r *zstdLogReadCloser) Close() error {
	r.dec.Close()
	return r.base.Close()
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

func (r *compressedTailReader) Reset(mode string, onLine func(string)) error {
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

func decodeCompressedTailStream(mode string, src io.Reader, onLine func(string)) error {
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
		dec, err := zstd.NewReader(src)
		if err != nil {
			return err
		}
		defer dec.Close()
		return scanDecompressedLines(dec, onLine)
	default:
		return fmt.Errorf("unsupported compression mode: %s", mode)
	}
}

func scanDecompressedLines(reader io.Reader, onLine func(string)) error {
	scanner := bufio.NewScanner(reader)
	// Keep follow mode aligned with max_arg_length by allowing lines up to 1MB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		onLine(scanner.Text())
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
