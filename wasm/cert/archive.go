package cert

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/korean"
)

// CA 가 보내주는 ZIP 압축파일을 메모리에서 푼다.
// 압축 폭탄 방지를 위해 파일 수, 파일당 크기, 전체 크기를 제한한다. 한국어 Windows 에서 만든 ZIP 은 파일명이 CP949 이므로
// UTF-8 이 아니면 CP949 로 읽는다.

const (
	maxArchiveEntries    = 500
	maxArchiveEntryBytes = 5 * 1024 * 1024
	maxArchiveTotalBytes = 50 * 1024 * 1024
)

// 인증서가 들어 있을 리 없는 문서/이미지/실행 파일은 읽지 않는다
var skippedExtensions = map[string]bool{"pdf": true, "doc": true, "docx": true, "hwp": true, "hwpx": true,
	"xls": true, "xlsx": true, "ppt": true, "pptx": true, "png": true, "jpg": true, "jpeg": true, "gif": true,
	"bmp": true, "html": true, "htm": true, "exe": true, "msi": true, "dll": true}

func isZip(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' &&
		((data[2] == 3 && data[3] == 4) || (data[2] == 5 && data[3] == 6))
}

// extractArchive 는 검사할 파일과 읽지 않은 파일 이름을 돌려준다.
func extractArchive(data []byte) (entries []InputSource, skipped []string, err error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, conversionError(err, "손상되었거나 지원하지 않는 ZIP 파일입니다: %v", err)
	}
	if len(reader.File) > maxArchiveEntries {
		return nil, nil, conversionError(nil, "압축파일 안의 파일이 너무 많습니다 (최대 %d개)", maxArchiveEntries)
	}
	total := 0
	for _, file := range reader.File {
		name := entryName(file)
		if file.FileInfo().IsDir() || isSystemFile(name) {
			continue
		}
		if skippedExtensions[extension(name)] {
			skipped = append(skipped, name)
			continue
		}
		if file.Flags&0x1 != 0 {
			return nil, nil, conversionError(nil, "암호가 걸린 ZIP 파일은 읽을 수 없습니다. 압축을 푼 뒤 안의 파일을 올리세요")
		}
		content, err := readEntry(file)
		if err != nil {
			return nil, nil, conversionError(err, "ZIP 파일을 읽을 수 없습니다: %v", err)
		}
		if len(content) > maxArchiveEntryBytes {
			skipped = append(skipped, name+" (크기 초과)")
			continue
		}
		total += len(content)
		if total > maxArchiveTotalBytes {
			return nil, nil, conversionError(nil, "압축 해제 크기가 너무 큽니다 (최대 %dMB)", maxArchiveTotalBytes/1024/1024)
		}
		entries = append(entries, InputSource{Name: name, Data: content})
	}
	return entries, skipped, nil
}

func readEntry(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		if errors.Is(err, zip.ErrAlgorithm) {
			return nil, fmt.Errorf("지원하지 않는 압축 방식")
		}
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(io.LimitReader(reader, maxArchiveEntryBytes+1))
}

func entryName(file *zip.File) string {
	if !file.NonUTF8 && utf8.ValidString(file.Name) {
		return file.Name
	}
	if decoded, err := korean.EUCKR.NewDecoder().String(file.Name); err == nil {
		return decoded
	}
	return file.Name
}

func isSystemFile(name string) bool {
	base := path.Base(name)
	return strings.HasPrefix(name, "__MACOSX/") || strings.Contains(name, "/__MACOSX/") ||
		strings.HasPrefix(base, "._") || base == ".DS_Store" || strings.EqualFold(base, "Thumbs.db") ||
		strings.EqualFold(base, "desktop.ini")
}

func extension(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot < 0 || dot < strings.LastIndex(name, "/") {
		return ""
	}
	return strings.ToLower(name[dot+1:])
}
