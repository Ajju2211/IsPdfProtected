package pdfencryption

import (
	"runtime"
	"sync"
)

const (
	bufferSize     = 1024
	encryptKeyword = "/Encrypt"
	multiplier     = 2
)

var encryptKeywordBytes = []byte(encryptKeyword)

func IsPasswordProtected(bytes []byte) bool {
	fileSize := int64(len(bytes))
	chunkSize := calculateChunkSize(fileSize)

	var wg sync.WaitGroup
	resultChan := make(chan bool)

	for offset := int64(0); offset < fileSize; offset += int64(chunkSize) {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()

			endOffset := offset + int64(chunkSize)
			if endOffset > fileSize {
				endOffset = fileSize
			}

			chunk := bytes[offset:endOffset]
			if containsKeyword(chunk, encryptKeywordBytes) {
				resultChan <- true
			}
		}(offset)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result {
			return true
		}
	}

	return false
}

func IsPasswordProtectedSimple(bytes []byte) bool {
	return containsKeyword(bytes, encryptKeywordBytes)
}

func calculateChunkSize(fileSize int64) int64 {
	totalThreads := int64(runtime.NumCPU()) * multiplier
	chunkSize := fileSize / totalThreads
	if chunkSize == 0 {
		chunkSize = 1
	}
	return chunkSize
}

// Using Boyer-Moore algorithm - https://favtutor.com/blogs/boyer-moore-algorithm for ref.
// Will return the first occurrence of the keyword.
func containsKeyword[Type containsInputType](buffer, keyword Type) bool {
	keywordLen := len(keyword)
	bufferLen := len(buffer)

	badCharTable := make([]int, 256)
	for i := range badCharTable {
		badCharTable[i] = keywordLen
	}
	for i := 0; i < keywordLen-1; i++ {
		badCharTable[keyword[i]] = keywordLen - i - 1
	}

	i := keywordLen - 1
	for i < bufferLen {
		k := 0
		for k < keywordLen && keyword[keywordLen-k-1] == buffer[i-k] {
			k++
		}
		if k == keywordLen {
			return true
		}
		i += badCharTable[buffer[i]]
	}

	return false
}
