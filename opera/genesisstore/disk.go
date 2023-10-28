package genesisstore

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"os"
	"crypto/sha256"


	"github.com/Fantom-foundation/lachesis-base/common/bigendian"
	"github.com/Fantom-foundation/lachesis-base/hash"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/status-im/keycard-go/hexutils"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/Fantom-foundation/go-opera/utils/iodb"



	"github.com/Fantom-foundation/go-opera/opera/genesis"
	"github.com/Fantom-foundation/go-opera/opera/genesisstore/filelog"
	"github.com/Fantom-foundation/go-opera/opera/genesisstore/fileshash"
	"github.com/Fantom-foundation/go-opera/opera/genesisstore/readersmap"
	"github.com/Fantom-foundation/go-opera/utils/ioread"
)

var (
	FileHeader  = hexutils.HexToBytes("641b00ac")
	FileVersion = hexutils.HexToBytes("00020001")
)

const (
	FilesHashMaxMemUsage = 256 * opt.MiB
	FilesHashPieceSize   = 64 * opt.MiB
)

type dummyByteReader struct {
	io.Reader
}

func (r dummyByteReader) ReadByte() (byte, error) {
	b := make([]byte, 1)
	err := ioread.ReadAll(r.Reader, b)
	return b[0], err
}

func checkFileHeader(reader io.Reader) error {
	headerAndVersion := make([]byte, len(FileHeader)+len(FileVersion))
	err := ioread.ReadAll(reader, headerAndVersion)
	if err != nil {
		return err
	}
	if bytes.Compare(headerAndVersion[:len(FileHeader)], FileHeader) != 0 {
		return errors.New("expected a genesis file, mismatched file header")
	}
	if bytes.Compare(headerAndVersion[len(FileHeader):], FileVersion) != 0 {
		got := hexutils.BytesToHex(headerAndVersion[len(FileHeader):])
		expected := hexutils.BytesToHex(FileVersion)
		return errors.New(fmt.Sprintf("wrong version of genesis file, got=%s, expected=%s", got, expected))
	}
	return nil
}

type ReadAtSeekerCloser interface {
	io.ReaderAt
	io.Seeker
	io.Closer
}

type Unit struct {
	UnitName string
	Header   genesis.Header
}

func OpenGenesisStore(rawReader ReadAtSeekerCloser) (*Store, genesis.Hashes, error) {
	header := genesis.Header{}
	hashes := genesis.Hashes{}
	units := make([]readersmap.Unit, 0, 3)
	offset := int64(0)
	for i := 0; ; i++ {
		// header cannot be long, cap it with 100000 bytes
		headerReader := io.NewSectionReader(rawReader, offset, offset+100000)
		err := checkFileHeader(headerReader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, hashes, err
		}
		unit := Unit{}
		err = rlp.Decode(dummyByteReader{headerReader}, &unit)
		if err != nil {
			return nil, hashes, err
		}
		if i == 0 {
			header = unit.Header
		} else {
			if !header.Equal(unit.Header) {
				return nil, hashes, errors.New("subsequent genesis header doesn't match the first header")
			}
		}

		var h hash.Hash
		err = ioread.ReadAll(headerReader, h[:])
		if err != nil {
			return nil, hashes, err
		}
		hashes[unit.UnitName] = h

		var numB [8]byte
		err = ioread.ReadAll(headerReader, numB[:])
		if err != nil {
			return nil, hashes, err
		}
		dataCompressedSize := bigendian.BytesToUint64(numB[:])

		err = ioread.ReadAll(headerReader, numB[:])
		if err != nil {
			return nil, hashes, err
		}
		uncompressedSize := bigendian.BytesToUint64(numB[:])

		headerSize, err := headerReader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, hashes, err
		}

		unitReader := io.NewSectionReader(rawReader, offset+headerSize, offset+headerSize+int64(dataCompressedSize))
		offset += headerSize + int64(dataCompressedSize)

		gzipReader, err := gzip.NewReader(unitReader)
		if err != nil {
			return nil, hashes, err
		}

		// wrap with a logger
		// human-readable name
		name := unit.UnitName
		scanfName := strings.ReplaceAll(name, "-", "")
		if scanfName[len(scanfName)-1] < '0' || scanfName[len(scanfName)-1] > '9' {
			scanfName += "0"
		}
		var part int
		if _, err := fmt.Sscanf(scanfName, "brs%d", &part); err == nil {
			name = fmt.Sprintf("blocks unit %d", part)
		}
		if _, err := fmt.Sscanf(scanfName, "ers%d", &part); err == nil {
			name = fmt.Sprintf("epochs unit %d", part)
		}
		if _, err := fmt.Sscanf(scanfName, "evm%d", &part); err == nil {
			name = fmt.Sprintf("EVM unit %d", part)
		}
		loggedReader := filelog.Wrap(gzipReader, name, uncompressedSize, time.Minute)

		units = append(units, readersmap.Unit{
			Name:   unit.UnitName,
			Reader: loggedReader,
		})
	}

	unitsMap, err := readersmap.Wrap(units)
	if err != nil {
		return nil, hashes, err
	}
	
	hashedMap := fileshash.Wrap(unitsMap.Open, FilesHashMaxMemUsage, hashes)

	genesisStore := NewStore(hashedMap, header, rawReader.Close)

    // Write to the genesis store
    filePath := "/home/devbox4/Desktop/dev/genesis.g"
    file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0600)
    if err != nil {
        return nil, hashes, err
    }
    defer file.Close()

    err = WriteGenesisStore(file, genesisStore)
    if err != nil {
        return nil, hashes, err
    }

    return genesisStore, hashes, nil
}
func (s *Store) Export(writer io.Writer) error {
	return iodb.Write2(writer, s.db)
}

func (s *Store) Hash() hash.Hash {
	hasher := sha256.New()
	it := iodb.NewIterator(nil)
	defer it.Release()
	for it.Next() {
		k := it.Key()
		v := it.Value()
		hasher.Write(bigendian.Uint32ToBytes(uint32(len(k))))
		hasher.Write(k)
		hasher.Write(bigendian.Uint32ToBytes(uint32(len(v))))
		hasher.Write(v)
	}
	return hash.BytesToHash(hasher.Sum(nil))
}
func WriteGenesisStore(rawWriter io.Writer, genesisStore *Store) error {
    _, err := rawWriter.Write(append(FileHeader, FileVersion...))
    if err != nil {
        return err
    }
    h := genesisStore.Hash()
    _, err = rawWriter.Write(h[:])
    if err != nil {
        return err
    }
    gzipWriter := gzip.NewWriter(rawWriter)
    defer gzipWriter.Close()
    err = genesisStore.Export(gzipWriter)
    if err != nil {
        return err
    }
    return nil
}
