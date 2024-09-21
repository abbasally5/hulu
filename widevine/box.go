package widevine

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type BoxHeader struct {
	Size uint32
	Type [4]byte
}

type PSSHBox struct {
	Version  uint8
	Flags    [3]byte
	SystemID [16]byte
	DataSize uint32
	Data     []byte
}

// ReadBoxHeader reads the MP4 box header (size and type)
func ReadBoxHeader(f *os.File) (*BoxHeader, error) {
	header := &BoxHeader{}
	err := binary.Read(f, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

// ParsePSSHBox parses the PSSH box from the file
func ParsePSSHBox(f *os.File, boxSize uint32) (*PSSHBox, error) {
	pssh := &PSSHBox{}

	// Read version and flags (4 bytes total)
	err := binary.Read(f, binary.BigEndian, &pssh.Version)
	if err != nil {
		return nil, err
	}
	_, err = f.Read(pssh.Flags[:])
	if err != nil {
		return nil, err
	}

	// Read system ID (16 bytes)
	_, err = f.Read(pssh.SystemID[:])
	if err != nil {
		return nil, err
	}

	// Read data size (4 bytes)
	err = binary.Read(f, binary.BigEndian, &pssh.DataSize)
	if err != nil {
		return nil, err
	}

	// Read the actual PSSH data
	pssh.Data = make([]byte, pssh.DataSize)
	_, err = f.Read(pssh.Data)
	if err != nil {
		return nil, err
	}

	return pssh, nil
}

func test() {
	fileName := "sample.mp4"

	f, err := os.Open(fileName)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	for {
		// Read the MP4 box header
		header, err := ReadBoxHeader(f)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading box header:", err)
			return
		}

		// Check if the box type is "pssh"
		if string(header.Type[:]) == "pssh" {
			// Parse the PSSH box
			psshBox, err := ParsePSSHBox(f, header.Size)
			if err != nil {
				fmt.Println("Error parsing PSSH box:", err)
				return
			}

			// Print the PSSH information
			fmt.Printf("PSSH Box Found!\n")
			fmt.Printf("Version: %d\n", psshBox.Version)
			fmt.Printf("System ID: %x\n", psshBox.SystemID)
			fmt.Printf("PSSH Data (hex): %x\n", psshBox.Data)
			return
		} else {
			// Skip to the next box (header.Size includes the 8-byte header, so subtract it)
			_, err = f.Seek(int64(header.Size)-8, io.SeekCurrent)
			if err != nil {
				fmt.Println("Error seeking to next box:", err)
				return
			}
		}
	}

	fmt.Println("PSSH Box not found in the MP4 file.")
}
