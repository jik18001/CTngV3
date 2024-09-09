package def

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	RED    = "\x1b[31m"
	GREEN  = "\x1b[32m"
	YELLOW = "\x1b[33m"
	BLUE   = "\x1b[34m"
	RESET  = "\x1b[0m"
)

type OutOfBounds struct{}

func (e *OutOfBounds) Error() string {
	return "Index Out of Bounds"
}

func RemovePadding(data []byte) []byte {
	// Remove zero padding from the end of data slices
	// This is safe under the assumption that original data does not end with zero bytes
	return bytes.TrimRight(data, "\x00")
}

func HandleError(err error, functionName string) {
	if err != nil {
		pc, fn, line, _ := runtime.Caller(1)
		logMessage := fmt.Sprintf("[ERROR] in %s[%s:%d] %s: %v",
			functionName,
			runtime.FuncForPC(pc).Name(),
			line,
			fn,
			err)
		log.Println(logMessage)
	}
}

// This read function reads from a Json file as a byte array and returns it.
// This function will be called for all the reading from json functions
func LoadData(config interface{}, file string) { //takes in the struct that it is updating and the file it is updating with
	// Let's first read the file
	content, err := os.ReadFile(file)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
	}
	// Now let's unmarshall the data into `payload`
	err = json.Unmarshal(content, config)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}
}

// Writes arbitrary data as a JSON File.
// If the file does not exist, it will be created.
func WriteData(data interface{}, filename string) error {
	jsonFile, err := os.Open(filename)
	// if we os.Open returns an error then handle it
	if err != nil && strings.Contains(err.Error(), "no such file or directory") {
		jsonFile, err = os.Create(filename)
	}
	if err != nil {
		return err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()
	//write to the corresponding file
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func CreateFile(path string) {
	// check if file exists
	var _, err = os.Stat(path)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			return
		}
		defer file.Close()
	}
}

func CreateDir(path string) {
	// check if directory exists
	var _, err = os.Stat(path)
	// create directory if not exists
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, 0755)
		if errDir != nil {
			return
		}
	}
}

func DeleteFilesAndDirectories(path string) error {
	// Open the directory specified by the path
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	// Read all the contents of the directory
	fileInfos, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	// Loop through all the files and directories in the directory
	for _, fileInfo := range fileInfos {
		// Create the full path to the file or directory
		fullPath := path + "/" + fileInfo.Name()

		// If the file or directory is a directory, recursively delete it
		if fileInfo.IsDir() {
			if err := DeleteFilesAndDirectories(fullPath); err != nil {
				return err
			}
		} else {
			// Otherwise, delete the file
			if err := os.Remove(fullPath); err != nil {
				return err
			}
		}
	}

	// Finally, delete the directory itself
	if err := os.Remove(path); err != nil {
		return err
	}

	return nil
}

func CompressData(data []byte) ([]byte, error) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	_, err := gzipWriter.Write(data)
	if err != nil {
		return nil, err
	}
	gzipWriter.Close()
	return compressed.Bytes(), nil
}

func DecompressData(compressedData []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, err
	}
	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}
	return decompressedData, nil
}

func GenerateRandomCTngIDs(numID int, total int) []CTngID {
	rand.Seed(time.Now().UnixNano())
	if numID > total {
		fmt.Println("numID cannot be greater than total")
		return nil
	}

	// Create a map to track used IDs to ensure uniqueness
	usedIDs := make(map[int]bool)
	result := make([]CTngID, numID)

	for i := 0; i < numID; i++ {
		var id int
		for {
			id = rand.Intn(total) + 1
			if !usedIDs[id] {
				usedIDs[id] = true
				break
			}
		}
		result[i] = CTngID("M" + strconv.Itoa(id))
	}

	return result
}
