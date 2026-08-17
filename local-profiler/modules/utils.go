package modules

import "os"

func OpenFile(fileName string) (*os.File, error) {

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return nil, err
	}
	return file, nil
}
