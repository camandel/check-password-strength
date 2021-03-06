package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"testing"
)

func TestRedactPassword(t *testing.T) {

	tests := []struct {
		name string
		in   string
		out  string
	}{
		{
			name: "Short password",
			in:   "pwd",
			out:  "p******d",
		},
		{
			name: "Long password",
			in:   "passssswwwwwoooorrrrdddd",
			out:  "p******d",
		},
		{
			name: "Empty password",
			in:   "",
			out:  "********",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			p := redactPassword(tt.in)

			if !reflect.DeepEqual(tt.out, p) {
				t.Fatalf("got %s, expected %s", p, tt.out)
			}

		})
	}
}

func TestGenerateHash(t *testing.T) {

	tests := []struct {
		name     string
		seed     []byte
		password string
		out      string
	}{
		{
			name:     "first password",
			seed:     []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			password: "password",
			out:      "c7f42603",
		},
		{
			name:     "same seed and different password",
			seed:     []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			password: "otherpassword",
			out:      "1413a414",
		},
		{
			name:     "same password but different seed",
			seed:     []byte{0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			password: "password",
			out:      "4b124f90",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := generateHash(tt.seed, tt.password)

			if !reflect.DeepEqual(tt.out, h) {
				t.Fatalf("got %s, expected %s", h, tt.out)
			}

		})
	}
}

func TestReadCsv(t *testing.T) {

	tests := []struct {
		name string
		in   []string
		out  csvHeaderOrder
		err  error
	}{
		{
			name: "Chrome csv header",
			in:   []string{"name", "url", "username", "password"},
			out:  csvHeaderOrder{"url": 1, "username": 2, "password": 3},
			err:  nil,
		},
		{
			name: "Chrome csv header",
			in:   []string{"name", "url", "username", "password"},
			out:  csvHeaderOrder{"url": 1, "username": 2, "password": 3},
			err:  nil,
		},
		{
			name: "Firefox csv header",
			in:   []string{"url", "username", "password"},
			out:  csvHeaderOrder{"url": 0, "username": 1, "password": 2},
			err:  nil,
		},
		{
			name: "Lastpass csv header",
			in:   []string{"url", "username", "password", "others"},
			out:  csvHeaderOrder{"url": 0, "username": 1, "password": 2},
			err:  nil,
		},
		{
			name: "Bitwarden csv header",
			in:   []string{"folder", "favorite", "type", "name", "notes", "fields", "login_uri", "login_username", "login_password"},
			out:  csvHeaderOrder{"url": 6, "username": 7, "password": 8},
			err:  nil,
		},
		{
			name: "Keepass csv header",
			in:   []string{"Group", "Title", "Username", "Password", "URL"},
			out:  csvHeaderOrder{"url": 4, "username": 2, "password": 3},
			err:  nil,
		},
		{
			name: "Custom csv header",
			in:   []string{"Username", "Password", "Url"},
			out:  csvHeaderOrder{"url": 2, "username": 0, "password": 1},
			err:  nil,
		},
		{
			name: "Missing field in csv header",
			in:   []string{"Username", "Url"},
			out:  csvHeaderOrder{},
			err:  errors.New("Header not valid"),
		},
		{
			name: "Duplicate fields in csv header",
			in:   []string{"Username", "Password", "Url", "login_username"},
			out:  csvHeaderOrder{},
			err:  errors.New("Header not valid"),
		},
		{
			name: "More fields with similar name in csv header",
			in:   []string{"Username", "Password", "Url", "login_username"},
			out:  csvHeaderOrder{},
			err:  errors.New("Header not valid"),
		},
		{
			name: "No header",
			in:   []string{},
			out:  csvHeaderOrder{},
			err:  errors.New("Header not valid"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			order, err := checkCSVHeader(tt.in)
			if err != nil {
				if err.Error() != tt.err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
				return
			}
			if tt.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.err)
			}
			if !reflect.DeepEqual(tt.out, order) {
				t.Fatalf("got %v, expected %v", order, tt.out)
			}
		})
	}
}

func TestShowTable(t *testing.T) {

	tests := []struct {
		name string
		in   [][]string
		out  string
	}{
		{
			name: "Single row",
			in:   [][]string{{"url1", "user1", "p******1", "1", "5.00", "instant", ""}},
			out: `  URL  | USERNAME | PASSWORD |   SCORE (0-4)    | ESTIMATED TIME TO CRACK | ALREADY USED  
-------+----------+----------+------------------+-------------------------+---------------
  url1 | user1    | p******1 | [101m 1 - Bad        [0m | instant                 |               
`,
		},
		{
			name: "Multiple rows no duplicates",
			in: [][]string{
				{"url0", "user0", "p******0", "0", "5.00", "instant", ""},
				{"url1", "user1", "p******1", "1", "5.00", "instant", ""},
				{"url2", "user2", "p******2", "2", "5.00", "instant", ""},
				{"url3", "user3", "p******3", "3", "5.00", "instant", ""},
				{"url4", "user4", "p******4", "4", "5.00", "instant", ""},
			},
			out: `  URL  | USERNAME | PASSWORD |   SCORE (0-4)    | ESTIMATED TIME TO CRACK | ALREADY USED  
-------+----------+----------+------------------+-------------------------+---------------
  url0 | user0    | p******0 | [41m 0 - Really bad [0m | instant                 |               
  url1 | user1    | p******1 | [101m 1 - Bad        [0m | instant                 |               
  url2 | user2    | p******2 | [103m 2 - Weak       [0m | instant                 |               
  url3 | user3    | p******3 | [102m 3 - Good       [0m | instant                 |               
  url4 | user4    | p******4 | [42m 4 - Strong     [0m | instant                 |               
`,
		},
		{
			name: "Multiple rows with duplicates",
			in: [][]string{
				{"url0", "user0", "p******0", "0", "5.00", "instant", "aaaaaaaa"},
				{"url1", "user1", "p******1", "1", "5.00", "instant", "bbbbbbbb"},
				{"url2", "user2", "p******0", "0", "5.00", "instant", "aaaaaaaa"},
				{"url3", "user3", "p******3", "3", "5.00", "instant", ""},
				{"url4", "user4", "p******1", "1", "5.00", "instant", "bbbbbbbb"},
			},
			out: `  URL  | USERNAME | PASSWORD |   SCORE (0-4)    | ESTIMATED TIME TO CRACK | ALREADY USED  
-------+----------+----------+------------------+-------------------------+---------------
  url0 | user0    | p******0 | [41m 0 - Really bad [0m | instant                 | aaaaaaaa      
  url1 | user1    | p******1 | [101m 1 - Bad        [0m | instant                 | bbbbbbbb      
  url2 | user2    | p******0 | [41m 0 - Really bad [0m | instant                 | aaaaaaaa      
  url3 | user3    | p******3 | [102m 3 - Good       [0m | instant                 |               
  url4 | user4    | p******1 | [101m 1 - Bad        [0m | instant                 | bbbbbbbb      
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			buf := &bytes.Buffer{}
			showTable(tt.in, buf)

			if !reflect.DeepEqual(tt.out, buf.String()) {
				t.Fatalf("got %s, expected %s", buf.String(), tt.out)
			}

		})
	}
}

func TestShowStats(t *testing.T) {

	tests := []struct {
		name string
		in   statistics
		out  string
	}{
		{
			name: "Single row",
			in: statistics{
				TotCount:       1,
				WordsCount:     59824,
				ScoreCount:     []int{0, 0, 0, 0, 1},
				DuplicateCount: 0,
			},
			out: `       DESCRIPTION      | COUNT  
------------------------+--------
  Password checked      |     1  
  Words in dictionaries | 59824  
  Duplicated passwords  |     0  
  Really bad passwords  |     0  
  Bad passwords         |     0  
  Weak passwords        |     0  
  Good passwords        |     0  
  Strong passwords      |     1  
`,
		},
		{
			name: "Multiple row",
			in: statistics{
				TotCount:       9,
				WordsCount:     59824,
				ScoreCount:     []int{3, 1, 2, 1, 2},
				DuplicateCount: 2,
			},
			out: `       DESCRIPTION      | COUNT  
------------------------+--------
  Password checked      |     9  
  Words in dictionaries | 59824  
  Duplicated passwords  |     2  
  Really bad passwords  |     3  
  Bad passwords         |     1  
  Weak passwords        |     2  
  Good passwords        |     1  
  Strong passwords      |     2  
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			buf := &bytes.Buffer{}
			showStats(tt.in, buf)

			if !reflect.DeepEqual(tt.out, buf.String()) {
				t.Fatalf("got %s, expected %s", buf.String(), tt.out)
			}

		})
	}
}

func TestReadCSV(t *testing.T) {

	type CSVData struct {
		row   [][]string
		order csvHeaderOrder
		err   error
	}

	testdir := fmt.Sprintf("..%ctest%c", os.PathSeparator, os.PathSeparator)
	filenotfound := fmt.Sprintf("open %snot-exists.csv: no such file or directory", testdir)
	if runtime.GOOS == "windows" {
		filenotfound = fmt.Sprintf("open %snot-exists.csv: The system cannot find the file specified.", testdir)
	}

	tests := []struct {
		name string
		in   string
		out  CSVData
	}{
		{
			name: "Simple csv file with quotes",

			in: testdir + "simple-with-quotes.csv",
			out: CSVData{
				row:   [][]string{{"url1", "user1", "password1"}},
				order: csvHeaderOrder{"url": 0, "username": 1, "password": 2},
				err:   nil,
			},
		},
		{
			name: "Simple csv file without quotes",
			in:   testdir + "simple-no-quotes.csv",
			out: CSVData{
				row:   [][]string{{"url1", "user1", "password1"}},
				order: csvHeaderOrder{"url": 0, "username": 1, "password": 2},
				err:   nil,
			},
		},
		{
			name: "Empty csv file",
			in:   testdir + "empty.csv",
			out: CSVData{
				row:   [][]string{},
				order: csvHeaderOrder{},
				err:   errors.New("File empty"),
			},
		},
		{
			name: "Not existing csv file",
			in:   testdir + "not-exists.csv",
			out: CSVData{
				row:   [][]string{},
				order: csvHeaderOrder{},
				err:   errors.New(filenotfound),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			var out CSVData

			out.row, out.order, out.err = readCsv(tt.in)

			if out.err != nil {
				if tt.out.err == nil {
					t.Fatalf("got error: %v, want nil error", out.err)
				}
				if out.err.Error() != tt.out.err.Error() {
					t.Fatalf("got error: %v, want error: %v", out.err, tt.out.err)
				}
				return
			}

			if tt.out.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.out.err)
			}

			if !reflect.DeepEqual(tt.out.row, out.row) {
				t.Fatalf("got %v, expected %v", out.row, tt.out.row)
			}
			if !reflect.DeepEqual(tt.out.order, out.order) {
				t.Fatalf("got %v, expected %v", out.order, tt.out.order)
			}

		})
	}
}

func TestReadJSON(t *testing.T) {

	testdir := fmt.Sprintf("..%ctest%c", os.PathSeparator, os.PathSeparator)
	filenotfound := fmt.Sprintf("open %snot-exists.json: no such file or directory", testdir)
	if runtime.GOOS == "windows" {
		filenotfound = fmt.Sprintf("open %snot-exists.json: The system cannot find the file specified.", testdir)
	}

	tests := []struct {
		name string
		in   string
		out  []string
		err  error
	}{
		{
			name: "Correct json file",
			in:   testdir + "words.json",
			out:  []string{"polygon-approve-entire-coexist", "Gsg#H4k#*966Dx"},
			err:  nil,
		},
		{
			name: "Wrong json file",
			in:   testdir + "wrong-name.json",
			out:  nil,
			err:  errors.New("Object 'words' is empty, custom dictionary not loaded"),
		},
		{
			name: "Empty csv file",
			in:   testdir + "empty.json",
			out:  nil,
			err:  errors.New("unexpected end of JSON input"),
		},
		{
			name: "Not existing json file",
			in:   testdir + "not-exists.json",
			out:  nil,
			err:  errors.New(filenotfound),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			out, err := loadCustomDict(tt.in)

			if err != nil {
				if tt.err == nil {
					t.Fatalf("got error: %v, want nil error", err)
				}
				if err.Error() != tt.err.Error() {
					t.Fatalf("got error: %v, want error: %v", err, tt.err)
				}
				return
			}

			if tt.err != nil {
				t.Fatalf("got nil error, want error: %v", tt.err)
			}

			if !reflect.DeepEqual(tt.out, out) {
				t.Fatalf("got %v, expected %v", out, tt.out)
			}
		})
	}
}
