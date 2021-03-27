package cmd

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"check-password-strength/assets"

	colorable "github.com/mattn/go-colorable"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh/terminal"
)

type csvHeader map[string]*[]string

type csvHeaderOrder map[string]int

type csvRow struct {
	URL      string
	Username string
	Password string
}

type jsonData struct {
	Words []string `json:"words"`
}

func loadBundleDict() ([]string, error) {

	var assetDict []string

	for _, an := range assets.AssetNames() {

		var d jsonData

		data, err := assets.Asset(an)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(data, &d)
		if err != nil {
			return nil, err
		}

		assetDict = append(assetDict, d.Words...)
	}

	return assetDict, nil
}

func loadCustomDict(filename string) ([]string, error) {

	var customDict []string
	var d jsonData

	log.Debugf("custom dict filename: %s", filename)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &d)
	if err != nil {
		return nil, err
	}

	if len(d.Words) == 0 {
		return nil, errors.New("Object 'words' is empty, custom dictionary not loaded")
	}

	customDict = append(customDict, d.Words...)

	return customDict, nil
}

func loadAllDict(filename string) ([]string, error) {
	// load bundle dictionaries
	assetDict, err := loadBundleDict()
	if err != nil {
		log.Debug("errore loading bundled dictionaries")
		return nil, err
	}

	// load custom dictionaries
	if filename != "" {
		customDict, err := loadCustomDict(filename)
		if err != nil {
			log.Debug("error loading custom dictionary")
			return nil, err
		}
		assetDict = append(assetDict, customDict...)
	}

	return assetDict, nil
}

func askUsernamePassword() (string, string, error) {

	var username string

	fmt.Print("Enter Username: ")
	fmt.Scanln(&username)
	fmt.Print("Enter Password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		return "", "", err
	}

	return username, string(password), nil
}

func checkMultiplePassword(csvfile, jsonfile string, interactive bool) error {

	var output [][]string

	// load all dictionaries
	allDict, err := loadAllDict(jsonfile)
	if err != nil {
		return err
	}

	lines, order, err := readCsv(csvfile)
	if err != nil {
		return err
	}
	log.Debugf("order: %v\n", order)

	for _, line := range lines {
		data := csvRow{
			URL:      line[order["url"]],
			Username: line[order["username"]],
			Password: line[order["password"]],
		}

		passwordStength := zxcvbn.PasswordStrength(data.Password, append(allDict, data.Username))
		data.Password = redactPassword(data.Password)
		output = append(output, []string{data.URL, data.Username, data.Password,
			fmt.Sprintf("%d", passwordStength.Score),
			fmt.Sprintf("%.2f", passwordStength.Entropy),
			passwordStength.CrackTimeDisplay})
	}

	showTable(output, colorable.NewColorableStdout())

	return nil
}

func checkSinglePassword(username, password, jsonfile string, quiet bool) error {

	var output [][]string

	// load all dictionaries
	allDict, err := loadAllDict(jsonfile)
	if err != nil {
		return err
	}

	passwordStength := zxcvbn.PasswordStrength(password, append(allDict, username))
	password = redactPassword(password)

	if quiet {
		os.Exit(passwordStength.Score)
	}

	output = append(output, []string{"", username, password,
		fmt.Sprintf("%d", passwordStength.Score),
		fmt.Sprintf("%.2f", passwordStength.Entropy),
		passwordStength.CrackTimeDisplay})

	showTable(output, colorable.NewColorableStdout())

	return nil
}

func readCsv(filename string) ([][]string, csvHeaderOrder, error) {

	log.Debugf("csv filename: %s", filename)

	// Open CSV file
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, nil, err
	}

	if len(lines) == 0 {
		return nil, nil, errors.New("File empty")
	}
	header := lines[0]

	order, err := checkCSVHeader(header)
	if err != nil {
		return nil, nil, err
	}

	// remove header
	return lines[1:], order, nil
}

func checkCSVHeader(header []string) (csvHeaderOrder, error) {

	// initialize structs
	headers := &csvHeader{
		"url":      &[]string{"url", "login_uri", "web site"},
		"username": &[]string{"username", "login_username", "login name"},
		"password": &[]string{"password", "login_password"},
	}

	log.Debugf("header: %v", header)

	order := make(csvHeaderOrder)

	for position, fieldFromFile := range header {
		// check header
		for k, h := range *headers {
			for _, v := range *h {
				if strings.ToLower(fieldFromFile) == v {
					if _, ok := order[k]; ok {
						return nil, errors.New("Header not valid")
					}
					order[k] = position
				}
			}
		}
	}

	if len(order) != 3 {
		return nil, errors.New("Header not valid")
	}
	return order, nil
}

func redactPassword(p string) string {
	if len(p) < 3 {
		return "********"
	}
	return fmt.Sprintf("%s******%s", p[0:1], p[len(p)-1:])
}

func showTable(data [][]string, w io.Writer) {
	// writer is a s parameter to pass buffer during tests
	table := tablewriter.NewWriter(w)
	table.SetHeader([]string{"URL", "Username", "Password", "Score (0-4)", "Estimated time to crack"})
	table.SetBorder(false)
	table.SetAlignment(tablewriter.ALIGN_LEFT)

	for _, row := range data {
		var score string
		var scoreColor int

		switch row[3] {
		case "0":
			score = " 0 - Really bad "
			scoreColor = tablewriter.BgRedColor
		case "1":
			score = " 1 - Bad        "
			scoreColor = tablewriter.BgHiRedColor
		case "2":
			score = " 2 - Weak       "
			scoreColor = tablewriter.BgHiYellowColor
		case "3":
			score = " 3 - Good       "
			scoreColor = tablewriter.BgHiGreenColor
		case "4":
			score = " 4 - Strong     "
			scoreColor = tablewriter.BgGreenColor
		}

		colorRow := []string{row[0], row[1], row[2], score, row[5]}
		table.Rich(colorRow, []tablewriter.Colors{nil, nil, nil, {scoreColor}})

	}

	table.Render()
}

func getPwdStdin() (string, error) {

	info, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}

	if info.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("Pipe error on stdin")
	}

	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}

	// remove spaces and new line
	output := strings.TrimSpace(string(stdinBytes))

	return output, nil
}
