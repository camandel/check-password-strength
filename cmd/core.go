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

	"check-password-strength/assets"

	colorable "github.com/mattn/go-colorable"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/olekukonko/tablewriter"
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

func loadBundledDict() ([]string, error) {

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

	// Open json file
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

func checkPassword(csvfile, jsonfile string) error {

	// load bundled dictionaries
	assetDict, err := loadBundledDict()
	if err != nil {
		log.Debug("errore loading bundled dictionaries")
		return err
	}

	// load custom dictionaries
	if jsonfile != "" {
		customDict, err := loadCustomDict(jsonfile)
		if err != nil {
			log.Debug("error loading custom dictionary")
			return err
		}

		assetDict = append(assetDict, customDict...)
	}

	lines, order, err := readCsv(csvfile)
	if err != nil {
		return err
	}
	log.Debugf("order: %v\n", order)

	var output [][]string

	for _, line := range lines {
		data := csvRow{
			URL:      line[order["url"]],
			Username: line[order["username"]],
			Password: line[order["password"]],
		}

		passwordStength := zxcvbn.PasswordStrength(data.Password, append(assetDict, data.Username))

		output = append(output, []string{data.URL, data.Username, data.Password,
			fmt.Sprintf("%d", passwordStength.Score),
			fmt.Sprintf("%.2f", passwordStength.Entropy),
			passwordStength.CrackTimeDisplay})
	}

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

		colorRow := []string{row[0], row[1], redactPassword(row[2]), score, row[5]}
		table.Rich(colorRow, []tablewriter.Colors{nil, nil, nil, {scoreColor}})

	}

	table.Render()
}
