package cmd

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

var log = New(Level).Sugar()

// Execute main function
func Execute() {

	var debug bool
	var customDict string

	app := &cli.App{
		Name:      "check-password-strength",
		Usage:     "Check the passwords strength from csv file",
		UsageText: "check-password-strength [--customdict JSONFILE] [--debug] CSVFILE",
		Version:   Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "customdict",
				Aliases:     []string{"c"},
				Usage:       "Load custom dictionary from `JSONFILE`",
				Destination: &customDict,
			},
			&cli.BoolFlag{Name: "debug",
				Aliases:     []string{"d"},
				Destination: &debug,
				Value:       false,
				Usage:       "show debug logs"},
		},
		HideHelpCommand: false,
		Action: func(c *cli.Context) error {

			if debug {
				Level.SetLevel(DebugLevel)
			}

			if c.NArg() != 1 {
				fmt.Print("One filename must be specified\n\n")
				cli.ShowAppHelpAndExit(c, 1)
			}

			return checkPassword(c.Args().First(), customDict)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
