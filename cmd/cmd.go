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

	app := &cli.App{
		Name:      "check-password-strength",
		Usage:     "Check the passwords strength from csv file",
		UsageText: "check-password-strength [--debug] CSVFILE",
		Version:   Version,
		Flags: []cli.Flag{
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

			return checkPassword(c.Args().First())
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
