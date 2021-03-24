package cmd

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

var log = New(Level).Sugar()

// Execute main function
func Execute() {

	var interactive, debug bool
	var filename, customDict string

	app := &cli.App{
		Name:      "check-password-strength",
		Usage:     "Check the passwords strength from csv file, interactively or stdin
		",
		UsageText: "check-password-strength [--customdict JSONFILE] [--interactive ]|[--filename CSVFILE]] [--debug]",
		Version:   Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "filename",
				Aliases:     []string{"f"},
				Usage:       "Check passwords from `CSVFILE`",
				Destination: &filename,
			},
			&cli.StringFlag{
				Name:        "customdict",
				Aliases:     []string{"c"},
				Usage:       "Load custom dictionary from `JSONFILE`",
				Destination: &customDict,
			},
			&cli.BoolFlag{Name: "interactive",
				Aliases:     []string{"i"},
				Destination: &interactive,
				Value:       false,
				Usage:       "enable interactive mode asking data from console"},
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

			if filename != "" && interactive {
				fmt.Print("Can not use '-f' and '-i' flags at the same time\n\n")
				cli.ShowAppHelpAndExit(c, -1)
			}

			// if c.NArg() != 1 {
			// 	fmt.Print("One filename must be specified\n\n")
			// 	cli.ShowAppHelpAndExit(c, 1)
			// }

			//return checkPassword(c.Args().First(), customDict)
			return checkPassword(filename, customDict, interactive)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
