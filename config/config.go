package config

import (
	"log"
	"os"

	"bitbucket.org/digitorus/pdfsign/sign"
	"github.com/BurntSushi/toml"
)

var (
	DefaultLocation string = "./pdfsign.conf" // Default location of the config file
	Settings        Config                    // Initialized once inside Read method Settings are stored in memory.
)

// Config is the root of the config
type Config struct {
	Info sign.SignDataSignatureInfo
	TSA  sign.TSA
}

func Read(configfile string) {

	_, err := os.Stat(configfile)
	if err != nil {
		log.Fatal("Config file is missing: ", configfile)
	}

	var c Config
	if _, err := toml.DecodeFile(configfile, &c); err != nil {
	}

	Settings = c
}
