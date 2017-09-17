package config

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/asaskevich/govalidator"
)

func init() {
	govalidator.SetFieldsRequiredByDefault(true)
}

var (
	DefaultLocation string = "./pdfsign.conf" // Default location of the config file
	Settings        Config                    // Initialized once inside Read method Settings are stored in memory.
)

// Config is the root of the config
type Config struct {
	//Info:
	//Name:        "Jeroen Bobbeldijk",
	//Location:    "Rotterdam",
	//Reason:      "Test",
	//ContactInfo: "Geen",
	//CertType: 2,
	//Approval: false,
	//TSA: sign.TSA{
	//URL: "http://aatl-timestamp.globalsign.com/tsa/aohfewat2389535fnasgnlg5m23",
}

// ValidateFields validates all the fields of the config
func (c Config) ValidateFields() error {
	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		return err
	}
	return nil
}

func Read(configfile string) {

	_, err := os.Stat(configfile)
	if err != nil {
		log.Fatal("Config file is missing: ", configfile)
	}

	var c Config
	if _, err := toml.DecodeFile(configfile, &c); err != nil {
	}

	if err := c.ValidateFields(); err != nil {
		log.Fatal("Config is not valid: ", err)
	}

	Settings = c
}
