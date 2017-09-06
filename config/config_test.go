package config_test

import (
	"testing"

	"bitbucket.org/digitorus/littlewatcher/src/config"
	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	const configContent = `
staticPath = "../static"
`

	var c config.Config

	if _, err := toml.Decode(configContent, &c); err != nil {
		t.Error(err)
	}

	// Root
	assert.Equal(t, "../static", c.StaticPath)

}

func TestValidation(t *testing.T) {
	const configContent = ``

	var c config.Config
	if _, err := toml.Decode(configContent, &c); err != nil {
		t.Error(err)
	}

	err := c.ValidateFields()
	assert.NotNil(t, err)
}
