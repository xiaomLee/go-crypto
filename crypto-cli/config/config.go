package config

type Config struct {
	PublicKey   string `mapstructure:"public-key"`
	PrivateKey  string `mapstructure:"private-key"`
	GenerateKey bool   `mapstructure:"generate-key"`
	Security    string `mapstructure:"security"`
	File        string `mapstructure:"file"`
	Out         string `mapstructure:"out"`
}
