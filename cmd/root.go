package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "guardian",
	Short: "My Guardian — detector de fraude y phishing en e-commerce",
	Long: `My Guardian analiza URLs y vendedores para detectar señales de fraude,
phishing y estafas en tiendas en línea y marketplaces.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}
