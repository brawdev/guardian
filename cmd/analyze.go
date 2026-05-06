package cmd

import (
	"fmt"
	"os"

	"github.com/brawdev/guardian/internal/urlanalyzer"
	"github.com/brawdev/guardian/pkg/report"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var jsonOutput bool

var analyzeCmd = &cobra.Command{
	Use:   "analyze <url>",
	Short: "Analiza una URL en busca de señales de phishing o fraude",
	Example: `  guardian analyze https://amaz0n-ofertas.com
  guardian analyze mercadolibre-descuentos.com --json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		rawURL := args[0]
		sbKey := viper.GetString("GOOGLE_SAFE_BROWSING_KEY")
		vtKey := viper.GetString("VIRUSTOTAL_KEY")

		fmt.Printf("  Analizando %s...\n", rawURL)

		result, err := urlanalyzer.Analyze(rawURL, sbKey, vtKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		report.PrintURL(result, jsonOutput)
	},
}

func init() {
	analyzeCmd.Flags().BoolVar(&jsonOutput, "json", false, "output en formato JSON")
	rootCmd.AddCommand(analyzeCmd)
}
