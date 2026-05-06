package cmd

import (
	"fmt"
	"os"

	"github.com/brawdev/guardian/internal/sellerscraper"
	"github.com/spf13/cobra"
)

var sellerPlatform string

var sellerCmd = &cobra.Command{
	Use:   "verify-seller <url-o-username>",
	Short: "Verifica el perfil de un vendedor/comprador en marketplaces",
	Example: `  guardian verify-seller https://www.mercadolibre.com.mx/perfil/VENDEDOR123
  guardian verify-seller VENDEDOR123 --platform mercadolibre
  guardian verify-seller https://www.amazon.com.mx/sp?seller=ABC123`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]

		fmt.Printf("  Verificando perfil: %s...\n", input)

		result, err := sellerscraper.Analyze(input, sellerPlatform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// TODO: implementar report.PrintSeller(result, jsonOutput)
		_ = result
	},
}

func init() {
	sellerCmd.Flags().StringVar(&sellerPlatform, "platform", "", "plataforma: mercadolibre, amazon, aliexpress")
	rootCmd.AddCommand(sellerCmd)
}
