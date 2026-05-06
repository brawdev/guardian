package sellerscraper

import "fmt"

type UnsupportedPlatformError struct {
	Platform string
}

func (e UnsupportedPlatformError) Error() string {
	return fmt.Sprintf("plataforma no soportada: '%s' — usa mercadolibre, amazon o aliexpress", e.Platform)
}

func ErrUnsupportedPlatform(platform string) error {
	return UnsupportedPlatformError{Platform: platform}
}
