package goauth

import "embed"

//go:embed assets/templates/*
var templateFS embed.FS

func GetTemplate(name string) ([]byte, error) {
	return templateFS.ReadFile("assets/templates/" + name)
}
