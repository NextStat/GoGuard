package main

import (
	"os"
	"os/exec"
)

func main() {
	input := os.Getenv("USER_CMD")
	exec.Command(input).Run()
}
