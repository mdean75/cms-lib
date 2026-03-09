module github.com/mdean75/cms-lib/cmd

go 1.24

require (
	github.com/mdean75/cms-lib v0.0.0
	github.com/smimesign/ietf-cms v0.0.0-20250713083702-7d76bb44b048
	go.mozilla.org/pkcs7 v0.9.0
)

require github.com/github/smimesign v0.2.0 // indirect

replace github.com/mdean75/cms-lib => ../
