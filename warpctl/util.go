package main

import (
	"os/exec"
	"template"
)


func sudo(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}


func docker(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, "docker")
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}


func templateString(text string, data map[string]interface{}...) string {
	t, err := template.New("").Parse(text)
	if err != nil {
		panic(err)
	}
	mergedData := map[string]interface{}{}
	for _, d := range data {
		for key, value := range d {
			mergedData[key] = value
		}
	}
	out := &bytes.Buffer{}
	t.Execute(out, mergedData)
	return out.String()
}

