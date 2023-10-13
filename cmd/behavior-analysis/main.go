package main

import (
    "fmt"
    "io"
    "os"
    "os/exec"
    "bytes"
    "net/http"
)

var apiKey string
var filePath string

func main() {
    // Chiedi all'utente di inserire la sua API key
    fmt.Print("Inserisci la tua API key di VirusTotal: ")
    _, err := fmt.Scan(&apiKey)
    if err != nil {
        fmt.Println("Errore durante la lettura dell'API key:", err)
        return
    }

    // Chiedi all'utente di inserire il percorso del file da analizzare
    fmt.Print("Inserisci il percorso del file da analizzare: ")
    _, err = fmt.Scan(&filePath)
    if err != nil {
        fmt.Println("Errore durante la lettura del percorso del file:", err)
        return
    }

    // Effettua la scansione del file con VirusTotal
    virusTotalReport, err := scanFileWithVirusTotal(filePath)
    if err != nil {
        fmt.Println("Errore nella scansione del file con VirusTotal:", err)
        return
    }

    // Verifica la firma del file
    signatureResult, err := analyzeFileSignature(filePath)
    if err != nil {
        fmt.Println("Errore durante l'analisi della firma del file:", err)
        return
    }

    fmt.Println("Report di scansione di VirusTotal:")
    fmt.Println(virusTotalReport)
    fmt.Println("Risultato dell'analisi della firma del file:")
    fmt.Println(signatureResult)
}

func scanFileWithVirusTotal(filePath string) (string, error) {
    url := "https://www.virustotal.com/vtapi/v2/file/scan"

    file, err := os.Open(filePath)
    if err != nil {
        return "", err
    }
    defer file.Close()

    fileContents, err := io.ReadAll(file)
    if err != nil {
        return "", err
    }

    body := bytes.NewBuffer(fileContents)
    req, err := http.NewRequest("POST", url, body)
    if err != nil {
        return "", err
    }

    req.Header.Set("x-apikey", apiKey)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    responseContents, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    return string(responseContents), nil
}

func analyzeFileSignature(filePath string) (string, error) {
    cmd := exec.Command("sigcheck", "-q", "-e", filePath)

    output, err := cmd.Output()
    if err != nil {
        return "", err
    }

    result := string(output)

    return result, nil
}
