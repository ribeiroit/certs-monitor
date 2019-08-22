package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Configuration struct {
	LogFile        string
	LogPath        string
	UrlFile        string
	UrlConcurrency int
}

type result struct {
	index int
	url   string
	res   string
	err   error
}

func loadUrl(config *Configuration) ([]string, error) {
	file, err := os.Open(config.UrlFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func getCertDate(url string) (string, error) {
	urlPort := url
	if !strings.Contains(url, ":") {
		urlPort += ":443"
	}

	conn, err := net.Dial("tcp", urlPort)
	if err != nil {
		log.Warn(err)
		return "Was not possible to connect on url", err
	}

	client := tls.Client(conn, &tls.Config{
		ServerName: url,
	})
	defer client.Close()

	if err := client.Handshake(); err != nil {
		log.Warn(err)
		return "Server coudnt execute the handshake", err
	}

	cert := client.ConnectionState().PeerCertificates[0]
	return cert.NotAfter.Format(time.RFC3339), nil
}

func reqParallel(urls []string, concurrent int) []result {
	poolingChan := make(chan struct{}, concurrent)
	resultChan := make(chan *result)

	defer func() {
		close(poolingChan)
		close(resultChan)
	}()

	for i, url := range urls {
		go func(i int, url string) {
			poolingChan <- struct{}{}

			res, err := getCertDate(url)
			result := &result{i, url, res, err}

			resultChan <- result

			<-poolingChan
		}(i, url)
	}

	var results []result

	for {
		result := <-resultChan
		results = append(results, *result)

		if len(results) == len(urls) {
			break
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].index < results[j].index
	})

	return results
}

func main() {
	var config Configuration
	viper.SetConfigName("config")
	viper.SetConfigType("toml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("LogPath", "/var/log/certs-monitor/")
	viper.SetDefault("LogFile", "scan.log")
	viper.SetDefault("UrlConcurrency", 2)
	viper.SetDefault("UrlFile", "urls.txt")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
	}

	var results []result
	urls, _ := loadUrl(&config)

	if _, err := os.Stat(config.LogPath); os.IsNotExist(err) {
		if err := os.Mkdir(config.LogPath, 0644); err != nil {
			panic(fmt.Errorf("Was not possible to create the log path dir: %s\n", config.LogPath))
		}
	}

	f, err := os.OpenFile(fmt.Sprintf("%s/%s", config.LogPath, config.LogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
	if err != nil {
		panic(fmt.Errorf("Was not possible to create the scan log file: %s/%s", config.LogPath, config.LogFile))
	}

	logrus.SetOutput(f)

	results = reqParallel(urls, config.UrlConcurrency)
	scanDate := time.Now()

	for i := range results {
		if results[i].err != nil {
			log.Printf("[%d] URL: %s FAIL", results[i].index, results[i].url)
		} else {
			cert_date, err := time.Parse(time.RFC3339, results[i].res)
			if err != nil {
				log.Printf("[%d] [URL: %s] [DAYS_TO_EXPIRE: -] [DATE: %s]", results[i].index, results[i].url, results[i].res)
			} else {
				days_expire := cert_date.Sub(scanDate).Hours() / 24
				log.Printf("[%d] [URL: %s] [DAYS_TO_EXPIRE: %.0f] [DATE: %s]", results[i].index, results[i].url, days_expire, results[i].res)
			}
		}
	}
}
