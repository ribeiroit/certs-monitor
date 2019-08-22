Certificates monitor
====================

Setup
-----
	# download dependencies
  	go mod tidy

  	# build the project
  	go build -v

Run
---

  	# create a new file named urls.txt and populate it with the all urls
  	echo "url1.com\nurl2.com" > urls.txt

	# run the scanner
	./scan
