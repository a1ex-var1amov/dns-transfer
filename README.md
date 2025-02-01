# dns-transfer

# Start server
sudo ./bin/server -fqdn test.local. -debug

# Send files
./bin/client -fqdn test.local -file test.txt -debug
