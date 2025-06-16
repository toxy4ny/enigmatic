# enigmatic
ENIGMATIC - a WAF IP Encoder - Tool for bypassing WAF IP validation.

# Features of the tool
✅ Advantages
Full automation - works as a wrapper for any
13 encoding tools, including Unicode variants
Intelligent IP detection in commands
Detailed logging of results
Flexible configuration of methods and parameters

# 🔧 Extensions
IPv6 address support
Integration with Burp Suite via API
Automatic detection of successful crawls by HTTP statuses
Support for domain names and their encoding

# pip install requests pyyaml dnspython

# Basic usage
./enigmatic.py -- nmap -Ss 192.168.1.1.


# Using specific methods

./enigmatic.py -m single_decimal,full_hex -- curl http://10.0.0.1


# Detailed mode with delay

./enigmatic.py -v -d 2.5 -- sqlmap -u "http://192.168.1.100/test.php"


# List of all methods

./enigmatic.py --list of methods


# End-IP testing

./enigmatic.py --test-ip 8.8.8.8


# Saving the results

./enigmatic.py -o results.json map 10.10.10.10
