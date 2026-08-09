# DNS_Analysis

## parse OPNsense dns log and extract the domain
usage:

./domain_count.sh -i resolver_20260728.log -o  domain_count.txt


## check any dns matched the blacklist 

./domain_blacklist_check.sh -i dns_domain_count.txt -b blacklist.txt
