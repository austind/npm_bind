# dnspython module examples:
# http://www.dnspython.org/examples.html

# Prep below adapted from these guides:
# * http://www.freebsdwiki.net/index.php/BIND%2C_dynamic_DNS
# * https://www.erianna.com/nsupdate-dynamic-dns-updates-with-bind9

# 1. Create seed zone file
# In our case, on CentOS6, the file needs to live in /var/named/dynamic/
# because this directory is owned by the named user. By default, SELinux
# prevents the named user from writing to /var/named/, but allows
# /var/named/dynamic/.

# Example zone file /var/named/dynamic/example.net.zone:
# $TTL 2  ; 2 seconds
# example.net.    IN SOA  ns1.example.com. postmaster.example.com. (
#                                 2017010101 ; serial
#                                 28800      ; refresh (8 hours)
#                                 1800       ; retry (30 minutes)
#                                 604800     ; expire (1 week)
#                                 86400      ; minimum (1 day)
#                                 )
#                         NS      ns1.example.com.
#                         NS      ns2.example.com.

# 2. Create DNSSEC keys
# mkdir /var/named/keys && cd /var/named/keys
# dnssec-keygen -a HMAC-SHA256 -b 128 -n HOST example.net.

# 3. Copy base64 key to our script
# cat /var/named/keys/Kexample.net.+127+25432.key
# example.net. IN KEY 512 3 157 z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==

# 4. Verify time/NTP is correct on both local server running this script,
# and remote DNS server(s), or TSIG will throw an error

import dns.query
import dns.tsigkeyring
import dns.update

keyring = dns.tsigkeyring.from_text({
    'example.net.': 'uex007clg4aZngiJLBYdVg=='
})

update = dns.update.Update("example.net.", keyring=keyring, keyalgorithm="hmac-sha256")
update.replace('test', 300, 'A', '127.3.3.7')

response = dns.query.tcp(update, 'ns1.exmaple.com')
print(response)
