#define DEBUG 2

#define MAX_PORT 65535
#define MAC_LEN 6
#define IP_LEN 4

#define MAX_THREADS 16

const int COMMON_PORTS_TCP[] = {
    20,         // FTP
    21,         // FTP
    22,         // SSH
    23,         // TELNET
    25,         // SMTP
    42,         // WINS
    43,         // WHOIS
    49,         // TACACS
    53,         // DNS
    69,         // TFTP
    70,         // GOPHER
    79,         // FINGER
    80,         // HTTP
    88,         // KERBEROS
    102,        // TSAP
    110,        // POP3
    113,        // IDENT
    119,        // NNTP (Usenet)
    123,        // NTP
    135,        // Ms RPC EPMAP
    137,        // NETBIOS NS
    138,        // NETBIOS (Datagram service)
    139,        // NETBIOS (Session service)
    143,        // IMAP
    161,        // SNMP
    179,        // Border Gateway Protocol
    194,        // IRC
    201,        // AppleTalk
    264,        // Border Gateway Multicast Protocol
    389,        // LDAP
    443,        // HTTPS
    445,        // SMB
    554,        // RTSP
    993,        // IMAPS
    995,        // POP3S
    1025,       // MS RPC
    1080,       // SOCKS
    1720,       // H.323
    2082,       // CPANEL
    3128,       // HTTP PROXY
    3306,       // MYSQL
    3389,       // RDP
    5060,       // SIP
    5061,       // SIP over TLS
    5432,       // POSTGRESQL
    6379,       // REDIS
    6970,       // QUICKTIME STREAMING SERVER
    8000,       // INTERNET RADIO
    8080,       // HTTP PROXY
    8200,       // VMWARE SERVER
    8222,       // VMWARE SERVER
    9092,       // KAFKA
    19226,      // ADMINSECURE
    27017       // MONGODB
}