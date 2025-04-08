/**
 * Port Scanner - A simple network port scanner
 * config.c - Configuration settings implementation
 *
 * This file implements configuration variables and settings.
 */

#include "../include/config.h"
#include <stdbool.h>

// List of common ports to scan by default
// These are some of the most commonly used ports for various services
const int COMMON_PORTS_TO_SCAN[MAX_COMMON_PORTS] = {
    20,    // FTP data
    21,    // FTP control
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    115,   // SFTP
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    194,   // IRC
    443,   // HTTPS
    445,   // SMB
    465,   // SMTPS
    587,   // SMTP (submission)
    993,   // IMAPS
    995,   // POP3S
    1080,  // SOCKS Proxy
    1194,  // OpenVPN
    1433,  // MS SQL
    1434,  // MS SQL Monitor
    1521,  // Oracle DB
    1723,  // PPTP
    3306,  // MySQL
    3389,  // RDP
    5060,  // SIP
    5222,  // XMPP
    5432,  // PostgreSQL
    5900,  // VNC
    5938,  // TeamViewer
    6379,  // Redis
    8000,  // Alternative HTTP
    8080,  // Alternative HTTP/Proxy
    8443,  // Alternative HTTPS
    8888,  // Alternative HTTP
    9000,  // SonarQube
    9090,  // WebSphere Admin
    9200,  // Elasticsearch
    9418,  // Git
    27017, // MongoDB
    27018, // MongoDB Shard
    27019, // MongoDB Config
    28017, // MongoDB Web
    33060, // MySQL X Protocol
    49152, // Windows RPC
    50000, // SAP
    51413  // BitTorrent
};

// Common ports to scan
const int COMMON_PORTS[COMMON_PORTS_COUNT] = {
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    25,   // SMTP
    53,   // DNS
    80,   // HTTP
    110,  // POP3
    143,  // IMAP
    443,  // HTTPS
    445,  // SMB
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    5900, // VNC
    8080, // HTTP Proxy
    8443  // HTTPS Alt
};

// Global configuration variables
bool use_common_ports = true; // Default to scanning common ports