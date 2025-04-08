#ifndef SERVICE_DETECTION_H
#define SERVICE_DETECTION_H

#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

// Service information structure
typedef struct
{
  int port;              // Port number
  char protocol[32];     // Protocol name (e.g., "HTTP", "FTP")
  char service_name[64]; // Service name (e.g., "Web Server", "File Server")
  char version[32];      // Service version
  char banner[1024];     // Service banner
} ServiceInfo;

// Function declarations
const char *get_service_name(int port);
const char *get_service_description(int port);
bool grab_banner(const char *target, int port, char *banner, size_t banner_size);
bool detect_service_version(const char *target, int port, char *version, size_t version_size);

// Main service detection function
bool detect_service(const char *host, int port, ServiceInfo *service_info);

// Service-specific detection functions
bool detect_http(const char *target, int port, ServiceInfo *service_info);
bool detect_ftp(const char *target, int port, ServiceInfo *service_info);
bool detect_smtp(const char *target, int port, ServiceInfo *service_info);
bool detect_ssh(const char *target, int port, ServiceInfo *service_info);
bool detect_telnet(const char *target, int port, ServiceInfo *service_info);

// Helper function to identify service from banner
void identify_service(ServiceInfo *service_info);

#endif /* SERVICE_DETECTION_H */