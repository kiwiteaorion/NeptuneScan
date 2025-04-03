#include "../include/service_detection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#endif

// Service information structure
typedef struct
{
  int port;
  const char *name;
  const char *description;
} ServiceInfo;

// Common services database
static const ServiceInfo common_services[] = {
    {21, "ftp", "File Transfer Protocol"},
    {22, "ssh", "Secure Shell"},
    {23, "telnet", "Telnet"},
    {25, "smtp", "Simple Mail Transfer Protocol"},
    {53, "dns", "Domain Name System"},
    {80, "http", "Hypertext Transfer Protocol"},
    {110, "pop3", "Post Office Protocol 3"},
    {143, "imap", "Internet Message Access Protocol"},
    {443, "https", "HTTP Secure"},
    {445, "smb", "Server Message Block"},
    {993, "imaps", "IMAP Secure"},
    {995, "pop3s", "POP3 Secure"},
    {3306, "mysql", "MySQL Database"},
    {3389, "rdp", "Remote Desktop Protocol"},
    {5432, "postgresql", "PostgreSQL Database"},
    {8080, "http-proxy", "HTTP Proxy"},
    {0, NULL, NULL} // End marker
};

// Function to get service name for a port
const char *get_service_name(int port)
{
  for (const ServiceInfo *service = common_services; service->port != 0; service++)
  {
    if (service->port == port)
    {
      return service->name;
    }
  }
  return "unknown";
}

// Function to get service description for a port
const char *get_service_description(int port)
{
  for (const ServiceInfo *service = common_services; service->port != 0; service++)
  {
    if (service->port == port)
    {
      return service->description;
    }
  }
  return "Unknown service";
}

// Function to perform banner grabbing
bool grab_banner(const char *target, int port, char *banner, size_t banner_size)
{
  // Implementation would go here
  // This is a placeholder
  return false;
}

// Function to detect service version
bool detect_service_version(const char *target, int port, char *version, size_t version_size)
{
  // Implementation would go here
  // This is a placeholder
  return false;
}

bool detect_service(const char *host, int port, ServiceInfo *service_info)
{
  if (!service_info)
    return false;

  // Initialize service info
  memset(service_info, 0, sizeof(ServiceInfo));
  service_info->port = port;

  // Try to grab banner first
  if (grab_banner(host, port, service_info->banner, sizeof(service_info->banner)))
  {
    identify_service(service_info);
    return true;
  }

  // If banner grabbing failed, try specific protocol detection
  if (port == 80 || port == 443)
  {
    return detect_http(host, port, service_info);
  }
  else if (port == 21)
  {
    return detect_ftp(host, port, service_info);
  }
  else if (port == 22)
  {
    return detect_ssh(host, port, service_info);
  }
  else if (port == 25)
  {
    return detect_smtp(host, port, service_info);
  }

  // If all else fails, try to identify by port number
  for (int i = 0; common_services[i].service != NULL; i++)
  {
    if (common_services[i].port == port)
    {
      strncpy(service_info->service_name, common_services[i].service,
              sizeof(service_info->service_name) - 1);
      return true;
    }
  }

  return false;
}

bool detect_http(const char *host, int port, ServiceInfo *service_info)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return false;
#else
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;
#endif

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(host);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sock);
    return false;
  }

  const char *request = "HEAD / HTTP/1.0\r\n\r\n";
#ifdef _WIN32
  send(sock, request, (int)strlen(request), 0);
#else
  send(sock, request, strlen(request), 0);
#endif

  char response[1024];
#ifdef _WIN32
  int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#else
  ssize_t bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#endif
  close(sock);

  if (bytes_read > 0)
  {
    response[bytes_read] = '\0';
    strcpy(service_info->protocol, "HTTP");
    strcpy(service_info->service_name, "Web Server");
    strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
    return true;
  }

  return false;
}

bool detect_ftp(const char *host, int port, ServiceInfo *service_info)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return false;
#else
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;
#endif

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(host);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sock);
    return false;
  }

  char response[1024];
#ifdef _WIN32
  int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#else
  ssize_t bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#endif
  close(sock);

  if (bytes_read > 0)
  {
    response[bytes_read] = '\0';
    strcpy(service_info->protocol, "FTP");
    strcpy(service_info->service_name, "FTP Server");
    strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
    return true;
  }

  return false;
}

bool detect_ssh(const char *host, int port, ServiceInfo *service_info)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return false;
#else
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;
#endif

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(host);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sock);
    return false;
  }

  char response[1024];
#ifdef _WIN32
  int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#else
  ssize_t bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#endif
  close(sock);

  if (bytes_read > 0)
  {
    response[bytes_read] = '\0';
    strcpy(service_info->protocol, "SSH");
    strcpy(service_info->service_name, "SSH Server");
    strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
    return true;
  }

  return false;
}

bool detect_smtp(const char *host, int port, ServiceInfo *service_info)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return false;
#else
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;
#endif

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(host);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sock);
    return false;
  }

  char response[1024];
#ifdef _WIN32
  int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#else
  ssize_t bytes_read = recv(sock, response, sizeof(response) - 1, 0);
#endif
  close(sock);

  if (bytes_read > 0)
  {
    response[bytes_read] = '\0';
    strcpy(service_info->protocol, "SMTP");
    strcpy(service_info->service_name, "Mail Server");
    strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
    return true;
  }

  return false;
}

void identify_service(ServiceInfo *service_info)
{
  if (!service_info)
    return;

  // Check for HTTP/HTTPS
  if (strstr(service_info->banner, "HTTP") != NULL)
  {
    strcpy(service_info->protocol, "HTTP");
    strcpy(service_info->service_name, "Web Server");

    // Try to extract version
    char *version = strstr(service_info->banner, "Server:");
    if (version)
    {
      version += 7; // Skip "Server:"
      while (*version == ' ')
        version++;
      char *end = strchr(version, '\r');
      if (end)
      {
        *end = '\0';
        strncpy(service_info->version, version, sizeof(service_info->version) - 1);
      }
    }
  }
  // Add more service identification patterns here
}
response[bytes_read] = '\0';
strcpy(service_info->protocol, "SMTP");
strcpy(service_info->service_name, "Mail Server");
strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
return true;
}

return false;
}