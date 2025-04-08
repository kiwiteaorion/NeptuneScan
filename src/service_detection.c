#include "../include/service_detection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

// Common service entry structure (for internal database only)
typedef struct
{
  int port;
  const char *name;
  const char *description;
} CommonServiceEntry;

// Common services database
static const CommonServiceEntry common_services[] = {
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

// Function to get service name for a port (local version)
static const char *get_service_name_local(int port)
{
    int i = 0;
    while (common_services[i].port != 0) {
        if (common_services[i].port == port) {
            return common_services[i].name;
        }
        i++;
    }
    return NULL;
}

/**
 * Attempts to grab a banner from a service running on the specified port
 * 
 * @param target The target host address
 * @param port The port to connect to
 * @param banner Buffer to store the banner
 * @param banner_size Size of the banner buffer
 * @return true if a banner was successfully grabbed, false otherwise
 */
bool grab_banner(const char *target, int port, char *banner, size_t banner_size)
{
    SOCKET sock;
    struct sockaddr_in server_addr;
    int result;
    fd_set read_fds;
    struct timeval timeout;

    // Initialize Winsock if not already done
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    // Set non-blocking mode
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    
    // Try to resolve hostname if it's not an IP address
    struct hostent *he = gethostbyname(target);
    if (he != NULL) {
        memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        server_addr.sin_addr.s_addr = inet_addr(target);
    }
    
    server_addr.sin_port = htons((unsigned short)port);

    // Connect to server
    result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (result == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(sock);
            WSACleanup();
            return false;
        }
    }

    // Set timeout for select operation
    timeout.tv_sec = 3;  // 3 seconds timeout
    timeout.tv_usec = 0;

    // Wait for connection to complete
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);
    fd_set except_fds;
    FD_ZERO(&except_fds);
    FD_SET(sock, &except_fds);
    
    result = select(0, &read_fds, &write_fds, &except_fds, &timeout);
    if (result <= 0 || FD_ISSET(sock, &except_fds)) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // Clear any non-blocking mode
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    // Wait for data
    memset(banner, 0, banner_size);
    timeout.tv_sec = 2;  // 2 seconds timeout
    timeout.tv_usec = 0;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    result = select(0, &read_fds, NULL, NULL, &timeout);
    
    if (result <= 0) {
        // Some services don't send a banner unprompted
        // Send service-specific probes
        if (port == 80 || port == 443 || port == 8080) {
            // HTTP request
            const char *request = "HEAD / HTTP/1.1\r\nHost: ";
            send(sock, request, strlen(request), 0);
            send(sock, target, strlen(target), 0);
            const char *request_tail = "\r\nUser-Agent: NeptuneScanner/3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            send(sock, request_tail, strlen(request_tail), 0);
        } else if (port == 21) {
            // FTP - typically sends a banner unprompted
            // But we might send a HELP command to get more info
            const char *request = "HELP\r\n";
            send(sock, request, strlen(request), 0);
        } else if (port == 25 || port == 587) {
            // SMTP
            const char *request = "EHLO neptunescanner.local\r\n";
            send(sock, request, strlen(request), 0);
        } else if (port == 110) {
            // POP3
            const char *request = "CAPA\r\n";
            send(sock, request, strlen(request), 0);
        } else if (port == 143) {
            // IMAP
            const char *request = "a001 CAPABILITY\r\n";
            send(sock, request, strlen(request), 0);
        } else if (port == 23) {
            // Telnet - might not send banner initially
            // Send a return to trigger a prompt
            const char *request = "\r\n";
            send(sock, request, strlen(request), 0);
        } else if (port == 22) {
            // SSH typically sends a banner without prompting
        } else {
            // Generic probe - just send a newline
            const char *request = "\r\n";
            send(sock, request, strlen(request), 0);
        }

        // Wait again for data after probe
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        result = select(0, &read_fds, NULL, NULL, &timeout);
        if (result <= 0) {
            closesocket(sock);
            WSACleanup();
            return false;
        }
    }

    // Receive data
    result = recv(sock, banner, (int)banner_size - 1, 0);
    if (result > 0) {
        banner[result] = '\0';  // Null terminate
        closesocket(sock);
        WSACleanup();
        return true;
    }

    closesocket(sock);
    WSACleanup();
    return false;
}

/**
 * Attempts to detect the version of a service
 * 
 * @param target The target host address
 * @param port The port to connect to
 * @param version Buffer to store the version string
 * @param version_size Size of the version buffer
 * @return true if a version was successfully detected, false otherwise
 */
bool detect_service_version(const char *target, int port, char *version, size_t version_size)
{
    char banner[1024] = {0};
    
    // Try to grab a banner from the service
    if (!grab_banner(target, port, banner, sizeof(banner))) {
        return false;
    }
    
    // Extract version information from the banner
    // This is service-specific, so we'll need to handle different services
    if (port == 22 && strstr(banner, "SSH")) {
        // SSH banner format is typically: SSH-2.0-OpenSSH_8.1p1
        char *version_start = strstr(banner, "SSH-");
        if (version_start) {
            // Skip the SSH-2.0- part
            version_start = strchr(version_start + 4, '-');
            if (version_start) {
                version_start++; // Skip the dash
                int i = 0;
                while (version_start[i] && version_start[i] != '\r' && version_start[i] != '\n' && 
                      i < (int)version_size - 1) {
                    version[i] = version_start[i];
                    i++;
                }
                version[i] = '\0';
                return true;
            }
        }
    } else if ((port == 80 || port == 443) && strstr(banner, "Server:")) {
        // HTTP server version is typically in a Server: header
        char *version_start = strstr(banner, "Server:");
        if (version_start) {
            version_start += 7; // Skip "Server:"
            // Skip whitespace
            while (*version_start && isspace((unsigned char)*version_start)) {
                version_start++;
            }
            int i = 0;
            while (version_start[i] && version_start[i] != '\r' && version_start[i] != '\n' && 
                  i < (int)version_size - 1) {
                version[i] = version_start[i];
                i++;
            }
            version[i] = '\0';
            return true;
        }
    } else if (port == 21 && (strstr(banner, "FTP") || strstr(banner, "220"))) {
        // FTP banner typically starts with 220 and may contain version info
        char *version_start = banner;
        if (strncmp(version_start, "220", 3) == 0) {
            version_start += 3;
            while (*version_start && isspace((unsigned char)*version_start)) {
                version_start++;
            }
            int i = 0;
            while (version_start[i] && version_start[i] != '\r' && version_start[i] != '\n' && 
                  i < (int)version_size - 1) {
                version[i] = version_start[i];
                i++;
            }
            version[i] = '\0';
            return true;
        }
    } else if ((port == 25 || port == 587) && (strstr(banner, "SMTP") || strstr(banner, "220"))) {
        // SMTP banner typically starts with 220 and may contain version info
        char *version_start = banner;
        if (strncmp(version_start, "220", 3) == 0) {
            version_start += 3;
            while (*version_start && isspace((unsigned char)*version_start)) {
                version_start++;
            }
            int i = 0;
            while (version_start[i] && version_start[i] != '\r' && version_start[i] != '\n' && 
                  i < (int)version_size - 1) {
                version[i] = version_start[i];
                i++;
            }
            version[i] = '\0';
            return true;
        }
    }
    
    // If we couldn't parse a specific format, just copy the first line of the banner
    int i = 0;
    while (banner[i] && banner[i] != '\r' && banner[i] != '\n' && i < (int)version_size - 1) {
        version[i] = banner[i];
        i++;
    }
    version[i] = '\0';
    
    return i > 0;  // Return true if we got something
}

/**
 * Main service detection function - tries to identify service on the given port
 * 
 * @param host The target host
 * @param port The port to check
 * @param service_info Pointer to service info structure to fill
 * @return true if service was detected, false otherwise
 */
bool detect_service(const char *host, int port, ServiceInfo *service_info)
{
  // Initialize service info
  memset(service_info, 0, sizeof(ServiceInfo));
  service_info->port = port;
  
  // Try to grab the banner
  bool banner_grabbed = grab_banner(host, port, service_info->banner, sizeof(service_info->banner));
  
  if (banner_grabbed)
  {
    // Banner was grabbed, identify service from it
    identify_service(service_info);
  }
  
  // Try protocol-specific detection based on port
  bool detected = false;
  
  if (port == 80 || port == 443 || port == 8080)
  {
    detected = detect_http(host, port, service_info);
  }
  else if (port == 21)
  {
    detected = detect_ftp(host, port, service_info);
  }
  else if (port == 22)
  {
    detected = detect_ssh(host, port, service_info);
  }
  else if (port == 23)
  {
    // Inline implementation of Telnet detection
    #ifdef _WIN32
      SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (sock != INVALID_SOCKET)
    #else
      int sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock >= 0)
    #endif
    {
      struct sockaddr_in addr;
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      addr.sin_addr.s_addr = inet_addr(host);

      if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) >= 0)
      {
        // Set receive timeout
        struct timeval tv;
        tv.tv_sec = 3;  // 3 seconds
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

        char response[1024];
        #ifdef _WIN32
          int bytes_read = recv(sock, response, sizeof(response) - 1, 0);
        #else
          ssize_t bytes_read = recv(sock, response, sizeof(response) - 1, 0);
        #endif
        
        if (bytes_read > 0)
        {
          response[bytes_read] = '\0';
          strncpy(service_info->protocol, "TELNET", sizeof(service_info->protocol) - 1);
          service_info->protocol[sizeof(service_info->protocol) - 1] = '\0';
          
          strncpy(service_info->service_name, "Telnet", sizeof(service_info->service_name) - 1);
          service_info->service_name[sizeof(service_info->service_name) - 1] = '\0';
          
          strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
          service_info->banner[sizeof(service_info->banner) - 1] = '\0';
          detected = true;
        }
      }
      close(sock);
    }
  }
  else if (port == 25 || port == 587)
  {
    detected = detect_smtp(host, port, service_info);
  }
  
  // If all else fails, try to identify by port number
  if (!detected && service_info->service_name[0] == '\0')
  {
    for (int i = 0; common_services[i].port != 0; i++)
    {
      if (common_services[i].port == port)
      {
        strncpy(service_info->service_name, common_services[i].name, sizeof(service_info->service_name) - 1);
        strncpy(service_info->protocol, "tcp", sizeof(service_info->protocol) - 1);
        detected = true;
        break;
      }
    }
  }
  
  // Default values if nothing else worked
  if (!detected && service_info->service_name[0] == '\0')
  {
    const char *name = get_service_name_local(port);
    strncpy(service_info->service_name, name ? name : "unknown", sizeof(service_info->service_name) - 1);
    strncpy(service_info->protocol, "tcp", sizeof(service_info->protocol) - 1);
  }
  
  return detected;
}

bool detect_http(const char *host, int port, ServiceInfo *service_info)
{
#ifdef _WIN32
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
#ifdef _DEBUG
    printf("Socket creation failed, error code: %d\n", WSAGetLastError());
#endif
    return false;
  }
#else
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
#ifdef _DEBUG
    printf("Socket creation failed\n");
#endif
    return false;
  }
#endif

  struct sockaddr_in addr;
  struct hostent *he;
  
  // First try to resolve the hostname in case it's not an IP address
  if ((he = gethostbyname(host)) != NULL) {
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
  } else {
    // Fall back to treating as IP address if hostname resolution fails
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
  }

  // Set a timeout for connection
  struct timeval tv;
  tv.tv_sec = 5;  // 5 seconds connection timeout
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
#ifdef _WIN32
#ifdef _DEBUG
    printf("Connection failed, error code: %d\n", WSAGetLastError());
#endif
#endif
    close(sock);
    return false;
  }

  // Use a more complete HTTP request with Host header to work better with virtual hosts
  char request[256];
  snprintf(request, sizeof(request), 
           "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: NeptuneScanner/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", 
           host);

#ifdef _WIN32
  int sent = send(sock, request, (int)strlen(request), 0);
  if (sent <= 0) {
#ifdef _DEBUG
    printf("Failed to send request, error code: %d\n", WSAGetLastError());
#endif
    close(sock);
    return false;
  }
#else
  int sent = send(sock, request, strlen(request), 0);
  if (sent <= 0) {
#ifdef _DEBUG
    printf("Failed to send request\n");
#endif
    close(sock);
    return false;
  }
#endif

  char response[4096];  // Larger buffer for bigger responses
  int total_bytes = 0;
  int bytes_read;
  
  // Set a timeout for recv
  tv.tv_sec = 3;  // 3 seconds timeout
  tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
  
  // Read response in chunks
  while ((size_t)total_bytes < sizeof(response) - 1) {
#ifdef _WIN32
    bytes_read = recv(sock, response + total_bytes, sizeof(response) - 1 - total_bytes, 0);
    if (bytes_read <= 0) {
      break;  // No more data or error
    }
#else
    bytes_read = recv(sock, response + total_bytes, sizeof(response) - 1 - total_bytes, 0);
    if (bytes_read <= 0) {
      break;  // No more data or error
    }
#endif
    total_bytes += bytes_read;
  }
  
  close(sock);

  if (total_bytes > 0)
  {
    response[total_bytes] = '\0';
    
    // Set basic HTTP protocol
    strncpy(service_info->protocol, "HTTP", sizeof(service_info->protocol) - 1);
    service_info->protocol[sizeof(service_info->protocol) - 1] = '\0';
    
    strncpy(service_info->service_name, "Web Server", sizeof(service_info->service_name) - 1);
    service_info->service_name[sizeof(service_info->service_name) - 1] = '\0';
    
    // Extract HTTP version from response
    if (strncmp(response, "HTTP/", 5) == 0) {
      char http_version[16] = {0};
      int i = 5;
      int j = 0;
      while (response[i] && response[i] != ' ' && j < 15) {
        http_version[j++] = response[i++];
      }
      if (j > 0) {
        strncpy(service_info->version, http_version, sizeof(service_info->version) - 1);
        service_info->version[sizeof(service_info->version) - 1] = '\0';
      }
    }
    
    // Look for Server header
    const char *server_header = strstr(response, "\r\nServer:");
    if (server_header) {
      server_header += 9;  // Skip "\r\nServer:"
      
      // Skip whitespace
      while (*server_header && isspace((unsigned char)*server_header)) {
        server_header++;
      }
      
      // Extract server info
      char server_info[128] = {0};
      int i = 0;
      while (server_header[i] && server_header[i] != '\r' && i < 127) {
        server_info[i] = server_header[i];
        i++;
      }
      
      if (i > 0) {
        // If we found a Server header, update both service_name and version
        char *version_start = NULL;
        
        // Try to identify common servers
        if (strstr(server_info, "Apache")) {
          strncpy(service_info->service_name, "Apache", sizeof(service_info->service_name) - 1);
          version_start = strstr(server_info, "Apache/");
          if (version_start) {
            version_start += 7;  // Skip "Apache/"
          }
        } else if (strstr(server_info, "nginx")) {
          strncpy(service_info->service_name, "nginx", sizeof(service_info->service_name) - 1);
          version_start = strstr(server_info, "nginx/");
          if (version_start) {
            version_start += 6;  // Skip "nginx/"
          }
        } else if (strstr(server_info, "Microsoft-IIS")) {
          strncpy(service_info->service_name, "IIS", sizeof(service_info->service_name) - 1);
          version_start = strstr(server_info, "Microsoft-IIS/");
          if (version_start) {
            version_start += 14;  // Skip "Microsoft-IIS/"
          }
        } else if (strstr(server_info, "gws")) {
          // Special case for Google Web Server
          strncpy(service_info->service_name, "Google Web Server", sizeof(service_info->service_name) - 1);
          strncpy(service_info->version, "gws", sizeof(service_info->version) - 1);
        } else {
          // For other servers, just use the whole Server string
          strncpy(service_info->service_name, server_info, sizeof(service_info->service_name) - 1);
        }
        
        // Extract version if found
        if (version_start) {
          char version_str[64] = {0};
          int j = 0;
          while (version_start[j] && version_start[j] != ' ' && version_start[j] != '\r' && j < 63) {
            version_str[j] = version_start[j];
            j++;
          }
          if (j > 0) {
            strncpy(service_info->version, version_str, sizeof(service_info->version) - 1);
            service_info->version[sizeof(service_info->version) - 1] = '\0';
          }
        }
      }
    }
    
    // If we don't have a version yet but we know it's a web server, try to determine type from response
    if (service_info->version[0] == '\0') {
      if (strstr(response, "X-Powered-By: PHP")) {
        strncpy(service_info->version, "PHP-powered", sizeof(service_info->version) - 1);
      } else if (strstr(response, "<title>Google</title>")) {
        strncpy(service_info->service_name, "Google Web Server", sizeof(service_info->service_name) - 1);
        strncpy(service_info->version, "gws", sizeof(service_info->version) - 1);
      } else if (strstr(response, "cloudflare")) {
        strncpy(service_info->service_name, "Cloudflare", sizeof(service_info->service_name) - 1);
      }
    }
    
    // Store a portion of the response as banner
    strncpy(service_info->banner, response, sizeof(service_info->banner) - 1);
    service_info->banner[sizeof(service_info->banner) - 1] = '\0';
    
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

// Helper function to identify service from banner
void identify_service(ServiceInfo *service_info)
{
    // Check if we have a banner to work with
    if (service_info == NULL || service_info->banner[0] == '\0') {
        return;
    }
    
    const char *banner = service_info->banner;
    
    // HTTP detection
    if (strstr(banner, "HTTP/") != NULL)
    {
        strncpy(service_info->protocol, "HTTP", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "http", sizeof(service_info->service_name) - 1);
        
        // Try to extract HTTP version
        const char *http_ver = strstr(banner, "HTTP/");
        if (http_ver) {
            char version[32] = {0};
            sscanf(http_ver, "HTTP/%31s", version);
            
            // Remove any spaces or newlines
            char *end = version;
            while (*end && *end != ' ' && *end != '\r' && *end != '\n')
                end++;
            *end = '\0';
            
            if (version[0]) {
                strncpy(service_info->version, version, sizeof(service_info->version) - 1);
            }
        }
        
        // Identify specific web server from Server header
        const char *server_header = strstr(banner, "\r\nServer:");
        if (server_header) {
            server_header += 9; // Skip "\r\nServer:"
            // Skip whitespace
            while (*server_header && isspace((unsigned char)*server_header))
                server_header++;
            
            char server_info[64] = {0};
            int i = 0;
            while (server_header[i] && server_header[i] != '\r' && i < 63) {
                server_info[i] = server_header[i];
                i++;
            }
            
            if (i > 0) {
                // Check for common web servers
                if (strstr(server_info, "Apache"))
                {
                    strncpy(service_info->service_name, "Apache httpd", sizeof(service_info->service_name) - 1);
                    // Try to extract version
                    const char *ver_start = strstr(server_info, "Apache/");
                    if (ver_start) {
                        ver_start += 7; // Skip "Apache/"
                        char version[32] = {0};
                        int j = 0;
                        while (ver_start[j] && ver_start[j] != ' ' && ver_start[j] != '(' && j < 31) {
                            version[j] = ver_start[j];
                            j++;
                        }
                        
                        if (j > 0) {
                            strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                        }
                    }
                }
                else if (strstr(server_info, "nginx"))
                {
                    strncpy(service_info->service_name, "nginx", sizeof(service_info->service_name) - 1);
                    // Try to extract version
                    const char *ver_start = strstr(server_info, "nginx/");
                    if (ver_start) {
                        ver_start += 6; // Skip "nginx/"
                        char version[32] = {0};
                        int j = 0;
                        while (ver_start[j] && ver_start[j] != ' ' && j < 31) {
                            version[j] = ver_start[j];
                            j++;
                        }
                        
                        if (j > 0) {
                            strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                        }
                    }
                }
                else if (strstr(server_info, "Microsoft-IIS"))
                {
                    strncpy(service_info->service_name, "Microsoft IIS httpd", sizeof(service_info->service_name) - 1);
                    // Try to extract version
                    const char *ver_start = strstr(server_info, "Microsoft-IIS/");
                    if (ver_start) {
                        ver_start += 14; // Skip "Microsoft-IIS/"
                        char version[32] = {0};
                        int j = 0;
                        while (ver_start[j] && ver_start[j] != ' ' && j < 31) {
                            version[j] = ver_start[j];
                            j++;
                        }
                        
                        if (j > 0) {
                            strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                        }
                    }
                }
                else if (strstr(server_info, "lighttpd"))
                {
                    strncpy(service_info->service_name, "lighttpd", sizeof(service_info->service_name) - 1);
                    // Try to extract version
                    const char *ver_start = strstr(server_info, "lighttpd/");
                    if (ver_start) {
                        ver_start += 9; // Skip "lighttpd/"
                        char version[32] = {0};
                        int j = 0;
                        while (ver_start[j] && ver_start[j] != ' ' && j < 31) {
                            version[j] = ver_start[j];
                            j++;
                        }
                        
                        if (j > 0) {
                            strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                        }
                    }
                }
                else
                {
                    // For other servers, just use the whole Server string
                    strncpy(service_info->service_name, server_info, sizeof(service_info->service_name) - 1);
                }
            }
        }
        
        return;
    }
    // SSH detection
    else if (strstr(banner, "SSH-"))
    {
        strncpy(service_info->protocol, "SSH", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "ssh", sizeof(service_info->service_name) - 1);
        
        // SSH banner format is typically: SSH-2.0-OpenSSH_8.1p1
        const char *ssh_banner = strstr(banner, "SSH-");
        if (ssh_banner) {
            char protocol_version[10] = {0};
            char software_version[64] = {0};
            
            // Parse protocol version (SSH-2.0)
            sscanf(ssh_banner, "SSH-%9[^-]-", protocol_version);
            
            // Parse software version (OpenSSH_8.1p1)
            const char *software = strchr(ssh_banner + 4, '-');
            if (software && *(software+1)) {
                software++; // Skip the dash
                
                int i = 0;
                while (software[i] && software[i] != '\r' && software[i] != '\n' && i < 63) {
                    software_version[i] = software[i];
                    i++;
                }
                
                // Determine the SSH implementation
                if (strstr(software_version, "OpenSSH")) {
                    strncpy(service_info->service_name, "OpenSSH", sizeof(service_info->service_name) - 1);
                    
                    // Extract version (e.g., 8.1p1)
                    const char *ver = strstr(software_version, "OpenSSH_");
                    if (ver) {
                        ver += 8; // Skip "OpenSSH_"
                        strncpy(service_info->version, ver, sizeof(service_info->version) - 1);
                    }
                } else {
                    // For other SSH implementations, use the software version as is
                    strncpy(service_info->service_name, software_version, sizeof(service_info->service_name) - 1);
                }
            }
        }
        
        return;
    }
    // FTP detection
    else if (strstr(banner, "FTP") != NULL || strncmp(banner, "220", 3) == 0)
    {
        strncpy(service_info->protocol, "FTP", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "ftp", sizeof(service_info->service_name) - 1);
        
        char ftp_banner[256] = {0};
        if (strncmp(banner, "220", 3) == 0) {
            // Skip the 220 code and any spaces
            const char *start = banner + 3;
            while (*start && isspace((unsigned char)*start))
                start++;
            
            // Copy the first line of the banner
            int i = 0;
            while (start[i] && start[i] != '\r' && start[i] != '\n' && i < 255) {
                ftp_banner[i] = start[i];
                i++;
            }
            
            ftp_banner[i] = '\0';
        } else {
            // Just use the banner as is
            strncpy(ftp_banner, banner, sizeof(ftp_banner) - 1);
        }
        
        // Extract FTP server type and version
        if (strstr(ftp_banner, "FileZilla")) {
            strncpy(service_info->service_name, "FileZilla ftpd", sizeof(service_info->service_name) - 1);
            const char *ver = strstr(ftp_banner, "FileZilla Server ");
            if (ver) {
                ver += 17; // Skip "FileZilla Server "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(ftp_banner, "vsftpd")) {
            strncpy(service_info->service_name, "vsftpd", sizeof(service_info->service_name) - 1);
            const char *ver = strstr(ftp_banner, "vsftpd ");
            if (ver) {
                ver += 7; // Skip "vsftpd "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(ftp_banner, "ProFTPD")) {
            strncpy(service_info->service_name, "ProFTPD", sizeof(service_info->service_name) - 1);
            const char *ver = strstr(ftp_banner, "ProFTPD ");
            if (ver) {
                ver += 8; // Skip "ProFTPD "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(ftp_banner, "Microsoft FTP Service")) {
            strncpy(service_info->service_name, "Microsoft ftpd", sizeof(service_info->service_name) - 1);
            // Version is usually not provided directly in the banner
        } else {
            // If we couldn't identify a specific server, use the banner content
            // to provide some information about the server
            if (strlen(ftp_banner) > 0) {
                // Extract the first word as the service name if we couldn't identify it otherwise
                char extracted_name[64] = {0};
                sscanf(ftp_banner, "%63s", extracted_name);
                if (strlen(extracted_name) > 0) {
                    strncpy(service_info->service_name, extracted_name, sizeof(service_info->service_name) - 1);
                }
            }
        }
        
        return;
    }
    // SMTP detection
    else if (strstr(banner, "SMTP") != NULL || strncmp(banner, "220", 3) == 0) 
    {
        strncpy(service_info->protocol, "SMTP", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "smtp", sizeof(service_info->service_name) - 1);
        
        // Check for common mail servers in the banner
        if (strstr(banner, "Postfix")) {
            strncpy(service_info->service_name, "Postfix smtpd", sizeof(service_info->service_name) - 1);
            // Try to extract Postfix version
            const char *ver = strstr(banner, "Postfix ");
            if (ver) {
                ver += 8; // Skip "Postfix "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(banner, "Exim")) {
            strncpy(service_info->service_name, "Exim smtpd", sizeof(service_info->service_name) - 1);
            // Try to extract Exim version
            const char *ver = strstr(banner, "Exim ");
            if (ver) {
                ver += 5; // Skip "Exim "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(banner, "Microsoft ESMTP")) {
            strncpy(service_info->service_name, "Microsoft ESMTP", sizeof(service_info->service_name) - 1);
            // Version typically not available in the banner
        } else if (strstr(banner, "Sendmail")) {
            strncpy(service_info->service_name, "Sendmail", sizeof(service_info->service_name) - 1);
            // Try to extract Sendmail version
            const char *ver = strstr(banner, "Sendmail ");
            if (ver) {
                ver += 9; // Skip "Sendmail "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && ver[j] != ';' && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        }
        
        return;
    }
    // POP3 detection
    else if (strstr(banner, "POP3") != NULL || strncmp(banner, "+OK", 3) == 0)
    {
        strncpy(service_info->protocol, "POP3", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "pop3", sizeof(service_info->service_name) - 1);
        
        // Extract server info if available
        if (strstr(banner, "Dovecot")) {
            strncpy(service_info->service_name, "Dovecot pop3d", sizeof(service_info->service_name) - 1);
        } else if (strstr(banner, "UW")) {
            strncpy(service_info->service_name, "UW POP3", sizeof(service_info->service_name) - 1);
        } else {
            // Generic extraction of the banner info
            const char *banner_start = banner;
            if (strncmp(banner, "+OK", 3) == 0) {
                banner_start += 3;
                while (*banner_start && isspace((unsigned char)*banner_start))
                    banner_start++;
            }
            
            // If there's meaningful content, use it
            if (banner_start && *banner_start) {
                char extracted_info[64] = {0};
                int i = 0;
                while (banner_start[i] && banner_start[i] != '\r' && banner_start[i] != '\n' && i < 63) {
                    extracted_info[i] = banner_start[i];
                    i++;
                }
                
                if (i > 0) {
                    strncpy(service_info->version, extracted_info, sizeof(service_info->version) - 1);
                }
            }
        }
        
        return;
    }
    // IMAP detection
    else if (strstr(banner, "IMAP") != NULL || strncmp(banner, "* OK", 4) == 0)
    {
        strncpy(service_info->protocol, "IMAP", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "imap", sizeof(service_info->service_name) - 1);
        
        // Extract server info if available
        if (strstr(banner, "Dovecot")) {
            strncpy(service_info->service_name, "Dovecot imapd", sizeof(service_info->service_name) - 1);
            // Try to extract Dovecot version
            const char *ver = strstr(banner, "Dovecot ");
            if (ver) {
                ver += 8; // Skip "Dovecot "
                char version[32] = {0};
                int j = 0;
                while (ver[j] && !isspace((unsigned char)ver[j]) && ver[j] != ')' && j < 31) {
                    version[j] = ver[j];
                    j++;
                }
                
                if (j > 0) {
                    strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                }
            }
        } else if (strstr(banner, "Cyrus")) {
            strncpy(service_info->service_name, "Cyrus imapd", sizeof(service_info->service_name) - 1);
            // Try to extract Cyrus version
            const char *ver = strstr(banner, "Cyrus IMAP");
            if (ver) {
                ver = strchr(ver, 'v');
                if (ver) {
                    ver++; // Skip 'v'
                    char version[32] = {0};
                    int j = 0;
                    while (ver[j] && !isspace((unsigned char)ver[j]) && ver[j] != ')' && j < 31) {
                        version[j] = ver[j];
                        j++;
                    }
                    
                    if (j > 0) {
                        strncpy(service_info->version, version, sizeof(service_info->version) - 1);
                    }
                }
            }
        } else {
            // Generic extraction of the banner info
            const char *banner_start = banner;
            if (strncmp(banner, "* OK", 4) == 0) {
                banner_start += 4;
                while (*banner_start && isspace((unsigned char)*banner_start))
                    banner_start++;
            }
            
            // If there's meaningful content, use it
            if (banner_start && *banner_start) {
                char extracted_info[64] = {0};
                int i = 0;
                while (banner_start[i] && banner_start[i] != '\r' && banner_start[i] != '\n' && i < 63) {
                    extracted_info[i] = banner_start[i];
                    i++;
                }
                
                if (i > 0) {
                    strncpy(service_info->version, extracted_info, sizeof(service_info->version) - 1);
                }
            }
        }
        
        return;
    }
    // Telnet detection
    else if (strstr(banner, "Telnet") != NULL || strstr(banner, "login:") != NULL || 
             strstr(banner, "Username:") != NULL || strstr(banner, "Password:") != NULL)
    {
        strncpy(service_info->protocol, "Telnet", sizeof(service_info->protocol) - 1);
        strncpy(service_info->service_name, "telnet", sizeof(service_info->service_name) - 1);
        
        // Usually telnet doesn't provide version info directly in the banner
        // But we can try to identify the telnet server type
        if (strstr(banner, "Linux") || strstr(banner, "Ubuntu") || strstr(banner, "Debian")) {
            strncpy(service_info->version, "Linux telnetd", sizeof(service_info->version) - 1);
        } else if (strstr(banner, "Windows")) {
            strncpy(service_info->version, "Windows telnetd", sizeof(service_info->version) - 1);
        }
        
        return;
    }
    
    // If we couldn't identify the service, try to extract some meaningful info from the banner
    if (banner && banner[0]) {
        char extracted_info[64] = {0};
        int i = 0;
        while (banner[i] && banner[i] != '\r' && banner[i] != '\n' && i < 63) {
            extracted_info[i] = banner[i];
            i++;
        }
        
        if (i > 0) {
            // Check if the banner starts with a service name
            char service_name[32] = {0};
            sscanf(extracted_info, "%31s", service_name);
            
            if (strlen(service_name) > 0) {
                strncpy(service_info->service_name, service_name, sizeof(service_info->service_name) - 1);
                strncpy(service_info->protocol, "tcp", sizeof(service_info->protocol) - 1);
            }
        }
    }
}