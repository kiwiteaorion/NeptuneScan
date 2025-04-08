#include "scan_utils.h"
#include "scanner.h"

const char *scan_type_to_string(scan_type_t scan_type)
{
  switch (scan_type)
  {
  case SCAN_CONNECT:
    return "TCP Connect";
  case SCAN_SYN:
    return "SYN";
  case SCAN_FIN:
    return "FIN";
  case SCAN_NULL:
    return "NULL";
  case SCAN_XMAS:
    return "XMAS";
  case SCAN_ACK:
    return "ACK";
  case SCAN_WINDOW:
    return "Window";
  case SCAN_MAIMON:
    return "Maimon";
  default:
    return "Unknown";
  }
}