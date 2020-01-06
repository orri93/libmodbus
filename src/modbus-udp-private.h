/*
 * Copyright � 2001-2011 St�phane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef MODBUS_UDP_PRIVATE_H
#define MODBUS_UDP_PRIVATE_H

#define _MODBUS_UDP_HEADER_LENGTH      7
#define _MODBUS_UDP_PRESET_REQ_LENGTH 12
#define _MODBUS_UDP_PRESET_RSP_LENGTH  8

#define _MODBUS_UDP_CHECKSUM_LENGTH    0

 /* In both structures, the transaction ID must be placed on first position
    to have a quick access not dependant of the UDP backend */
typedef struct _modbus_udp {
  /* Extract from MODBUS Messaging on TCP/IP Implementation Guide V1.0b
     (page 23/46):
     The transaction identifier is used to associate the future response
     with the request. This identifier is unique on each TCP connection. */
  uint16_t t_id;
  /* UDP port */
  int port;
  /* IP address */
  char ip[16];
  /* Client address */
  struct sockaddr_in cliaddr;
  int cliaddrlen;
  /* Last UDP received count */
  int rc;
  /* Position in the UDP receive buffer */
  char* at;
} modbus_udp_t;

#define _MODBUS_UDP_PI_NODE_LENGTH    1025
#define _MODBUS_UDP_PI_SERVICE_LENGTH   32

typedef struct _modbus_udp_pi {
  /* Transaction ID */
  uint16_t t_id;
  /* TCP port */
  int port;
  /* Node */
  char node[_MODBUS_UDP_PI_NODE_LENGTH];
  /* Service */
  char service[_MODBUS_UDP_PI_SERVICE_LENGTH];

} modbus_udp_pi_t;

#endif /* MODBUS_UDP_PRIVATE_H */
