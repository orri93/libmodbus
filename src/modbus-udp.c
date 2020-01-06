/*
 * Copyright © 2001-2013 Stéphane Raimbault <stephane.raimbault@gmail.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if defined(_WIN32)
# define OS_WIN32
 /* ws2_32.dll has getaddrinfo and freeaddrinfo on Windows XP and later.
  * minwg32 headers check WINVER before allowing the use of these */
# ifndef WINVER
#   define WINVER 0x0501
# endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <signal.h>
#include <sys/types.h>

#if defined(_WIN32)
  /* Already set in modbus-udp.h but it seems order matters in VS2005 */
# include <winsock2.h>
# include <ws2tcpip.h>
# define SHUT_RDWR 2
# define close closesocket
#else
# include <sys/socket.h>
# include <sys/ioctl.h>

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ < 5)
# define OS_BSD
# include <netinet/in_systm.h>
#endif

# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/udp.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#if defined(_AIX) && !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

#include "modbus-private.h"

#include "modbus-udp.h"
#include "modbus-udp-private.h"

static char udp_buffer_[MODBUS_UDP_MAX_ADU_LENGTH];

#ifdef OS_WIN32
static int _modbus_udp_init_win32(void)
{
  /* Initialise Windows Socket API */
  WSADATA wsaData;

  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    fprintf(stderr, "WSAStartup() returned error code %d\n",
      (unsigned int)GetLastError());
    errno = EIO;
    return -1;
  }
  return 0;
}
#endif

static int _modbus_set_slave(modbus_t* ctx, int slave)
{
  /* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
  if (slave >= 0 && slave <= 247) {
    ctx->slave = slave;
  } else if (slave == MODBUS_UDP_SLAVE) {
    /* The special value MODBUS_UDP_SLAVE (0xFF) can be used in UDP mode to
     * restore the default value. */
    ctx->slave = slave;
  } else {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

/* Builds a UCP request header */
static int _modbus_udp_build_request_basis(modbus_t* ctx, int function,
  int addr, int nb,
  uint8_t* req)
{
  modbus_udp_t* ctx_udp = ctx->backend_data;

  /* Increase transaction ID */
  if (ctx_udp->t_id < UINT16_MAX)
    ctx_udp->t_id++;
  else
    ctx_udp->t_id = 0;
  req[0] = ctx_udp->t_id >> 8;
  req[1] = ctx_udp->t_id & 0x00ff;

  /* Protocol Modbus */
  req[2] = 0;
  req[3] = 0;

  /* Length will be defined later by set_req_length_udp at offsets 4
     and 5 */

  req[6] = ctx->slave;
  req[7] = function;
  req[8] = addr >> 8;
  req[9] = addr & 0x00ff;
  req[10] = nb >> 8;
  req[11] = nb & 0x00ff;

  return _MODBUS_UDP_PRESET_REQ_LENGTH;
}

/* Builds a UDP response header */
static int _modbus_udp_build_response_basis(sft_t* sft, uint8_t* rsp)
{
  /* Extract from MODBUS Messaging on TCP/IP Implementation
     Guide V1.0b (page 23/46):
     The transaction identifier is used to associate the future
     response with the request. */
  rsp[0] = sft->t_id >> 8;
  rsp[1] = sft->t_id & 0x00ff;

  /* Protocol Modbus */
  rsp[2] = 0;
  rsp[3] = 0;

  /* Length will be set later by send_msg (4 and 5) */

  /* The slave ID is copied from the indication */
  rsp[6] = sft->slave;
  rsp[7] = sft->function;

  return _MODBUS_UDP_PRESET_RSP_LENGTH;
}

static int _modbus_udp_prepare_response_tid(const uint8_t* req, int* req_length)
{
  return (req[0] << 8) + req[1];
}

static int _modbus_udp_send_msg_pre(uint8_t* req, int req_length)
{
  /* Substract the header length to the message length */
  int mbap_length = req_length - 6;

  req[4] = mbap_length >> 8;
  req[5] = mbap_length & 0x00FF;

  return req_length;
}

static ssize_t _modbus_udp_send(modbus_t* ctx, const uint8_t* req, int req_length)
{
  modbus_udp_t* ctx_udp = ctx->backend_data;
  
  return sendto(
    ctx->s,
    (const char*)req,
    req_length,
    0,
    (const struct sockaddr*) &ctx_udp->cliaddr,
    ctx_udp->cliaddrlen);

  /* MSG_NOSIGNAL
     Requests not to send SIGPIPE on errors on stream oriented
     sockets when the other end breaks the connection.  The EPIPE
     error is still returned. */

  //return send(ctx->s, (const char*)req, req_length, MSG_NOSIGNAL);
}

static int _modbus_udp_receive(modbus_t* ctx, uint8_t* req) {
  modbus_udp_t* ctx_udp = ctx->backend_data;
  ctx_udp->rc = 0;
  return _modbus_receive_msg(ctx, req, MSG_INDICATION);
}

static ssize_t _modbus_udp_recv(modbus_t* ctx, uint8_t* rsp, int rsp_length) {
  int rc;
  int flags = 0;
  modbus_udp_t* ctx_udp = ctx->backend_data;
  if (ctx_udp->rc == 0) {
    ctx_udp->cliaddrlen = sizeof(ctx_udp->cliaddr);
    memset(&(ctx_udp->cliaddr), 0, ctx_udp->cliaddrlen);
    memset(udp_buffer_, 0, MODBUS_UDP_MAX_ADU_LENGTH);
    ctx_udp->rc = recvfrom(
      ctx->s,
      udp_buffer_,
      MODBUS_UDP_MAX_ADU_LENGTH,
      flags,
      (struct sockaddr*) & (ctx_udp->cliaddr),
      &(ctx_udp->cliaddrlen));
    if (ctx_udp->rc == -1) {
      return -1;
    }
    ctx_udp->at = udp_buffer_;
  }
  rc = min(rsp_length, ctx_udp->rc);
  memcpy((void*)rsp, ctx_udp->at, rc);
  ctx_udp->at += rc;
  ctx_udp->rc -= rc;
  return rc;
}

static int _modbus_udp_check_integrity(modbus_t* ctx, uint8_t* msg, const int msg_length)
{
  return msg_length;
}

static int _modbus_udp_pre_check_confirmation(modbus_t* ctx, const uint8_t* req,
  const uint8_t* rsp, int rsp_length)
{
  /* Check transaction ID */
  if (req[0] != rsp[0] || req[1] != rsp[1]) {
    if (ctx->debug) {
      fprintf(stderr, "Invalid transaction ID received 0x%X (not 0x%X)\n",
        (rsp[0] << 8) + rsp[1], (req[0] << 8) + req[1]);
    }
    errno = EMBBADDATA;
    return -1;
  }

  /* Check protocol ID */
  if (rsp[2] != 0x0 && rsp[3] != 0x0) {
    if (ctx->debug) {
      fprintf(stderr, "Invalid protocol ID received 0x%X (not 0x0)\n",
        (rsp[2] << 8) + rsp[3]);
    }
    errno = EMBBADDATA;
    return -1;
  }

  return 0;
}

static int _modbus_udp_connect(modbus_t* ctx)
{
  /* Do nothing */
  return 0;
}

/* Closes the network connection and socket in UDP mode */
static void _modbus_udp_close(modbus_t* ctx)
{
  if (ctx->s != -1) {
    shutdown(ctx->s, SHUT_RDWR);
    close(ctx->s);
    ctx->s = -1;
  }
}

static int _modbus_udp_flush(modbus_t* ctx)
{
  /* Do nothing */
  return 0;
}

int modbus_udp_bind(modbus_t* ctx)
{
  int rc;
  /* Specialized version of sockaddr for Internet socket address (same size) */
  struct sockaddr_in addr;
  modbus_udp_t* ctx_udp = ctx->backend_data;
  int flags = SOCK_DGRAM;

  if (ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef OS_WIN32
  if (_modbus_udp_init_win32() == -1) {
    return -1;
  }
#endif

  ctx->s = socket(PF_INET, flags, 0);
  if (ctx->s == -1) {
    return -1;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(ctx_udp->port);
  /* addr.sin_addr.s_addr = inet_addr(ctx_udp->ip); */
  addr.sin_addr.s_addr = INADDR_ANY;

  rc = bind(ctx->s, (struct sockaddr*) & addr, sizeof(addr));

  return rc == 0 ? ctx->s : rc;
}

int modbus_udp_pi_bind(modbus_t* ctx)
{
  int rc;

  struct sockaddr_storage addr;
  socklen_t addrlen;

  if (ctx == NULL) {
    errno = EINVAL;
    return -1;
  }

  ctx->s = socket(AF_INET6, SOCK_DGRAM, 0);
  if (ctx->s == -1) {
    return -1;
  }

  addrlen = sizeof(addr);

  rc = bind(ctx->s, (struct sockaddr*) & addr, addrlen);

  return rc;
}

static int _modbus_udp_select(modbus_t* ctx, fd_set* rset, struct timeval* tv, int length_to_read)
{
  int s_rc;
  modbus_udp_t* ctx_udp = ctx->backend_data;
  if (ctx_udp->rc == 0) {
    while ((s_rc = select(ctx->s + 1, rset, NULL, NULL, tv)) == -1) {
      if (errno == EINTR) {
        if (ctx->debug) {
          fprintf(stderr, "A non blocked signal was caught\n");
        }
        /* Necessary after an error */
        FD_ZERO(rset);
        FD_SET(ctx->s, rset);
      } else {
        return -1;
      }
    }

    if (s_rc == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
  } else {
    s_rc = 1;
  }

  return s_rc;
}

static void _modbus_udp_free(modbus_t* ctx) {
  free(ctx->backend_data);
  free(ctx);
}

const modbus_backend_t _modbus_udp_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_receive,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_free
};

const modbus_backend_t _modbus_udp_pi_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_receive,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_free
};

modbus_t* modbus_new_udp(const char* ip, int port)
{
  modbus_t* ctx;
  modbus_udp_t* ctx_udp;
  size_t dest_size;
  size_t ret_size;

  ctx = (modbus_t*)malloc(sizeof(modbus_t));
  if (ctx == NULL) {
    return NULL;
  }
  _modbus_init_common(ctx);

  /* Could be changed after to reach a remote serial Modbus device */
  ctx->slave = MODBUS_UDP_SLAVE;

  ctx->backend = &_modbus_udp_backend;

  ctx->backend_data = (modbus_udp_t*)malloc(sizeof(modbus_udp_t));
  if (ctx->backend_data == NULL) {
    modbus_free(ctx);
    errno = ENOMEM;
    return NULL;
  }
  ctx_udp = (modbus_udp_t*)ctx->backend_data;

  if (ip != NULL) {
    dest_size = sizeof(char) * 16;
    ret_size = strlcpy(ctx_udp->ip, ip, dest_size);
    if (ret_size == 0) {
      fprintf(stderr, "The IP string is empty\n");
      modbus_free(ctx);
      errno = EINVAL;
      return NULL;
    }

    if (ret_size >= dest_size) {
      fprintf(stderr, "The IP string has been truncated\n");
      modbus_free(ctx);
      errno = EINVAL;
      return NULL;
    }
  } else {
    ctx_udp->ip[0] = '0';
  }
  ctx_udp->port = port;
  ctx_udp->t_id = 0;

  return ctx;
}

modbus_t* modbus_new_udp_pi(const char* node, const char* service)
{
  modbus_t* ctx;
  modbus_udp_pi_t* ctx_udp_pi;
  size_t dest_size;
  size_t ret_size;

  ctx = (modbus_t*)malloc(sizeof(modbus_t));
  if (ctx == NULL) {
    return NULL;
  }
  _modbus_init_common(ctx);

  /* Could be changed after to reach a remote serial Modbus device */
  ctx->slave = MODBUS_UDP_SLAVE;

  ctx->backend = &_modbus_udp_pi_backend;

  ctx->backend_data = (modbus_udp_pi_t*)malloc(sizeof(modbus_udp_pi_t));
  if (ctx->backend_data == NULL) {
    modbus_free(ctx);
    errno = ENOMEM;
    return NULL;
  }
  ctx_udp_pi = (modbus_udp_pi_t*)ctx->backend_data;

  if (node == NULL) {
    /* The node argument can be empty to indicate any hosts */
    ctx_udp_pi->node[0] = 0;
  } else {
    dest_size = sizeof(char) * _MODBUS_UDP_PI_NODE_LENGTH;
    ret_size = strlcpy(ctx_udp_pi->node, node, dest_size);
    if (ret_size == 0) {
      fprintf(stderr, "The node string is empty\n");
      modbus_free(ctx);
      errno = EINVAL;
      return NULL;
    }

    if (ret_size >= dest_size) {
      fprintf(stderr, "The node string has been truncated\n");
      modbus_free(ctx);
      errno = EINVAL;
      return NULL;
    }
  }

  if (service != NULL) {
    dest_size = sizeof(char) * _MODBUS_UDP_PI_SERVICE_LENGTH;
    ret_size = strlcpy(ctx_udp_pi->service, service, dest_size);
  } else {
    /* Empty service is not allowed, error catched below. */
    ret_size = 0;
  }

  if (ret_size == 0) {
    fprintf(stderr, "The service string is empty\n");
    modbus_free(ctx);
    errno = EINVAL;
    return NULL;
  }

  if (ret_size >= dest_size) {
    fprintf(stderr, "The service string has been truncated\n");
    modbus_free(ctx);
    errno = EINVAL;
    return NULL;
  }

  ctx_udp_pi->t_id = 0;

  return ctx;
}
