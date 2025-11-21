#pragma once

//! @file
//!
//! Copyright (c) Memfault, Inc.
//! See LICENSE for details
//!
//! @brief
//! Zephyr specific coap utility for interfacing with Memfault CoAP utilities

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

//! Writer invoked by calls to "memfault_coap_start_chunk_post"
//!
//! For example, this would be where a user of the API would make a call to send() to push data
//! over a socket
typedef bool (*MfltCoAPClientSendCb)(const void *data, size_t data_len, void *ctx);

//! Context structure used to carry state information about the CoAP connection
typedef struct {
  int sock_fd;
  struct zsock_addrinfo *res;
  size_t bytes_sent;
  uint8_t message_token[COAP_TOKEN_MAX_LEN];
} sMemfaultCoAPContext;

void memfault_zephyr_port_coap_close_socket(sMemfaultCoAPContext *ctx);

int memfault_zephyr_port_coap_upload_sdk_data(sMemfaultCoAPContext *ctx);

#ifdef __cplusplus
}
#endif
