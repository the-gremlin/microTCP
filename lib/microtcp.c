/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include <stdbool.h>
#include "../utils/crc32.h"
#include <time.h>
#include <stdlib.h>
#include "../utils/log.h"
#include <stdio.h>
#include <sys/socket.h>
#include <poll.h>

microtcp_sock_t microtcp_socket (int domain, int type, int protocol){

  /*OPEN A SOCKET*/
  int sock;
  if((sock = socket(domain, type, protocol)) == -1){
    LOG_ERROR("SOCKET COULD NOT BE OPENED");
    exit(EXIT_FAILURE);
  }

  /*ALLOCATE STRUCT MEMORY*/
  microtcp_sock_t *micro_sock = (microtcp_sock_t *) malloc(sizeof(microtcp_sock_t));
  if (micro_sock == NULL){
    exit(EXIT_FAILURE);
  }

  /*INITIALIZE STRUCT FIELDS*/
  micro_sock->sd = sock;
  micro_sock->state = CLOSED;
  micro_sock->peer_addr = NULL;
  micro_sock->peer_addr_len = 0;
  micro_sock->init_win_size = MICROTCP_WIN_SIZE;
  micro_sock->curr_win_size = micro_sock->init_win_size;
  micro_sock->can_read = true;
  micro_sock->can_write = true;

  micro_sock->recvbuf = (uint8_t *) calloc(MICROTCP_RECVBUF_LEN, MICROTCP_MSS);
  if (micro_sock->recvbuf == NULL){
    exit(EXIT_FAILURE);
  }

  micro_sock->buf_fill_level = 0; /*buffer has no data*/
  micro_sock->cwnd = MICROTCP_INIT_CWND;
  micro_sock->ssthresh = MICROTCP_INIT_SSTHRESH;

  /*RANDOM SEQUENCE NUMBER*/
  srand(time(NULL));
  micro_sock->seq_number = rand();

  micro_sock->ack_number = 0;
  micro_sock->packets_send = 0;
  micro_sock->packets_received = 0;
  micro_sock->packets_lost = 0;
  micro_sock->bytes_send = 0;
  micro_sock->bytes_received = 0;
  micro_sock->bytes_lost = 0;

  return *micro_sock;
}

microtcp_packet_t*
microtcp_make_pkt (microtcp_sock_t *socket, const char* data, int data_len, int flags) {
  int i;
  microtcp_packet_t* packet;

  /*ALLOCATE MEMORY*/
  packet = (microtcp_packet_t*) malloc(sizeof(microtcp_packet_t));
  
  /*SET HEADER VARIABLES*/
  packet->header.ack_number = socket->ack_number;
  packet->header.seq_number = socket->seq_number;
  packet->header.data_len = data_len;
  packet->header.control = flags;
  packet->header.window = socket->buf_fill_level;
  packet->header.future_use0 = 0;
  packet->header.future_use1 = 0;
  packet->header.future_use2 = 0;

  for (i = 0; i < data_len; i++){
    packet->data[i] = data[i];
  }
  
  packet->header.checksum = crc32((void*)packet, HEADER_SIZE + data_len);

  return packet;
}

int microtcp_test_checksum(microtcp_packet_t* packet) {
    int checksum = packet->header.checksum;

    packet->header.checksum = 0; 
    if (crc32((void*)packet, HEADER_SIZE + packet->header.data_len) != checksum)
        return 0;
    else
        return 1;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  if(bind(socket->sd, address, address_len) == -1){

    LOG_ERROR("Could not bind socket to port, see `perror` for more infor.");
    return -1;
  } else {
    return 0;
  }
}

void microtcp_close_socket(microtcp_sock_t* socket) {
    free(socket->recvbuf);
    socket->bytes_lost = 0;
    socket->bytes_received = 0;
    socket->bytes_send = 0;
    socket->curr_win_size = socket->init_win_size;
    socket->packets_send = 0;
    socket->packets_lost = 0;
    socket->packets_received = 0;
    socket->buf_fill_level = 0;
    socket->seq_number = rand();
    socket->ack_number = 0;
    socket->cwnd = MICROTCP_INIT_CWND;
    socket->ssthresh = MICROTCP_INIT_SSTHRESH;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  /* make a SYN packet and send it */
  microtcp_packet_t* syn_pack = microtcp_make_pkt(socket, NULL, 0, SYN);

  socket->conn_role = CLIENT;
  
  if (sendto(socket->sd, syn_pack, HEADER_SIZE, 0, 
              address, address_len) == -1)
  {
    LOG_ERROR("Failed to send SYN packet.");
    socket->state = INVALID;
    return -1;
  }
  LOG_INFO("Sent SYN packet, waiting for SYNACK.");

  /* increase our sequence number */
  socket->seq_number += 1;

  /* wait to receive SYNACK response */
  microtcp_packet_t* synack_pck = malloc(sizeof(microtcp_packet_t));
  
  /* get packet and verify it was both received correctly and 
    * has the expected contents */
    
  if(recvfrom(socket->sd, synack_pck, HEADER_SIZE,
              0, NULL, 0) == -1) {
    LOG_ERROR("Failed to receive SYNACK packet.");
    socket->state = INVALID;
    return -1;
  } else if (!microtcp_test_checksum(synack_pck)) {
    LOG_ERROR("Received corrupted packet, will continue to wait.");
    socket->state = INVALID;
    return -1;
  } else if ((synack_pck->header.control ^ (ACK | SYN)) != 0) {
    LOG_ERROR("Packet didn't only have syn and ack flags, aborting.");
    socket->state = INVALID;
    return -1;
  }

  /* store the sequence number of the other host as our ACK number and 
    * add 1 to it */
  socket->ack_number = synack_pck->header.seq_number + 1;
  
  /* create final ack packet for handshake */
  microtcp_packet_t* final_pck = microtcp_make_pkt(socket, NULL, 0, ACK);

  /* increase our sequence number */
  socket->seq_number += 1;

  if(sendto(socket->sd, final_pck, HEADER_SIZE, 0, 
              address, address_len) == -1)
  {
      LOG_ERROR("Error sending last ack in handshake.");
      socket->state = INVALID;
      return -1;
  }

  /* we have established connection!!! save the remote
    * host's address and return success */
  socket->peer_addr = address;
  socket->peer_addr_len = address_len;

  /* also change the socket state accprdingly */
  socket->state = ESTABLISHED;

  return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  int sent;
  microtcp_packet_t* synack_pack = microtcp_make_pkt(socket, NULL, 0, (SYN|ACK));

  socket->conn_role = SERVER;

  /*SEND SYNACK*/
  sent = sendto(socket->sd, synack_pack, HEADER_SIZE, 0, address, address_len);

  if(sent == -1){
    LOG_ERROR("Failed to send SYNACK packet");
    socket->state = INVALID;
    return -1;
  }

  LOG_INFO("Sent SYNACK packet, waiting for ACK");

  /*RECEIVE FINAL ACK*/
  microtcp_packet_t* ack_pack = malloc(sizeof(microtcp_packet_t));
  
  if(recvfrom(socket->sd, ack_pack, HEADER_SIZE, 0, NULL, 0) == -1) {
    LOG_ERROR("Failed to receive ACK");
    socket->state = INVALID;
    return -1;
  }else if(!microtcp_test_checksum(ack_pack)) {
    LOG_ERROR("Received corrupted packet, aborting");
    socket->state = INVALID;
    return -1;
  }else if((ack_pack->header.control ^ ACK) != 0) {
    LOG_ERROR("Unexpected header flags, aborting");
    socket->state = INVALID;
    return -1;
  }

  /*UPDATE SEQUENCE NUMBERS*/
  socket->seq_number += 1;
  socket->ack_number = ack_pack->header.seq_number + 1;

  socket->state = ESTABLISHED;
  LOG_INFO("Connection has been established");

  return 0;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  int sent;
  microtcp_packet_t* fin_pack;

  if (socket->conn_role == SERVER) {
    LOG_ERROR("The server cannot shut down the connection.");
    return -1;
  }
  
  switch (how){
    
    case 0: /*SHUT_RD: DISABLE RECEPTION*/

      /* disable reads */
      socket->can_read = false;

    case 1: /*SHUT_WR: DISABLE TRANSMISSION*/

      /* disable writes */
      socket->can_write = false;
      /*SEND A FIN PACKET*/
      fin_pack = microtcp_make_pkt(socket, NULL, 0, FIN);
      sent = sendto(socket->sd, fin_pack, HEADER_SIZE, 0, 
                  socket->peer_addr, socket->peer_addr_len);

      if(sent == -1){
        LOG_ERROR("Failed to send FIN packet");
        return -1;
      }

      LOG_INFO("Successful transmission of FIN packet");

      socket->state = FIN_WAIT_1;

      break;

    case 2: /*SHUT_RDWR: DISABLE RECEPTION AND TRANSMISSION*/

      /* disable reads and writes */
      socket->can_read = false;
      socket->can_write = false;

      /*SEND A FIN PACKET*/
      fin_pack = microtcp_make_pkt(socket, NULL, 0, FIN);
      sent = sendto(socket->sd, fin_pack, HEADER_SIZE, 0, 
                  socket->peer_addr, socket->peer_addr_len);

      if(sent == -1){
        LOG_ERROR("Failed to send FIN packet");
        return -1;
      }
      
      LOG_INFO("Successful transmission of FIN packet");

      socket->state = FIN_WAIT_1;
      
      break;

    default: /*INVALID HOW VALUE*/
      LOG_ERROR("Invalid value specified in how");
      return -1;
  }

  return 0;       
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags)
{
  /* Your code here */
}



ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
    if (socket->can_read == false) {
      LOG_ERROR("Connection is closed, cannot read");
      return -1;
    }

    /* polling code taken from Beej's Guide to Network Programming */
    struct pollfd events[1];
    microtcp_packet_t* data_in = malloc(sizeof(char) * MICROTCP_MSS);
    int data_len = sizeof(char) * MICROTCP_MSS;

    events[0].fd = socket->sd;
    events[0].events = POLLIN;


    LOG_INFO("Waiting for incoming messages with poll();");

wait_for_packet:
    poll(events, 1, -1); // -1 means it will wait until an event happens;
    
    LOG_INFO("Received a message, reading packet now!");
    
    /* get the data */
    if(recvfrom(socket->sd, data_in, data_len,
                0, NULL, 0) == -1) 
    {
        LOG_ERROR("Reading incoming data from socket failed, aborting.");
        socket->state = INVALID;
        return -1;
    } else if (!microtcp_test_checksum(data_in)) {
        /* test checksum */
        LOG_WARN("Packet checksum failed, continuing to wait for valid packets");
        goto wait_for_packet;
    }

    LOG_INFO("received packet");

    /* get the packet's header */
    microtcp_header_t header = data_in->header; 

    if (socket->state == FIN_WAIT_1 &&
            header.control == ACK) {
        socket->state = CLOSING_BY_HOST;

        goto wait_for_packet;
    } else if (socket->state == CLOSING_BY_HOST &&
            (header.control ^ FIN) == 0) {
        socket->state = CLOSED;  
        microtcp_close_socket(socket);
        return 0;
    } else if (socket->conn_role == SERVER &&
            (header.control ^ FIN) == 0) {
        socket->state = CLOSING_BY_PEER;
    }
    
    /* send the ack */
    socket->ack_number += 1;

    microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
    
    while (sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, 
                socket->peer_addr_len) == -1)
    {
        LOG_ERROR("Failed to send ack, retrying");
    }
    free(ack);

    if (socket->state == CLOSING_BY_PEER) {
        microtcp_shutdown(socket, 2);
        microtcp_close_socket(socket);
        return 0;
    } else {
        goto wait_for_packet;
    }
}

