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
    perror("SOCKET COULD NOT BE OPENED");
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
  micro_sock->remote_host_addr = NULL;
  micro_sock->remote_host_addr_size = 0;
  micro_sock->init_win_size = MICROTCP_WIN_SIZE;
  micro_sock->curr_win_size = micro_sock->init_win_size;

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

void*
microtcp_make_pkt (microtcp_sock_t *socket, void* data, int data_len, int flags) {

  void* microtcp_packet;
  int checksum;

  /* user calloc to initialize the header because it zeroes out the memory */
  microtcp_header_t* header = calloc(HEADER_SIZE, 1);
  
  /* assign the relevant values to the header */
  header->ack_number = socket->ack_number;
  header->seq_number = socket->seq_number;
  header->data_len = data_len;
  header->control = flags;
  header->window = socket->buf_fill_level;
  
  /* 
    * NOTE THAT THE FOLLOWING CODE SHOULD WORK REGARDLESS OF THE SIZE OF THE DATA
    * IF THE DATA LENGTH IS ZERO THEN THE FUNCTIONS SHOULD NOT ACCESS IT 
    */

  /* allocate space both for the data and the header*/
  microtcp_packet = malloc(HEADER_SIZE + sizeof(char) * data_len);
  
  /* copy the header to the start of the packet and the data after the 
    * header */
  memcpy(microtcp_packet, header, HEADER_SIZE);
  memcpy(microtcp_packet + HEADER_SIZE, data, data_len);
  
  /* calculate the checksum */
  checksum = crc32(microtcp_packet, HEADER_SIZE + data_len); 

  /*
    * put the checksum in the header and put the header in the packet again
    */
  header->checksum = checksum;
  memcpy(microtcp_packet, header, HEADER_SIZE);

  free(header);
  
  return microtcp_packet;
}

int microtcp_test_checksum(void* packet) {
    microtcp_header_t* packet_header = (microtcp_header_t*) packet;
    int checksum = packet_header->checksum;

    packet_header->checksum = 0; 
    if (crc32(packet, HEADER_SIZE + packet_header->data_len) != checksum)
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
    free(socket->remote_host_addr);
    socket->remote_host_addr_size = 0;
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
    socket->cwnd = 0;
    socket->ssthresh = 0;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  //first step of 3-way handshake
  //client initiates a connection:
  //sends a special segment, no data, flag SYN = 1
  //randomly assigns a seq num
  //encapsulate in a datagram and send!
    /* make a SYN packet and send it */
    void* syn_pack = microtcp_make_pkt(socket, NULL, 0, SYN);
    
    if (sendto(socket->sd, syn_pack, HEADER_SIZE, 0, 
                address, address_len) == -1)
    {
        LOG_ERROR("Failed to send SYN packet.");
        socket->state = INVALID;
        return -1;
    }
    LOG_INFO("Sent SYN packet, waiting for SYNACK.\n");

    /* wait to receive SYNACK response */
    microtcp_header_t* synack_pck = malloc(HEADER_SIZE);
    
    /* get packet and verify it was both received correctly and 
     * has the expected contents */
    
wait_for_synack:
    if(recvfrom(socket->sd, synack_pck, HEADER_SIZE,
                0, NULL, 0) == -1) {
        LOG_ERROR("Failed to receive SYNACK packet.");
        socket->state = INVALID;
        return -1;
    } else if (!microtcp_test_checksum(synack_pck)) {
        LOG_WARN("Received corrupted packet, will continue to wait.");
        goto wait_for_synack;
    } else if ((synack_pck->control ^ (ACK | SYN)) != 0) {
        LOG_ERROR("Packet didn't only have syn and ack flags, aborting.");
        socket->state = INVALID;
        return -1;
    }

    /* increase our sequence number */
    socket->seq_number += 1;

    /* store the sequence number of the other host as our ACK number and 
     * add 1 to it */
    socket->ack_number = synack_pck->seq_number + 1;
    
    /* crete final ack packet for handshake */
    void* final_pck = microtcp_make_pkt(socket, NULL, 0, ACK);

    /* increase out sequence number */
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
    socket->remote_host_addr = address;
    socket->remote_host_addr_size = address_len;

    /* also change the socket state accprdingly */
    socket->state = ESTABLISHED;

    return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  /* Your code here */
  //second step of 3-way handshake
  //server responds to SYN segment
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
  /* Your code here */         
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


    /* polling code taken from Beej's Guide to Network Programming */
    struct pollfd events[1];
    void* data_in = malloc(sizeof(char) * MICROTCP_MSS);
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

    LOG_INFO("received packet lmao");
    /* we have received the packet!!! next we do stuff with it but i shall
     * deal with that later ... 
     * TODO: actually implement the shutdown thingy :3 */

    /* get the packet's header */
    microtcp_header_t* header = (microtcp_header_t*) data_in; 
    
    /* check if FIN flag is set, if not, ignore the packet */
    if((header->control & FIN) != 0) {
       LOG_INFO("Packet doesn't have FIN flag, ignoring for now...");
       goto wait_for_packet;
    }
    
    /* otherwise send the ack */
    socket->ack_number += 1;

    void* ack = microtcp_make_pkt(socket, NULL, 0, ACK);

    while (sendto(socket->sd, ack, HEADER_SIZE, 0, socket->remote_host_addr, 
                socket->remote_host_addr_size) == -1)
    {
        LOG_ERROR("Failed to send ack, retrying");
    }
    free(ack);

    /* set the socket state accordingly */
    socket->state = CLOSING_BY_PEER;
    
    /* send FIN packet */
    void* fin = microtcp_make_pkt(socket, NULL, 0, FIN | ACK); 

    while(sendto(socket->sd, fin, HEADER_SIZE, 0, socket->remote_host_addr, 
                socket->remote_host_addr_size) == -1)
    {
        LOG_WARN("Failed to send fin, retrying...");
    }
    free(fin);
    
    /* wait for ack */

wait_for_fin_ack:
    while(recvfrom(socket->sd, data_in, data_len,
                0, NULL, 0) == -1) 
    {
        LOG_WARN("Failed to receive ack, continuing to wait.");
    }
    
    /* get the header from the data */
    header = (microtcp_header_t*)data_in;
    
    if((header->control & (FIN|ACK)) == 0) {
        LOG_WARN("Received packet wasn't ack, continuing to wait...");
        goto wait_for_fin_ack;
    }

    /* we got the ack! close the connection and deallocate all memory */
    microtcp_close_socket(socket);
    return 0;
}

