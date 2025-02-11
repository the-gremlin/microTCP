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
#include <asm-generic/socket.h>
#include <bits/types/struct_timeval.h>
#include <stdbool.h>
#include "../utils/crc32.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "../utils/log.h"
#include <stdio.h>
#include <sys/socket.h>
#include <poll.h>

microtcp_sock_t microtcp_socket(int domain, int type, int protocol){

  /*OPEN A SOCKET*/
  int sock;
  if((sock = socket(domain, SOCK_DGRAM, protocol)) == -1){
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
  micro_sock->init_win_size = 0; // 0 initial window size, will be set by the handshake
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
  packet->header.window = socket->curr_win_size;
  packet->header.future_use0 = 0;
  packet->header.future_use1 = 0;
  packet->header.future_use2 = 0;
  // set checksum to 0 for calculation
  packet->header.checksum = 0;

  for (i = 0; i < data_len; i++){
    packet->data[i] = data[i];
  }
  
  packet->header.checksum = crc32((void*)packet, HEADER_SIZE + data_len);

  return packet;
}

int microtcp_test_checksum(microtcp_packet_t* packet) {
    uint32_t checksum = packet->header.checksum;

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
  
  // set the window size
  syn_pack->header.window = MICROTCP_WIN_SIZE;

  /* we have to recalculate the checksum after setting the window size because */
  syn_pack->header.checksum = 0;
  syn_pack->header.checksum = crc32((void*)syn_pack, HEADER_SIZE + 0);

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
} // microtcp_connect

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  microtcp_packet_t* syn_pck = malloc(sizeof(microtcp_packet_t));

  if(recvfrom(socket->sd, syn_pck, HEADER_SIZE,
              0, address, &address_len) == -1) {
    LOG_ERROR("Failed to receive ACK packet.");
    perror("uh-oh");
    socket->state = INVALID;
    return -1;
  } else if (!microtcp_test_checksum(syn_pck)) {
    LOG_ERROR("Received corrupted packet, aborting.");
    socket->state = INVALID;
    return -1;
  } else if ((syn_pck->header.control ^ SYN) != 0) {
    LOG_ERROR("Packet didn't only have SYN flag, aborting.");
    socket->state = INVALID;
    return -1;
  }

  /* we've received the SYN packet, time to send our ACK packet, but first set our
   * buffer size to the size indicated by the SYN packet 
   * also set our ACK number to the packet's seq number*/
  socket->init_win_size = syn_pck->header.window;
  socket->ack_number = syn_pck->header.seq_number + 1;

  /* also write down the other hosts's address */
  socket->peer_addr = address;
  socket->peer_addr_len = address_len;


  socket->conn_role = SERVER;

  /*SEND SYNACK*/
  int sent;
  microtcp_packet_t* synack_pack = microtcp_make_pkt(socket, NULL, 0, (SYN|ACK));

  // transmit our buffer size + recalculate checksum
  syn_pck->header.window = MICROTCP_WIN_SIZE;
  syn_pck->header.checksum = 0;
  syn_pck->header.checksum = crc32((void*)syn_pck, HEADER_SIZE + 0);

  sent = sendto(socket->sd, synack_pack, HEADER_SIZE, 0, address, address_len);

  if(sent == -1){
    LOG_ERROR("Failed to send SYNACK packet");
    socket->state = INVALID;
    return -1;
  }

  LOG_INFO("Sent SYNACK packet, waiting for ACK");

  /*RECEIVE FINAL ACK*/
  microtcp_packet_t* ack_pack = malloc(sizeof(microtcp_packet_t));
  
  // we don't put the address in this recvfrom call because we already know it, hopefully 
  if(recvfrom(socket->sd, ack_pack, HEADER_SIZE, 0, NULL, 0) == -1) {
    LOG_ERROR("Failed to receive final ACK");
    socket->state = INVALID;
    return -1;
  }else if(!microtcp_test_checksum(ack_pack)) {
    LOG_ERROR("Received corrupted packet for final ACK, aborting");
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
} // microtcp_accept

int
microtcp_shutdown (microtcp_sock_t *socket, int how) {
  int sent;
  microtcp_packet_t* fin_pack;

  switch (how){
    
    case SHUT_RD: /*DISABLE RECEPTION*/

      /* free receive buffer */
      free(socket->recvbuf);
      break;

    case SHUT_WR: /*SIGNAL END OF TRANSMISSION AND DISABLE FURTHER SENDING*/

      /* force only the client being able to initiate connection close */
      
      if (socket->conn_role == SERVER && socket->state != CLOSING_BY_PEER) {
          LOG_ERROR("The server cannot initiate the shutdown of the connection!");
          return -1;
      }

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

      LOG_INFO("Send FIN, waiting for ACK");

      microtcp_packet_t* syn_pck = malloc(sizeof(microtcp_packet_t));

      // not very elegant, just throws out all packets until it receives and ACK
      int res = 0;
      do {
          // increase sequence number by the size of the packets
          // // increase sequence number by the size of the packets
        res = recvfrom(socket->sd, syn_pck, HEADER_SIZE,0, NULL, 0);
      } while (res == -1 || 
                !microtcp_test_checksum(syn_pck) ||
                (syn_pck->header.control ^ ACK) != 0);

      // we've received the ACK, change socket state
      socket->state = CLOSING_BY_HOST;

      break;
    case SHUT_RDWR: /*DISABLE RECEPTION AND TRANSMISSION*/
      // this is basically a shorthand for doing SHUT_WR and SHUT_RD immeadiately one after the other,
      // basically only in case we don't want to wait for any incoming data from the other host and want
      // to close our part of the connection immediatelly.
      // The shutdown still has to be initiated by the client

      if (socket->conn_role == SERVER && socket->state != CLOSING_BY_PEER) {
          LOG_ERROR("The server cannot initiate the shutdown of the connection!");
          return -1;
      }

      microtcp_shutdown(socket, SHUT_WR);
        
      if (socket->conn_role == CLIENT) {
          // blindly receive until FIN and send ACK
          LOG_INFO("client waiting for FIN");
          microtcp_packet_t *tmp = malloc(sizeof(microtcp_packet_t));
          do {
             res = recvfrom(socket->sd, tmp, sizeof(microtcp_packet_t),0, NULL, 0);

          } while (res != -1 &&
                    (tmp->header.control ^ FIN) != 0);

          microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
          
          while (sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, 
                      socket->peer_addr_len) == -1)
          {
             LOG_ERROR("Failed to send ack, retrying");
          }
          free(ack);
      }

      microtcp_shutdown(socket, SHUT_RD);

      break;

    default: /*INVALID HOW VALUE*/
     LOG_ERROR("Invalid value given for `how`");
     return -1;
  }

  return 0;       
}

size_t min (size_t a, size_t b, size_t c) {
    size_t tmp = (a < b) ? a : b;

    return (tmp < c) ? tmp : c;
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
        // increase sequence number by the size of the packets
               int flags)
{
  if (!socket->can_write) {
      LOG_ERROR("Writing has been disabled for this socket, either close it or initiate a new connection");
      return -1;
    }

  // set timeout for recvfrom
  struct timeval timeout = {0, MICROTCP_ACK_TIMEOUT_US};

  if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, 
              &timeout, sizeof(struct timeval)) == -1) {
      perror(" Error setting timeout ");
  }

  size_t starting_sq = socket->seq_number;  // used for calculating which part to
                                            // retransmit

  void* data_start = (void*)buffer;         // used to point at the start of the segment
                                            // of data we will send this "round"
  size_t remaining_bytes = length;
  size_t data_sent = 0;                     // how many bytes we have sent so far
  size_t bytes_to_send;                     
  int chunks;

  while (data_sent < length) {
      bytes_to_send = length; // no flow or congestion control for now so we just vibe
      chunks = bytes_to_send / MICROTCP_MSS;

      for (int i = 0; i < chunks; i++) {
          // get the slice of data we will transmit from the buffer
          void* data_chunk = malloc(MICROTCP_MSS);
          memcpy(data_chunk, data_start + (MICROTCP_MSS * i), MICROTCP_MSS);

          microtcp_packet_t* to_send = microtcp_make_pkt(socket, 
                  data_chunk, MICROTCP_MSS, 0);

          // increase sequence number by the size of the packets
          socket->seq_number += MICROTCP_MSS;

          sendto(socket->sd, to_send, HEADER_SIZE + MICROTCP_MSS, 0,
                  socket->peer_addr, socket->peer_addr_len);
      }
        
      // if we have any leftover bytes to send send them on their own
      if ((bytes_to_send % MICROTCP_MSS)!= 0) {
          int leftover_size = bytes_to_send - (chunks * MICROTCP_MSS);

          void* data_chunk = malloc(leftover_size);
          memcpy(data_chunk, data_start + (chunks * MICROTCP_MSS), leftover_size);

          microtcp_packet_t* to_send = microtcp_make_pkt(socket, 
                  data_chunk, leftover_size, 0);

          // increase sequence number by the size of the packets
          socket->seq_number += leftover_size;

          sendto(socket->sd, to_send, HEADER_SIZE + leftover_size, 0,
                  socket->peer_addr, socket->peer_addr_len);

          chunks += 1;
      }

      // we have sent all of our data, time to wait for the ACKs
      int num_dup_acks = 0;
      size_t last_ack_recvd = socket->seq_number; // just to ensure no accidental
                                                  // duplcate ACKs

      for (int i = 0; i < chunks; i++) {
          microtcp_packet_t* recvd = malloc(HEADER_SIZE);

          int res = recvfrom(socket->sd, recvd, HEADER_SIZE, 
                  0, NULL, NULL);

          if (recvd->header.ack_number == last_ack_recvd) {
              num_dup_acks += 1;
          }

          last_ack_recvd = recvd->header.ack_number;


          

          // the data has been received sucessfully, move the data pointer forward
          if (i + 1 < chunks) {
              // we know that the chunks before the last must have a size
              // of MICROTCP_MSS
              data_start += MICROTCP_MSS;
          } else if (i + 1 == chunks) {
              // for the last chunk, this ensures that the pointer will be 
              // incremented the correct amount whether the chunk has a length
              // of MICROTCP_MSS or the remainder 
              data_start += bytes_to_send - (i * MICROTCP_MSS);
          }
      }

      // everything was sent sucessfully, decrease the total remaining data and 
      // go agane
      remaining_bytes -= bytes_to_send;
      data_sent += bytes_to_send;
  }


  
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
    if (socket->can_read == false) {
      LOG_ERROR("Reading has been disabled for this socket, either close it or initiate a new connection");
      return -1;
    }

    /* ALLOCATE MEMORY FOR HEADER */
    microtcp_packet_t* data_in = malloc(sizeof(char) * (MICROTCP_MSS + sizeof(microtcp_header_t)));
    int data_len = sizeof(char) * MICROTCP_MSS;


wait_for_packet:


    /* RECEIVE PACKET */
    if(recvfrom(socket->sd, data_in, data_len,
                0, NULL, 0) == -1) 
    {
        LOG_ERROR("Reading incoming data from socket failed, sending a duplicate ACK");

        microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
        
        /*DUPLICATE ACK*/
        sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, socket->peer_addr_len);

        free(ack);
        goto wait_for_packet;

    }else if (!microtcp_test_checksum(data_in)) {
        /* test checksum */
       LOG_WARN("Packet checksum failed, sending a duplicate ACK");

       microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
        
        /*DUPLICATE ACK*/
        sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, socket->peer_addr_len);

        free(ack);

       goto wait_for_packet;
    }

    LOG_INFO("received packet"); /*AT THIS POINT, WE HAVE RECEIVED A PACKET WITHOUT ERRORS*/

    /* get the packet's header */
    microtcp_header_t header = data_in->header; 

    /*CHECK THE SEQUENCE NUMBER TO MAKE SURE WE GOT WHAT WE WERE WAITING FOR*/
    if(header.seq_number == socket->ack_number){
      /* send the ack */
      socket->ack_number += header.data_len;

      microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
      
      /*WE DON'T ENSURE ITS ARRIVAL HERE, ONLY RESEND IT IF SMTH GOES WRONG AND IT DOESN'T ARRIVE*/
      sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, socket->peer_addr_len);

      //THIS IS WHERE I AM GOING TO EMPTY OUT SOME SLOTS IN THE BUFFER BUT IDK HOW!!!!!!!!!!!

      free(ack);
    }else{
        microtcp_packet_t* ack = microtcp_make_pkt(socket, NULL, 0, ACK);
        
        /*DUPLICATE ACK*/
        sendto(socket->sd, ack, HEADER_SIZE, 0, socket->peer_addr, socket->peer_addr_len);

        /*if there's a gap in seq nums, save the packet for later*/
        if(header.seq_number > socket->ack_number){
          if(socket->curr_win_size > 0){
            memcpy(socket->recvbuf + socket->buf_fill_level, data_in, data_len);
            socket->buf_fill_level++;
            socket->curr_win_size--;
          }
        }

        free(ack);

       goto wait_for_packet;
    }

    if ((header.control ^ FIN) == 0) {
        if (socket->conn_role == SERVER) {
            LOG_INFO("Server received a FIN, changing connection state");
            socket->state = CLOSING_BY_PEER;
        }

        return -1;
    }
    
    goto wait_for_packet;
}

