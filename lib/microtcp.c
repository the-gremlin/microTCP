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

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
  /* Your code here */
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

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len)
{
  /* Your code here */
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{

}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len)
{
  /* Your code here */
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
         
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
  /* Your code here */
}
