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

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */
#include "../lib/microtcp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>

int
main(int argc, char **argv)
{
    
    microtcp_sock_t s = microtcp_socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in local;

    local.sin_addr.s_addr = inet_addr("127.0.0.1");
    local.sin_port = 6505;
    local.sin_family = AF_INET;

    microtcp_bind(&s, (struct sockaddr *) &local, sizeof(local));


    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(remote);

    microtcp_accept(&s, (struct sockaddr*)&remote, len);    

    int res = microtcp_recv(&s, NULL, 0, 0);

    if (res == -1) {
        microtcp_shutdown(&s, SHUT_RDWR);
    }

}
