//
// Created by eleven on 18-11-19.
//

#ifndef STARTER_CODE_PEER_H
#define STARTER_CODE_PEER_H

#define BUFLEN      1500
#define HEADERLEN   16
#define DATALEN     BUFLEN-HEADERLEN
typedef struct header_s {
    short magic_num;
    char version;
    char packet_type;
    short header_len;
    short packet_len;
    u_int seq_num;
    u_int ack_num;
}header_t;

typedef struct data_packet {
    header_t header;
    char data[DATALEN];
}data_packet_t;




#endif //STARTER_CODE_PEER_H
