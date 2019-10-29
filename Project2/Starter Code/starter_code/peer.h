//
// Created by eleven on 18-11-19.
//

#ifndef STARTER_CODE_PEER_H
#define STARTER_CODE_PEER_H

#define BUFLEN      1500
#define HEADERLEN   16
#define DATALEN     BUFLEN-HEADERLEN

#include "bt_parse.h"
#include "sha.h"
#include "packet.h"
#include "queue.h"

typedef struct chunk_s{
    int id;
    uint8_t  hash[SHA1_HASH_SIZE];
    char *data;
    int cur_size;
    queue_t *providers;
}chunk_t;

//typedef struct peer_s{
//    int num_chunk;
//    int num_need;
//    chunk_t* chunks;
//    char get_chunk_file[BT_FILENAME_LEN];
//}peer_t;


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
