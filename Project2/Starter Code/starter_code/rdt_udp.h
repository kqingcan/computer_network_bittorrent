//
// Created by eleven on 18-11-20.
//

#ifndef STARTER_CODE_RDT_UDP_H
#define STARTER_CODE_RDT_UDP_H

#include "bt_parse.h"
#include "peer.h"
#include "queue.h"
#include <time.h>
#define WINDOW_SIZE 8

typedef struct upload_task_s {
    bt_peer_t * receiver;
    queue_t * send_packet_queue;//排队等待发送的数据包，包括已发送未确认和未发送
    int wait_ack_num;  //已发送但未确认包的数量
    int window_size;
    int ssthresh;
    int wait_time;
    time_t start;
    time_t  end;
}upload_task_t;

typedef struct download_task_s{
    bt_peer_t * provider;
    queue_t * get_queue;
    queue_t * get_chunks;
    time_t start;
    time_t end;
    int expect_num;

}download_task_t;

void init_upload_task(upload_task_t * upload_task, bt_peer_t *receiver);
void init_download_task(download_task_t * download_task, bt_peer_t *provider);
void add_upload_packet(upload_task_t * upload_task, data_packet_t *packet);
void add_download_chunks(download_task_t * download_task, chunk_t *chunk);
void rdt_send(upload_task_t *upload_task, int sock, data_packet_t *packet, struct sockaddr* to );
void rdt_rcv(download_task_t *download_task, data_packet_t *rcv_packet);
#endif //STARTER_CODE_RDT_UDP_H
