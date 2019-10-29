//
// Created by eleven on 18-11-20.
//

#include <stdio.h>
#include "rdt_udp.h"



void init_upload_task(upload_task_t * upload_task, bt_peer_t *receiver){
    upload_task->window_size = 1;
    upload_task->ssthresh = 64;
    upload_task->receiver = receiver;
    upload_task->wait_time = 10;
    upload_task->wait_ack_num = 0;
    upload_task->send_packet_queue = queue_init();
    upload_task->start = time(NULL);
    upload_task->end = time(NULL);
}


void init_download_task(download_task_t * download_task, bt_peer_t *provider){
    download_task->provider=provider;
    download_task->expect_num = 1;
    printf("init expect_num: %d\n",download_task->expect_num);
    download_task->get_chunks = queue_init();
    download_task->get_queue = queue_init();
    download_task->start = time(NULL);
    download_task->end = time(NULL);
}


void add_upload_packet(upload_task_t * upload_task, data_packet_t *packet){
        enqueue(upload_task->send_packet_queue,packet);
}
void add_download_chunks(download_task_t * download_task, chunk_t *chunk){
    enqueue(download_task->get_chunks,chunk);
}

void rdt_send(upload_task_t *upload_task, int sock, data_packet_t *packet, struct sockaddr* to ){
//    enqueue(upload_task->send_packet_queue,packet);

}
