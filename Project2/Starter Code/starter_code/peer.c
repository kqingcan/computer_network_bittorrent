/*
 * peer.c
 * 
 * Modified from CMU 15-441,
 * Original Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *                   Dave Andersen
 * 
 * Class: Computer Network (Autumn 2018)
 * id: 16302010033
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"


#include "peer.h"
#include "chunk.h"
#include "queue.h"
#include "rdt_udp.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define CHUNK_SIZE ( 1<< 19)
queue_t *has_chunks;
chunk_t *get_chunks;
queue_t *master_chunks;
char data_file_name[FILENAME_MAX];
int get_chunk_num;
bt_config_t config;
int sock;
//struct sockaddr_in *gfrom;
//socklen_t *gfromlen;
struct sockaddr_in from;
socklen_t fromlen;
void init_has_chunks(char* has_chunk_file);


void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
 // bt_config_t config;

  bt_init(&config, argc, argv);

  DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
  config.identity = 1; // your student number here
  strcpy(config.chunk_file, "chunkfile");
  strcpy(config.has_chunk_file, "haschunks");
#endif

  bt_parse_command_line(&config);

#ifdef DEBUG
  if (debug & DEBUG_INIT) {
    bt_dump_config(&config);
  }
#endif
  
  peer_run(&config);
  return 0;
}

//根据has_chunk_file初始化自己拥有的chunks
void init_has_chunks(char* has_chunk_file){
    #define BUF_SIZE 60
    FILE* file_temp = fopen(has_chunk_file,"r");
    char one_temp_buf[BUF_SIZE];
    char hash_buf[SHA1_HASH_SIZE*2];

    has_chunks = queue_init();
    while (fgets(one_temp_buf, BUF_SIZE, file_temp)){
        chunk_t* chunk_temp = malloc(sizeof(chunk_t));
        sscanf(one_temp_buf, "%d %s", &(chunk_temp->id),hash_buf);
        hex2binary(hash_buf,SHA1_HASH_SIZE*2,chunk_temp->hash);
        enqueue(has_chunks, (void *)chunk_temp);

        memset(one_temp_buf,0,BUF_SIZE);
        memset(hash_buf,0,SHA1_HASH_SIZE*2);
    }
    fclose(file_temp);
}

//初始化master_chunks方便根据hash值来获得文件位置的偏移量
void init_master_chunks(){
    char *master_file_temp = config.chunk_file;
    FILE *file_temp = fopen(master_file_temp,"r");
    char one_temp_buf[255];
    int id=0;

    char hash_buf[SHA1_HASH_SIZE*2];
    uint8_t hash[SHA1_HASH_SIZE];
    master_chunks = queue_init();

    fgets(one_temp_buf,255, file_temp);
    sscanf(one_temp_buf,"File: %s\n", data_file_name);
    fgets(one_temp_buf,BUF_SIZE, file_temp);// chunks:行
    while (fgets(one_temp_buf,255, file_temp) !=NULL){
        sscanf(one_temp_buf,"%d %s \n", &id,hash_buf);
        hex2binary(hash_buf,SHA1_HASH_SIZE*2, hash);
        chunk_t *chunk = malloc(sizeof(chunk_t));
        chunk->id = id;
        memcpy(chunk->hash,hash,SHA1_HASH_SIZE);
        enqueue(master_chunks,chunk);
    }
}

void init_get_chunks(char* get_chunk_file){
    FILE* file_temp = fopen(get_chunk_file,"r");
    char one_temp_buf[BUF_SIZE];
    char hash_buf[SHA1_HASH_SIZE*2];
    int chunk_num = 0;


    while (fgets(one_temp_buf,BUF_SIZE,file_temp)){
        chunk_num++;
    }
    get_chunk_num = chunk_num;
    get_chunks = malloc(sizeof(chunk_t) * chunk_num);

    fseek(file_temp,0,SEEK_SET);

    int i = 0;
    while (fgets(one_temp_buf, BUF_SIZE, file_temp)){

        sscanf(one_temp_buf, "%d %s", &(get_chunks[i].id),hash_buf);
        hex2binary(hash_buf,SHA1_HASH_SIZE*2,get_chunks[i].hash);
        memset(one_temp_buf,0,BUF_SIZE);
        memset(hash_buf,0,SHA1_HASH_SIZE*2);
        get_chunks[i].providers = queue_init();
        get_chunks[i].cur_size = 0;
        get_chunks[i].data = malloc(sizeof(char)*512*1024);
        i++;
    }
    fclose(file_temp);
}

// 判断他所请求的chunk该peer是否拥有
int check_if_have(uint8_t *hash_start){
    node_t* node;
    chunk_t* chunk_temp;
    if (has_chunks->n==0){
        return 0;
    }
    node = has_chunks->head;
    int num = has_chunks->n;
    for (int i = 0; i < num ; ++i) {
        chunk_temp = (chunk_t *)node->data;
        if (memcmp(hash_start, chunk_temp->hash, SHA1_HASH_SIZE)){
            node = node->next;
            continue;
        }
        return 1;
    }
    return 0;
}

// host包向net包转换
void host_to_net_transfer(data_packet_t * packet){
    packet->header.magic_num = htons(packet->header.magic_num);
    packet->header.header_len = htons(packet->header.header_len);
    packet->header.packet_len = htons(packet->header.packet_len);
    packet->header.seq_num = htonl(packet->header.seq_num);
    packet->header.ack_num = htonl(packet->header.ack_num);
}

// net包向host包转换
void net_to_host_transfer(data_packet_t * packet){
    packet->header.magic_num = ntohs(packet->header.magic_num);
    packet->header.header_len = ntohs(packet->header.header_len);
    packet->header.packet_len = ntohs(packet->header.packet_len);
    packet->header.seq_num = ntohl(packet->header.seq_num);
    packet->header.ack_num = ntohl(packet->header.ack_num);
}
// 储存收到的数据包到chunks里面
void save_data_to_chunk(chunk_t *chunk, data_packet_t *packet){
    int data_len = packet->header.packet_len - packet->header.header_len;
    memcpy(chunk->data+chunk->cur_size, packet->data, data_len);
    chunk->cur_size += data_len;
}

//判断一个chunk的数据是否正确地传输完整,未传完返回0，传完返回1，内容出错返回-1；
int is_chunk_finished(chunk_t *chunk){
    int cur_szie = chunk->cur_size;
    if (cur_szie != BT_CHUNK_SIZE){
        printf("Not finished yet, cur_size = %.5f kb\n", (float)(cur_szie/1024));
        return 0;
    }
    uint8_t hash[SHA1_HASH_SIZE];
    shahash((uint8_t*)chunk->data,cur_szie, hash);
    if (memcmp(hash,chunk->hash,SHA1_HASH_SIZE)==0){
        return 1;
    } else{
        return -1;
    }
}

// 合并get_chunk_file中的数据块
void merge_data_to_file(){
    FILE * out_file;
    int chunk_num = get_chunk_num;
    chunk_t *chunks_temp = get_chunks;

    out_file = fopen(config.output_file,"w");
    for (int i = 0; i <chunk_num ; ++i) {
        fwrite(chunks_temp[i].data,1,BT_CHUNK_SIZE,out_file);
    }
    printf("out to file finished");
    fclose(out_file);
}

//用来生成packet的头部信息
data_packet_t* generate_packet_header(short packet_len, short packet_type, u_int seq_num, u_int ack_num){
    data_packet_t *data_packet_temp = (data_packet_t *)malloc(sizeof(data_packet_t));
    data_packet_temp->header.magic_num = 15441;
    data_packet_temp->header.version = 1;
    data_packet_temp->header.header_len = HEADERLEN;
    data_packet_temp->header.packet_len = packet_len;
    data_packet_temp->header.packet_type = packet_type;
    data_packet_temp->header.seq_num = seq_num;
    data_packet_temp->header.ack_num = ack_num;
    return data_packet_temp;

}

//通过chunks的hash值来构建数据包,并加入到upload_task的send_queue里
void add_packet_to_upload_task(upload_task_t *upload_task, uint8_t *hash){

    node_t* node;
    chunk_t* chunk_temp;
    char *data_src;
    int data_fd;
    struct stat statbuf;
    data_fd = open(data_file_name,O_RDONLY);
    fstat(data_fd,&statbuf);
    data_src = mmap(0, statbuf.st_size+1024, PROT_READ,MAP_SHARED, data_fd, 0);
    close(data_fd);
    int id=0;
    node = master_chunks->head;
    int num = master_chunks->n;
    printf("num: %d\n",num);
    for (int i = 0; i <num ; ++i) {
        printf("i: %d\n",i);
        chunk_temp = (chunk_t *)node->data;
        if (memcmp(hash, chunk_temp->hash,SHA1_HASH_SIZE)==0){
            id = chunk_temp->id;
            for (int j = 0; j <512 ; ++j) {
                data_packet_t *data_packet_temp = generate_packet_header(1040, 3, j+1,0 );
                if (j!=511|| i!=num-1){
                    memcpy(data_packet_temp->data,(data_src+id*CHUNK_SIZE+j*1024), DATALEN);
                }
                enqueue(upload_task->send_packet_queue,data_packet_temp);
            }
            munmap(data_src,statbuf.st_size);
            break;
        }
        node =node->next;
    }

}


//当开始发送数据包时，开始一个新的线程来控制一段时间未收到ack时的重发操作。
void* timeout(void *upload_task){
    printf("timeout:\n");
    upload_task_t *upload_task1 = (upload_task_t *)upload_task;
    pthread_detach(pthread_self());
    int j =0;
    while (1) {
        upload_task1->end = time(NULL);
        if (difftime(upload_task1->end, upload_task1->start) >=1) {
            if (upload_task1->window_size>=4){
                upload_task1->ssthresh = upload_task1->window_size/2;

            } else{
                upload_task1->ssthresh = 2;
            }
            upload_task1->window_size  =1;
            printf("j: %d\n",++j);
            int window_size = upload_task1->window_size;

            node_t *node1;
            node1 = upload_task1->send_packet_queue->head;
            upload_task1->wait_ack_num = 0;
            //发送前window_size的数据包。
            for (int i = 0; i < window_size; ++i) {
                upload_task1->start = time(NULL);
                data_packet_t *data_packet = (data_packet_t *) node1->data;

                host_to_net_transfer(data_packet);

                spiffy_sendto(sock, data_packet, data_packet->header.packet_len, 0, (struct sockaddr *) &from, fromlen);
                upload_task1->wait_ack_num +=1;
                net_to_host_transfer(data_packet);
                if (memcmp(upload_task1->send_packet_queue->tail, node1, 1040) == 0) {//TODO 可能会有问题
                    printf("quit\n");
                    break;
                } else {
                    node1 = node1->next;
                }
            }
            if (upload_task1->send_packet_queue->head==NULL){
                printf("time thread exit()\n");
                pthread_exit(NULL);
            }


        }
    }
}


void* resend_WHOHAS(download_task_t *download_task){
    char request_data[BUFLEN];
    int data_len = 4;
    int req_num = 0;
    node_t *chunk_node = download_task->get_chunks->head;
    while (chunk_node != NULL){
        chunk_t *temp_chunk = (chunk_t *) chunk_node->data;
        memcpy(request_data+data_len,temp_chunk->hash,SHA1_HASH_SIZE);
        data_len +=SHA1_HASH_SIZE;
        req_num +=1;
    }
    request_data[0] = req_num;
    data_packet_t *whohas_packet = generate_packet_header(HEADERLEN+data_len,0,0,0);
    memcpy(whohas_packet->data,request_data,data_len);

    int packet_len = whohas_packet->header.packet_len;
    host_to_net_transfer(whohas_packet);
    char str[20];
    struct bt_peer_s* peer = config.peers;

    while(peer != NULL) {
        struct sockaddr *peer_addr = (struct sockaddr *) &peer->addr;
        if (peer->id != config.identity) {
            spiffy_sendto(sock, whohas_packet, packet_len, 0, peer_addr, sizeof(peer_addr));
        }
        peer = peer->next;
    }
    net_to_host_transfer(whohas_packet);

}

//判断正在连接的peer是否还存在，如果不存在就换下一个提供者
void* is_disconnect(void *download_task){
    download_task_t *download_task1 = (download_task_t *)download_task;
    pthread_detach(pthread_self());
    while (1){
        download_task1->end = time(NULL);
        if (difftime(download_task1->end,download_task1->start)>=10){
            printf("one peer exit! change to another\n");
            node_t *node = download_task1->get_chunks->head;
            chunk_t *temp_chunk = (chunk_t *)node->data;
            node_t *before = temp_chunk->providers->head;
            bt_peer_t *before_peer = (bt_peer_t *)before->data;
            printf("n: %d \n",temp_chunk->providers->n);
            printf("before id : %d \n",before_peer->id);
            dequeue(temp_chunk->providers);
            node_t *pvd = temp_chunk->providers->head;
            //判断chunk是否还有剩余的provider，如果有就向剩余的provider发送GET，如果没有就再向全网发送whohas包。
            if (pvd == NULL){
                resend_WHOHAS(download_task1);
                pthread_exit(NULL);
            } else{
                bt_peer_t *provider = (bt_peer_t *)pvd->data;
                data_packet_t *get_pkt = generate_packet_header(HEADERLEN+SHA1_HASH_SIZE,2,0,0);
                memcpy(get_pkt->data,temp_chunk->hash, SHA1_HASH_SIZE);
                host_to_net_transfer(get_pkt);
                int packet_size = get_pkt->header.packet_len;
                spiffy_sendto(sock, get_pkt, packet_size, 0, (struct sockaddr *) &(provider->addr), fromlen);
                printf("send GET to %d\n",provider->id);
                download_task1->start = time(NULL);
            }

        }
    }
}

void process_inbound_udp(int sock) {
//  struct sockaddr_in from;
//  socklen_t fromlen;
  char buf[BUFLEN];
  data_packet_t* res_pkt;
  upload_task_t  upload_task;
  download_task_t  download_task;
  time_t start,currrent_time;
  start = time(NULL);
  currrent_time = time(NULL);
  int last_ack = 0;
  int duplicate_count = 0;
  pthread_t tid;
  init_download_task(&download_task, NULL);
  int has_sent = 0;
  for (int l = 0; l <get_chunk_num ; ++l) {
      enqueue(download_task.get_chunks,&get_chunks[l]);
  }

  FILE *problem_file;
  problem_file = fopen("problem2_peer.txt","w");


  fromlen = sizeof(from);

  int data_pkt_num = 0;
  while (spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen) !=-1){
      net_to_host_transfer((data_packet_t*)buf);
      data_packet_t* packet = (data_packet_t*) buf;
      header_t* header = &packet->header;
      int packet_type = header->packet_type;
      bt_peer_t* peer = bt_peer_get(&config,(struct sockaddr *)&from);
      switch (packet_type){
          case 0:{// WHOHAS
              printf("receive WHOHAS packet!\n");
              int req_num;
              int data_len = 4;
              int have_num = 0;
              char result_data[BUFLEN];
              uint8_t *hash_start;


              req_num = packet->data[0]; //请求的块的数量 1个byte
              hash_start = (uint8_t *)(packet->data+4); // chunk的hash值开始的位置
              for (int i = 0; i <req_num ; ++i) {
                  // 对于每一个请求的快，判断自己有没有
                  if (check_if_have(hash_start)){

                      have_num++;
                      memcpy(result_data+data_len, hash_start, SHA1_HASH_SIZE);
                      data_len += SHA1_HASH_SIZE;
                  }
                  hash_start +=SHA1_HASH_SIZE;
              }
              if (have_num==0){
                  res_pkt = NULL;
              } else{
                  memset(result_data, 0, 4);
                  result_data[0] = have_num;
                 // printf("result_data: %s\n", result_data);
                  res_pkt = generate_packet_header(HEADERLEN+data_len, 1,0,0);
                  if (res_pkt->data !=NULL)
                      memcpy(res_pkt->data, result_data, data_len);
              }


              if (res_pkt !=NULL){
                  //TODO: 把host包转换成net包，然后发送给请求块的peer
                  int packet_size = res_pkt->header.packet_len;
                  host_to_net_transfer(res_pkt);
                  spiffy_sendto(sock, res_pkt, packet_size, 0, (struct sockaddr *) &from, fromlen);
                  net_to_host_transfer(res_pkt);
              }
              free(res_pkt);
              printf("whohas finished");
              break;
          }
          case 1:{// IHAVE
              printf("receive IHAVE packet!\n");
              if (get_chunk_num ==0){
                  break;
              }
              int have_num = packet->data[0];
              uint8_t *hash_start;
              hash_start = (uint8_t *)(packet->data+4);
              printf("have_num %d\n",have_num);
              for (int i = 0; i <have_num ; ++i) {
                  //printf("i: %d\n",i);
                  uint8_t hash[SHA1_HASH_SIZE];
                  memcpy(hash, hash_start, SHA1_HASH_SIZE);
                  for (int j = 0; j <get_chunk_num ; ++j) {
                      //printf("j: %d\n", j);
                      if (memcmp(hash,get_chunks[j].hash, SHA1_HASH_SIZE)==0){

                          //将要下载的包的chunk信息存在download_task里面
                          enqueue(get_chunks[j].providers,peer);
//                          enqueue(download_task.get_chunks,&get_chunks[i]);
                          download_task.provider = peer;
//                          get_chunks[i].providers = peer;
//                          data_packet_t *get_pkt = generate_packet_header(HEADERLEN+SHA1_HASH_SIZE,2,0,0);
//                          memcpy(get_pkt->data,hash, SHA1_HASH_SIZE);
//                          host_to_net_transfer(get_pkt);
//                          enqueue(download_task.get_queue,get_pkt);
                      }
                  }
                  hash_start += SHA1_HASH_SIZE;
              }
              printf("line 374\n");
              if (has_sent){
                  break;
              }
              node_t *node;
              node = download_task.get_chunks->head;
              if (node !=NULL){
                  chunk_t *get_chunk = (chunk_t *)node->data;
                  bt_peer_t *provider = (bt_peer_t *)get_chunk->providers->head->data;
                  data_packet_t *get_pkt = generate_packet_header(HEADERLEN+SHA1_HASH_SIZE,2,0,0);
                  memcpy(get_pkt->data,get_chunk->hash, SHA1_HASH_SIZE);
                  host_to_net_transfer(get_pkt);
                  int packet_size = get_pkt->header.packet_len;
                  spiffy_sendto(sock, get_pkt, packet_size, 0, (struct sockaddr *) &(provider->addr), fromlen);
                  has_sent = 1;
                  download_task.start = time(NULL);
                  pthread_create(&tid,NULL,is_disconnect, &download_task);
              }
              break;
          }
          case 2:{// GET
              printf("receive GET packet!\n");
              init_upload_task(&upload_task, peer);
              uint8_t hash[SHA1_HASH_SIZE];
              memcpy(hash, packet->data, SHA1_HASH_SIZE);
              //从master_chunk_file里找到相应hash值对应的文件数据在内存中的位置，并创建数据包加入到待发送队列中
              add_packet_to_upload_task(&upload_task,hash);
              int window_size = upload_task.window_size;
              node_t *node;
              node = upload_task.send_packet_queue->head;
              //发送前window_size的数据包。
              for (int i = 0; i <window_size ; ++i) {
                  upload_task.start = time(NULL);
                  data_packet_t *data_packet = (data_packet_t *)node->data;
                  host_to_net_transfer(data_packet);
                  spiffy_sendto(sock,data_packet, data_packet->header.packet_len,0,(struct sockaddr *) &from, fromlen);
                  net_to_host_transfer(data_packet);
                  upload_task.wait_ack_num +=1;
                  if (memcmp(upload_task.send_packet_queue->tail,node,1040)==0){//TODO 可能会有问题
                      break;
                  } else{
                      node =node->next;
                  }
              }
              //创建新的线程来控制时间
              pthread_create(&tid,NULL,timeout, &upload_task);
              printf("line 410\n");
              break;
          }
          case 3:{// DATA
              data_pkt_num++;
              printf("receive DATA packet %d!\n",data_pkt_num);
              download_task.start = time(NULL);
              //TODO: 可能出现download_task未被初始化的情况
              printf("expect_num: %d\n", download_task.expect_num);
              printf("seq_num: %d\n", ((data_packet_t*)buf)->header.seq_num);

              if (download_task.expect_num == ((data_packet_t*)buf)->header.seq_num){

                  //TODO: 将数据储存起来
                  save_data_to_chunk((chunk_t*)download_task.get_chunks->head->data, packet);
                  printf("save %d\n", packet->header.seq_num);
                  // 返回ACK包
                  data_packet_t * ack_packet = generate_packet_header(HEADERLEN,4,0,packet->header.seq_num);
                  //TODO: expect_num范围可能有一定的限制
                  download_task.expect_num++;
                  host_to_net_transfer(ack_packet);
                  spiffy_sendto(sock, ack_packet, HEADERLEN, 0, (struct sockaddr *) &from, fromlen);
                  free(ack_packet);
                  int  if_finished = is_chunk_finished((chunk_t*)download_task.get_chunks->head->data);
                  printf("is_finished == %d\n",if_finished);
                  if (if_finished==1){
                      printf("Finished \n");
                      dequeue(download_task.get_chunks);
                      dequeue(download_task.get_queue);
                      if (download_task.get_chunks->head ==NULL){
                          printf("GOT : %s\n", config.chunk_file);
                          //合并这些chunks；
                          merge_data_to_file();

                      } else{
                          printf("line 531\n");
                          download_task.expect_num = 1;
                          node_t *node = download_task.get_chunks->head;
                          chunk_t *get_chunk = (chunk_t *)node->data;
                          bt_peer_t *provider = (bt_peer_t *)get_chunk->providers->head->data;
                          data_packet_t *get_pkt = generate_packet_header(HEADERLEN+SHA1_HASH_SIZE,2,0,0);
                          memcpy(get_pkt->data,get_chunk->hash, SHA1_HASH_SIZE);
                          host_to_net_transfer(get_pkt);
                          int packet_size = get_pkt->header.packet_len;
                          spiffy_sendto(sock, get_pkt, packet_size, 0, (struct sockaddr *) &(provider->addr), fromlen);
                          printf("GET ANOTHER\n");
                      }
                  }
              } else{
                  data_packet_t * ack_packet = generate_packet_header(HEADERLEN,4, 0, download_task.expect_num-1);
                  host_to_net_transfer(ack_packet);
                  spiffy_sendto(sock, ack_packet, HEADERLEN, 0, (struct sockaddr *) &from, fromlen);
              }
              break;
          }
          case 4:{// ACK
              int id = peer->id;
              currrent_time = time(NULL);
              int diff_time = difftime(currrent_time,start);
              int window_size_temp = upload_task.window_size;
//              printf("window_szie: %d\n",window_size_temp);
              printf("f%d    %d    %d\n",id,diff_time,window_size_temp);
              fprintf(problem_file,"f%d    %ds    %d\n",id, diff_time, window_size_temp);
              printf("receive ACK packet!\n");
              int ack_index = 0;
              int match = 0;
              node_t *node;
              node = upload_task.send_packet_queue->head;
              int ack = packet->header.ack_num;
              if (ack ==last_ack){
                  duplicate_count+=1;
              } else{
                  duplicate_count=0;
              }
              last_ack =ack;
              if (duplicate_count >=3){//视为expect_num+1的包丢失
                  duplicate_count =0;
                  if (upload_task.window_size>=4){
                      upload_task.ssthresh = upload_task.window_size/2;

                  } else{
                      upload_task.ssthresh = 2;
                  }
                  upload_task.window_size  =1;

                  int window_size = upload_task.window_size;
                  node_t *node1;
                  node1 = upload_task.send_packet_queue->head;
                  //发送前window_size的数据包。
                  for (int i = 0; i < window_size; ++i) {
                      upload_task.start = time(NULL);
                      data_packet_t *data_packet = (data_packet_t *) node1->data;
                      host_to_net_transfer(data_packet);
                      spiffy_sendto(sock, data_packet, data_packet->header.packet_len, 0,
                                    (struct sockaddr *) &from,
                                    fromlen);
                      net_to_host_transfer(data_packet);
                      if (memcmp(upload_task.send_packet_queue->tail, node1, 1040) == 0) {//TODO 可能会有问题
                          break;
                      } else {
                          node1 = node1->next;
                      }
                  }
                  break;
              }
              printf("ack: %d\n",ack);
              for (int i = 0; i <upload_task.wait_ack_num ; ++i) {
                  if (node==NULL) break;
                  data_packet_t *data_packet_temp = (data_packet_t *)node->data;
                  int seq_num = data_packet_temp->header.seq_num;
                 // printf("seq_num: %d\n",seq_num);
                  ack_index++;
                  if(ack == seq_num){
                      match =1;
                      break;
                  }
                  if(node != upload_task.send_packet_queue->tail){
                      node = node->next;
                  } else{
                      break;
                  }
              }
              //printf("ack_index: %d\n",ack_index);
              if (match){
                  printf("match\n");
                  for (int i = 0; i <ack_index ; ++i) {
                      dequeue(upload_task.send_packet_queue);
                      upload_task.wait_ack_num --;
                  }
              }
              int num_send = 0;
              //判断是采用慢启动还是拥塞避免
              if (upload_task.window_size >= upload_task.ssthresh){//拥塞避免
                  num_send = 1;
              } else{//慢启动
                  num_send = 2;
              }
              printf("n : %d wait  :  %d \n",upload_task.send_packet_queue->n,upload_task.wait_ack_num);
              if (upload_task.send_packet_queue->n == upload_task.wait_ack_num){
                  printf("break\n");
                  break;
              }
//              printf("line 611\n");
              node = upload_task.send_packet_queue->head;
              for (int j = 0; j <upload_task.wait_ack_num ; ++j) {
                  if (node ==NULL) break;
                  node = node->next;
              }
              if (node ==NULL) break;
              for (int k = 0; k <num_send ; ++k) {
                  upload_task.start =time(NULL);
                  data_packet_t *data_packet = (data_packet_t *)node->data;
                  host_to_net_transfer(data_packet);
                  spiffy_sendto(sock,data_packet,data_packet->header.packet_len,0,(struct sockaddr *) &from, fromlen);
                  net_to_host_transfer(data_packet);
                  upload_task.window_size++;
                  upload_task.wait_ack_num++;
              }

              break;
          }
          case 5:{// DENIED

              break;
          }
          default:{
              break;
          }
      }
  }

    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
	 "Incoming message from %s:%d\n%s\n\n", 
	 inet_ntoa(from.sin_addr),
	 ntohs(from.sin_port),
	 buf);
}

void process_get(char *chunkfile, char *outputfile) {

  printf("mypeer: PROCESS GET SKELETON CODE CALLED.  Fill me in!  (%s, %s)\n",
          chunkfile, outputfile);
  //TODO: 读取chunkfile，得到要请求的文件的chunk的hash值，生成一个请求chunk的packet队列
  init_get_chunks(chunkfile);
  printf("output_file: %s", config.output_file);
  memcpy(config.output_file,outputfile,BT_FILENAME_LEN);
  FILE *chunk_file = fopen(chunkfile,"r");
  assert(chunk_file !=NULL);
  char one_line[BUF_SIZE];
  char hash_buf[SHA1_HASH_SIZE*2];
  int req_num = 0;
  int data_len = 4;
  char request_data[BUFLEN];
  uint8_t hash[SHA1_HASH_SIZE];
  int *id;
  id = malloc(sizeof(int));
  //读取每一行，并把要请求的chunk都加到请求的包里;
  printf("chunkfile: %s \n", chunkfile);
  int c =0;
  while (fgets(one_line, BUF_SIZE, chunk_file)){
      printf("time: %d\n", c);
      sscanf(one_line, "%d %s", id, hash_buf);
      hex2binary(hash_buf,SHA1_HASH_SIZE*2, hash);
      memcpy(request_data+data_len, hash, SHA1_HASH_SIZE);
      memset(hash,0,SHA1_HASH_SIZE);
      data_len  += SHA1_HASH_SIZE;
      req_num++;
      c++;
  }
  request_data[0] = req_num;
  data_packet_t *whohas_packet = generate_packet_header(HEADERLEN+data_len,0,0,0);
  memcpy(whohas_packet->data,request_data,data_len);

  int packet_len = whohas_packet->header.packet_len;
  host_to_net_transfer(whohas_packet);
  char str[20];
  struct bt_peer_s* peer = config.peers;


  while(peer != NULL) {
      struct sockaddr *peer_addr = (struct sockaddr *) &peer->addr;
      if (peer->id != config.identity) {
          spiffy_sendto(sock, whohas_packet, packet_len, 0, peer_addr, sizeof(peer_addr));
      }
      peer = peer->next;
  }
  net_to_host_transfer(whohas_packet);


}

void handle_user_input(char *line, void *cbdata) {
    printf("handle_user_input......\n");
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));

    if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
    if (strlen(outf) > 0) {
      process_get(chunkf, outf);
    }
  }
}


void peer_run(bt_config_t *config) {

  struct sockaddr_in myaddr;
  fd_set readfds;
  struct user_iobuf *userbuf;
  struct timeval tv;

  if ((userbuf = create_userbuf()) == NULL) {
    perror("peer_run could not allocate userbuf");
    exit(-1);
  }
  
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
    perror("peer_run could not create socket");
    exit(-1);
  }
  
  bzero(&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(config->myport);
  
  if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
    perror("peer_run could not bind socket");
    exit(-1);
  }

  
  spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

  init_has_chunks(config->has_chunk_file);
  printf("master_file: %s\n", config->chunk_file);
  init_master_chunks();

  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);

    tv.tv_sec = 10; /* Wait up to 10 seconds. */
    tv.tv_usec = 0;
    nfds = select(sock+1, &readfds, NULL, NULL, &tv);
//    printf("ntds: %d\n", nfds);
    if (nfds > 0) {
        printf("1\n");
        if (FD_ISSET(sock, &readfds)) {
	        process_inbound_udp(sock);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
	        process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused");
      }

    } else{
        printf("2\n");
    }
  }
}
