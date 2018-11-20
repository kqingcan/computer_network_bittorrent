/*
 * peer.c
 * 
 * Modified from CMU 15-441,
 * Original Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *                   Dave Andersen
 * 
 * Class: Computer Network (Autumn 2018)
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

queue_t *has_chunks;
chunk_t *get_chunks;
int get_chunk_num;
bt_config_t config;
int sock;
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

        sscanf(one_temp_buf, "%d %s", &(get_chunks[i]->id),hash_buf);
        hex2binary(hash_buf,SHA1_HASH_SIZE*2,get_chunks[i]->hash);
        memset(one_temp_buf,0,BUF_SIZE);
        memset(hash_buf,0,SHA1_HASH_SIZE*2);
        get_chunks[i].provider = NULL;
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

void process_inbound_udp(int sock) {
  struct sockaddr_in from;
  socklen_t fromlen;
  char buf[BUFLEN];
  data_packet_t* res_pkt;
  

  fromlen = sizeof(from);
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
                  printf("result_data: %s\n", result_data);
                  res_pkt = (data_packet_t *)malloc(sizeof(data_packet_t));
                  res_pkt->header.magic_num = 15441;
                  res_pkt->header.version = 1;
                  res_pkt->header.header_len = HEADERLEN;
                  res_pkt->header.packet_len = HEADERLEN + data_len;
                  res_pkt->header.seq_num = 0;
                  res_pkt->header.ack_num = 0;
                  res_pkt->header.packet_type = 1;
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

              for (int i = 0; i <have_num ; ++i) {
                  uint8_t hash[SHA1_HASH_SIZE];
                  memcpy(hash, hash_start, SHA1_HASH_SIZE);
                  for (int j = 0; j <get_chunk_num ; ++j) {
                      if (get_chunks[i].provider ==NULL &&
                          memcmp(hash,get_chunks[i].hash, SHA1_HASH_SIZE)==0){
                          get_chunks[i].provider = peer;
                          res_pkt = (data_packet_t *)malloc(sizeof(data_packet_t));
                          res_pkt->header.magic_num = 15441;
                          res_pkt->header.version = 1;
                          res_pkt->header.header_len = HEADERLEN;
                          res_pkt->header.packet_type = 2;
                          res_pkt->header.packet_len = HEADERLEN + SHA1_HASH_SIZE;
                          res_pkt->header.seq_num = 0;
                          res_pkt->header.ack_num = 0;
                          memcpy(res_pkt->data,hash, SHA1_HASH_SIZE);

                      } else{
                          res_pkt = NULL;
                      }
                      if (res_pkt !=NULL){
                          int packet_size = res_pkt->header.packet_len;
                          host_to_net_transfer(res_pkt);
                          spiffy_sendto(sock, res_pkt, packet_size, 0, (struct sockaddr *) &from, fromlen);
                          net_to_host_transfer(res_pkt);
                      }
                      free(res_pkt);
                  }
              }

              break;
          }
          case 2:{// GET
              printf("receive GET packet!\n");



              break;
          }
          case 3:{// DATA

              break;
          }
          case 4:{// ACK

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
  //读取每一行，并把要请求的chunk都加到请求的包里
  printf("line 230\n");
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
  printf("line 238\n");
  request_data[0] = req_num;
  data_packet_t *whohas_packet = malloc(sizeof(data_packet_t));
  whohas_packet->header.magic_num = 15441;
  whohas_packet->header.version = 1;
  whohas_packet->header.header_len = HEADERLEN;
  whohas_packet->header.packet_type = 0;
  whohas_packet->header.ack_num = 0;
  whohas_packet->header.seq_num = 0;
  whohas_packet->header.packet_len = HEADERLEN + data_len;
  memcpy(whohas_packet->data,request_data,data_len);

  int packet_len = whohas_packet->header.packet_len;
  host_to_net_transfer(whohas_packet);
  char str[20];
  struct bt_peer_s* peer = config.peers;

  printf("line 253\n");
  while(peer != NULL) {
      printf("line 255\n");
      fprintf(stderr, "ID:%d\n", peer->id);
      printf(stderr, "Port:%d\n", ntohs(peer->addr.sin_port));
      inet_ntop(AF_INET, &(peer->addr.sin_addr), str, INET_ADDRSTRLEN);
      fprintf(stderr, "IP:%s\n", str);
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

  while (1) {
    int nfds;
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sock, &readfds);

    tv.tv_sec = 10; /* Wait up to 10 seconds. */
    tv.tv_usec = 0;
    nfds = select(sock+1, &readfds, NULL, NULL, &tv);
    printf("ntds: %d\n", nfds);
    if (nfds > 0) {
        if (FD_ISSET(sock, &readfds)) {
	        process_inbound_udp(sock);
        }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
	        process_user_input(STDIN_FILENO, userbuf, handle_user_input,
			   "Currently unused");
      }
    }
  }
}
