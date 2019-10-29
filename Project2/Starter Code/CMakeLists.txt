cmake_minimum_required(VERSION 3.12)
project(Starter_Code C)

set(CMAKE_C_STANDARD 11)

include_directories(starter_code)

add_executable(Starter_Code
        starter_code/bt_parse.c
        starter_code/bt_parse.h
        starter_code/chunk.c
        starter_code/chunk.h
        starter_code/client.c
        starter_code/debug-text.h
        starter_code/debug.c
        starter_code/debug.h
        starter_code/input_buffer.c
        starter_code/input_buffer.h
        starter_code/make_chunks.c
        starter_code/packet.h
        starter_code/peer.c
        starter_code/peer.h
        starter_code/queue.c
        starter_code/queue.h
        starter_code/rdt_udp.c
        starter_code/rdt_udp.h
        starter_code/server.c
        starter_code/sha.c
        starter_code/sha.h
        starter_code/spiffy.c
        starter_code/spiffy.h
        starter_code/test_input_buffer.c)
