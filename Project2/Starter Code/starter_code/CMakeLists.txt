cmake_minimum_required(VERSION 3.12)
project(starter_code)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)
include_directories(example)

add_executable(starter_code
        example/A.gif
        example/B.gif
        bt_parse.c
        bt_parse.h
        chunk.c
        chunk.h
        client.c
        debug-text.h
        debug.c
        debug.h
        debugparse.pl
        hupsim.pl
        input_buffer.c
        input_buffer.h
        make_chunks.c
        Makefile
        nodes.map
        peer.c
        server.c
        sha.c
        sha.h
        spiffy.c
        spiffy.h
        test_input_buffer.c
        topo.map peer.h queue.c rdt_udp.h rdt_udp.c packet.h)
