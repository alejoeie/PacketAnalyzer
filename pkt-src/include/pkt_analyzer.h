#ifndef PACKET_ANALYZER_H
#define PACKET_ANALYZER_H

typedef enum {
    PACKET_ANALYZER_RES_OK,
    PACKET_ANALYZER_RES_FAIL,
    PACKET_ANALYZER_RES_NONE,
    PACKET_ANALYZER_MAX
}packet_parser_result_e;

packet_parser_result_e packet_parser_retrieve_pkt_data(int unix_cmd, char* cmd);

#endif