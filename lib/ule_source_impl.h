/* -*- c++ -*- */
/* 
 * Copyright 2016,2017 Ron Economos.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_ULE_ULE_SOURCE_IMPL_H
#define INCLUDED_ULE_ULE_SOURCE_IMPL_H

#include <ule/ule_source.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include "libdvbv5/dvb-file.h"

#define TRUE 1
#define FALSE 0

#define MPEG2_PACKET_SIZE 188
#define PAYLOAD_POINTER_SIZE 1
#define SNDU_BASE_HEADER_SIZE 4

typedef struct {
    unsigned char sync_byte                   :8; /* Synchronization byte. */
    unsigned char pid_12to8                   :5; /* Program ID, bits 12:8. */
    unsigned char transport_priority          :1; /* Transport stream priority. */
    unsigned char payload_unit_start_indicator:1; /* Payload unit start indicator. */
    unsigned char transport_error_indicator   :1; /* Transport stream error indicator. */
    unsigned char pid_7to0                    :8; /* Program ID, bits 7:0. */
    unsigned char continuity_counter          :4; /* Countinuity counter. */
    unsigned char adaptation_field_control    :2; /* Transport stream Adaptation field control. */
    unsigned char transport_scrambling_control:2; /* Transport stream scrambling control. */
} TS_HEADER;

#define TS_HEADER_SIZE 4

typedef struct {
    unsigned int table_id:8;
    unsigned int section_length_h:4;
    unsigned int reserved0:2;
    unsigned int b0:1;
    unsigned int section_syntax_indicator:1;
    unsigned int section_length_l:8;
    unsigned int transport_stream_id_h:8;
    unsigned int transport_stream_id_l:8;
    unsigned int current_next_indicator:1;
    unsigned int version_number:5;
    unsigned int reserved1:2;
    unsigned int section_number:8;
    unsigned int last_section_number:8;
} PAT_HEADER;

#define PAT_HEADER_SIZE 8

typedef struct {
    unsigned int program_number_h:8;
    unsigned int program_number_l:8;
    unsigned int program_map_PID_h:5;
    unsigned int reserved2:3;
    unsigned int program_map_PID_l:8;
} PAT_ELEMENT;

#define PAT_ELEMENT_SIZE 4

typedef struct {
    unsigned int table_id:8;
    unsigned int section_length_h:4;
    unsigned int reserved0:2;
    unsigned int b0:1;
    unsigned int section_syntax_indicator:1;
    unsigned int section_length_l:8;
    unsigned int program_number_h:8;
    unsigned int program_number_l:8;
    unsigned int current_next_indicator:1;
    unsigned int version_number:5;
    unsigned int reserved1:2;
    unsigned int section_number:8;
    unsigned int last_section_number:8;
    unsigned int PCR_PID_h:5;
    unsigned int reserved2:3;
    unsigned int PCR_PID_l:8;
    unsigned int program_info_length_h:4;
    unsigned int reserved3:4;
    unsigned int program_info_length_l:8;
} PMT_HEADER;

#define PMT_HEADER_SIZE 12

typedef struct {
    unsigned int stream_type:8;
    unsigned int elementary_PID_h:5;
    unsigned int reserved0:3;
    unsigned int elementary_PID_l:8;
    unsigned int ES_info_length_h:4;
    unsigned int reserved1:4;
    unsigned int ES_info_length_l:8;
} PMT_ELEMENT;

#define PMT_ELEMENT_SIZE 5

typedef struct {
    unsigned int descriptor_tag:8;
    unsigned int descriptor_length:8;
    unsigned int component_tag:8;
} PMT_STREAM_DESCRIPTOR;

#define PMT_STREAM_DESCRIPTOR_SIZE 3

typedef struct {
    unsigned int descriptor_tag:8;
    unsigned int descriptor_length:8;
    unsigned int format_identifier_31to24:8;
    unsigned int format_identifier_23to16:8;
    unsigned int format_identifier_15to8:8;
    unsigned int format_identifier_7to0:8;
} PMT_REGISTRATION_DESCRIPTOR;

#define PMT_REGISTRATION_DESCRIPTOR_SIZE 6

typedef struct {
    unsigned int table_id:8;
    unsigned int section_length_h:4;
    unsigned int reserved0:2;
    unsigned int private_indicator:1;
    unsigned int section_syntax_indicator:1;
    unsigned int section_length_l:8;
    unsigned int table_id_extension_h:8;
    unsigned int table_id_extension_l:8;
    unsigned int current_next_indicator:1;
    unsigned int version_number:5;
    unsigned int reserved1:2;
    unsigned int section_number:8;
    unsigned int last_section_number:8;
    unsigned int protocol_version:8;
    unsigned int tables_defined_h:8;
    unsigned int tables_defined_l:8;
} MGT_HEADER;

#define MGT_HEADER_SIZE 11

typedef struct {
    unsigned int table_type_h:8;
    unsigned int table_type_l:8;
    unsigned int table_type_PID_h:5;
    unsigned int reserved0:3;
    unsigned int table_type_PID_l:8;
    unsigned int table_type_version_number:5;
    unsigned int reserved1:3;
    unsigned int number_bytes_h:8;
    unsigned int number_bytes_mh:8;
    unsigned int number_bytes_ml:8;
    unsigned int number_bytes_l:8;
    unsigned int table_type_descriptors_length_h:4;
    unsigned int reserved2:4;
    unsigned int table_type_descriptors_length_l:8;
} MGT_ELEMENT;

#define MGT_ELEMENT_SIZE 11

typedef struct {
    unsigned int descriptors_length_h:4;
    unsigned int reserved:4;
    unsigned int descriptors_length_l:8;
} MGT_TRAILER;

#define MGT_TRAILER_SIZE 2

typedef struct {
    unsigned int table_id:8;
    unsigned int section_length_h:4;
    unsigned int reserved0:2;
    unsigned int private_indicator:1;
    unsigned int section_syntax_indicator:1;
    unsigned int section_length_l:8;
    unsigned int transport_stream_id_h:8;
    unsigned int transport_stream_id_l:8;
    unsigned int current_next_indicator:1;
    unsigned int version_number:5;
    unsigned int reserved1:2;
    unsigned int section_number:8;
    unsigned int last_section_number:8;
    unsigned int protocol_version:8;
    unsigned int num_channels_in_section:8;
} TVCT_HEADER;

#define TVCT_HEADER_SIZE 10

typedef struct {
    unsigned int short_name_1h:8;
    unsigned int short_name_1l:8;
    unsigned int short_name_2h:8;
    unsigned int short_name_2l:8;
    unsigned int short_name_3h:8;
    unsigned int short_name_3l:8;
    unsigned int short_name_4h:8;
    unsigned int short_name_4l:8;
    unsigned int short_name_5h:8;
    unsigned int short_name_5l:8;
    unsigned int short_name_6h:8;
    unsigned int short_name_6l:8;
    unsigned int short_name_7h:8;
    unsigned int short_name_7l:8;
    unsigned int major_channel_number_h:4;
    unsigned int reserved0:4;
    unsigned int minor_channel_number_h:2;
    unsigned int major_channel_number_l:6;
    unsigned int minor_channel_number_l:8;
    unsigned int modulation_mode:8;
    unsigned int carrier_frequency_h:8;
    unsigned int carrier_frequency_mh:8;
    unsigned int carrier_frequency_ml:8;
    unsigned int carrier_frequency_l:8;
    unsigned int channel_TSID_h:8;
    unsigned int channel_TSID_l:8;
    unsigned int program_number_h:8;
    unsigned int program_number_l:8;
    unsigned int reserved2:1;
    unsigned int hide_guide:1;
    unsigned int reserved1:2;
    unsigned int hidden:1;
    unsigned int access_controlled:1;
    unsigned int ETM_location:2;
    unsigned int service_type:6;
    unsigned int reserved3:2;
    unsigned int source_id_h:8;
    unsigned int source_id_l:8;
    unsigned int descriptors_length_h:2;
    unsigned int reserved4:6;
    unsigned int descriptors_length_l:8;
} TVCT_ELEMENT;

#define TVCT_ELEMENT_SIZE 32

typedef struct {
    unsigned int additional_descriptors_length_h:2;
    unsigned int reserved:6;
    unsigned int additional_descriptors_length_l:8;
} TVCT_TRAILER;

#define TVCT_TRAILER_SIZE 2

typedef struct {
    unsigned int descriptor_tag:8;
    unsigned int descriptor_length:8;
    unsigned int PCR_PID_h:5;
    unsigned int reserved:3;
    unsigned int PCR_PID_l:8;
    unsigned int number_elements:8;
} TVCT_SLD_DESCRIPTOR;

#define TVCT_DESCRIPTOR_SIZE 5

typedef struct {
    unsigned int stream_type:8;
    unsigned int elementary_PID_h:5;
    unsigned int reserved:3;
    unsigned int elementary_PID_l:8;
    unsigned int ISO_639_language_code_1:8;
    unsigned int ISO_639_language_code_2:8;
    unsigned int ISO_639_language_code_3:8;
} TVCT_SLD_DESCRIPTOR_ELEMENT;

#define TVCT_DESCRIPTOR_ELEMENT_SIZE       (6)

#define SNDU_PAYLOAD_SIZE (MPEG2_PACKET_SIZE - TS_HEADER_SIZE)
#define SNDU_PAYLOAD_PP_SIZE (MPEG2_PACKET_SIZE - TS_HEADER_SIZE - PAYLOAD_POINTER_SIZE)
#define SNDU_PAYLOAD_PP_OFFSET (TS_HEADER_SIZE + PAYLOAD_POINTER_SIZE)

namespace gr {
  namespace ule {

    class ule_source_impl : public ule_source
    {
     private:
      unsigned int pat_count;
      unsigned int pmt_count;
      unsigned int mgt_count;
      unsigned int tvct_count;
      unsigned char *packet_ptr;
      unsigned int packet_count;
      int packet_length, shift;
      int ping_reply_mode;
      int ipaddr_spoof_mode;
      bool next_packet_valid;
      unsigned char pat[MPEG2_PACKET_SIZE];
      unsigned char pmt[MPEG2_PACKET_SIZE];
      unsigned char ule[MPEG2_PACKET_SIZE];
      unsigned char mgt[MPEG2_PACKET_SIZE];
      unsigned char tvct[MPEG2_PACKET_SIZE];
      unsigned char stuffing[MPEG2_PACKET_SIZE];
      unsigned int crc32_table[256];
      pcap_t* descr;
      const unsigned char *packet;
      unsigned char packet_save[4110];
      unsigned char ule_continuity_counter;
      struct dvb_v5_fe_parms *parms;
      int crc32_partial;
      unsigned char src_addr[sizeof(in_addr)];
      unsigned char dst_addr[sizeof(in_addr)];
      void crc32_init(void);
      int crc32_calc(unsigned char *, int);
      int crc32_calc_partial(unsigned char *, int, int);
      int crc32_calc_final(unsigned char *, int, int);
      int checksum(unsigned short *, int, int);
      inline void ping_reply(void);
      inline void ipaddr_spoof(void);
      inline void dump_packet(void);

     public:
      ule_source_impl(char *mac_address, char *filename, char *frequency, char *call_sign, ule_ping_reply_t ping_reply, ule_ipaddr_spoof_t ipaddr_spoof, char *src_address, char *dst_address);
      ~ule_source_impl();

      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace ule
} // namespace gr

#endif /* INCLUDED_ULE_ULE_SOURCE_IMPL_H */

