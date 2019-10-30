#include <stdint.h>
#include <stdio.h>

const int FRAME_HEADER_LEN = 40;

const int FFXIV_MSG_HEADER_LEN = 20;
const int FFXIV_MSG_HEADER_OFFSET_MSG_LEN = 0;
const int FFXIV_MSG_HEADER_OFFSET_SEND_ID = 4;
const int FFXIV_MSG_HEADER_OFFSET_RECEIVE_ID = 8;
const int FFXIV_MSG_HEADER_OFFSET_UNKNOWN1 = 12;
const int FFXIV_MSG_HEADER_OFFSET_UNKNOWN2 = 16;
const int FFXIV_MSG_HEADER_OFFSET_OPCODE = 18;

// FFXIV protocol generic types
typedef struct {
  uint16_t magic;         // [0:1]
  uint8_t  mystery1[14];  // unknown [2:15]
  uint64_t timestamp;     // [16:23]
  uint32_t length;        // [24:27]
  uint8_t  mystery2[2];   // unknown [28-29]
  uint16_t blocks;        // [30:31]
  uint8_t  mystery3;      // unknown [32:]
  uint8_t  compressed;    // [33:]
  uint8_t  mystery4[6];   // unknown [34:39]
} frame_header_t;

typedef enum
{
    opcode_heartbeat = 0xe022
} message_type;

// Utility methods
static guint32 get_frame_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static guint32 get_message_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static void build_frame_header(tvbuff_t *tvb, int offset, packet_info*, proto_tree *tree, frame_header_t *eh_ptr);
static void decode_message_header(tvbuff_t *tvb, int offset, packet_info*, proto_tree *tree);

// Message decoding
static int decode_msg_data(tvbuff_t* msgbuf, proto_tree* tree, message_type type, guint data_length); //!< Decoder switch for all messages

static int decode_msg_data_unknown(tvbuff_t* msgbuf, proto_tree* tree, guint data_length);            //!< Default decoder for all unknown message types
static int decode_msg_data_heartbeat(tvbuff_t* msgbuf, proto_tree* tree, guint data_length);          //!< Opcode 0xe022

// Dissection methods
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
