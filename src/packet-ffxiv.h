#include <stdint.h>
#include <stdio.h>

const int FFXIV_PDU_HEADER_OFFSET_TAG     = 0;
const int FFXIV_PDU_HEADER_OFFSET_MAGIC1  = 2;
const int FFXIV_PDU_HEADER_OFFSET_UTC_MS  = 16;
const int FFXIV_PDU_HEADER_OFFSET_PDU_LEN = 24;
const int FFXIV_PDU_HEADER_OFFSET_MAGIC2  = 28;
const int FFXIV_PDU_HEADER_OFFSET_NUM_MSG = 30;
const int FFXIV_PDU_HEADER_OFFSET_MAGIC3  = 32;
const int FFXIV_PDU_HEADER_OFFSET_ENCODE  = 33;
const int FFXIV_PDU_HEADER_OFFSET_MAGIC4  = 34;

const int FFXIV_MSG_HEADER_LEN = 20;
const int FFXIV_MSG_HEADER_OFFSET_MSG_LEN = 0;
const int FFXIV_MSG_HEADER_OFFSET_SEND_ID = 4;
const int FFXIV_MSG_HEADER_OFFSET_RECEIVE_ID = 8;
const int FFXIV_MSG_HEADER_OFFSET_UNKNOWN1 = 12;
const int FFXIV_MSG_HEADER_OFFSET_UNKNOWN2 = 16;
const int FFXIV_MSG_HEADER_OFFSET_OPCODE = 18;

const int FFXIV_MSG_DATA_OFFSET_TIMESTAMP = 2;

/** Frame header
*/
typedef struct
{
  uint16_t rr_tag;      // [0:1]
  uint16_t magic1[7];   // [2:15]
  uint64_t utc_time_ms; // [16:23]
  uint32_t length;      // [24:27]
  uint16_t magic2;      // [28:29]
  uint16_t msg_count;   // [30:31]
  uint8_t  magic3;      // [32]
  uint8_t  encoding;    // [33]
  uint16_t magic4[3];   // [34:39]
} frame_header_t;

const int FRAME_HEADER_LEN = 40;

typedef enum
{
    opcode_change_gearset = 0x018a,
    opcode_player_movement = 0x01ec,
    opcode_relative_time = 0x0346,
    opcode_heartbeat = 0x1068
} message_type;

// Utility methods
static guint32 get_frame_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static guint32 get_message_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static void build_frame_header(tvbuff_t* tvb, proto_tree* tree, frame_header_t* pdu_header);
static void decode_message_header(tvbuff_t *tvb, proto_tree *tree);

/**
 * @brief Decodes the timestamp at the beginning of almost every message data.
 */
static void decode_data_timestamp(tvbuff_t* tvb, proto_tree* tree);

// Message decoding
static void decode_msg_data(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, message_type type, guint data_length); //!< Decoder switch for all messages

static void decode_msg_data_unknown(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length);            //!< Default decoder for all unknown message types
static void decode_msg_data_heartbeat(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length);
static void decode_msg_data_chg_gearset(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length);
static void decode_data_some_relative_time(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length);
static void decode_data_player_move(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length);

// Dissection methods
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
