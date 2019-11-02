#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>
#include "epan/dissectors/packet-tcp.h"
#include "epan/wmem/wmem.h"

#include "packet-ffxiv.h"

#define FFXIV_COMPRESSED_FLAG 0x01
#define FFXIV_MAGIC 0x5252
#define FFXIV_PORT_RANGE "54992-54994,55006-55007,55021-55040"

static dissector_handle_t ffxiv_handle;
static gint ett_ffxiv = -1;

static const int ffxiv_header_length = 40;

static int proto_ffxiv = -1; //!< Global id for this protocol. Set by wireshark on register.

static range_t *global_ffxiv_port_range = NULL;

// FFXIV header
static int hf_ffxiv_frame_pdu_magic = -1; //!< "RR" Tag 0x5252
static int hf_ffxiv_frame_pdu_timestamp = -1; 
static int hf_ffxiv_frame_pdu_length = -1;
static int hf_ffxiv_frame_magic2 = -1;
static int hf_ffxiv_frame_pdu_count = -1;
static int hf_ffxiv_frame_magic3 = -1;
static int hf_ffxiv_frame_flag_compressed = -1;
static int hf_ffxiv_frame_magic4 = -1;

// FFXIV Message
static int hf_ffxiv_message = -1;
static int hf_ffxiv_message_pdu_length = -1;
static int hf_ffxiv_message_pdu_send_id = -1;
static int hf_ffxiv_message_pdu_recv_id = -1;
static int hf_ffxiv_message_header_unknown1 = -1;
static int hf_ffxiv_message_header_unknown2 = -1;
static int hf_ffxiv_message_opcode = -1;
static int hf_ffxiv_message_pdu_timestamp = -1;

// Message data
static int hf_ffxiv_generic_data = -1;
static int hf_ffxiv_data_epoch_seconds = -1;
static int hf_ffxiv_data_set_id = -1;
static int hf_ffxiv_data_slot_action = -1;
static int hf_ffxiv_data_slot_id = -1;
static int hf_ffxiv_data_set_ac_array = -1;
static int hf_ffxiv_data_set_slot_array = -1;
static int hf_ffxiv_data_rel_time = -1;
static int hf_ffxiv_data_los = -1;
static int hf_ffxiv_data_move_flags = -1;
static int hf_ffxiv_data_pos_x = -1;
static int hf_ffxiv_data_pos_z = -1;
static int hf_ffxiv_data_pos_y = -1;
static int hf_ffxiv_data_move_unknown = -1;




static const value_string at_str_opcode_vals[] = {
    { opcode_change_gearset,   "Change Gearset" },
    { opcode_player_movement,   "Move request" },
    { opcode_relative_time,    "Relative time" },
    { opcode_heartbeat,        "Heartbeat" },
    { 0, NULL }
};

static const value_string str_gearset_actions[] =
{
    { 1000,   "Unchanged" },

    { 3200,   "Change Offhand" },
    { 3201,   "Change Head" },
    { 3202,   "Change Body" },
    { 3203,   "Change Hands" },
    { 3204,   "Change Waist" },
    { 3205,   "Change Legs" },
    { 3206,   "Change Feet" },
    { 3207,   "Change Ears" },
    { 3208,   "Change Neck" },
    { 3209,   "Change Wrists" },

    { 3300,   "Change Ring" },
    { 3400,   "Change Job Crystal" },
    { 3500,   "Change Main Hand" },

    { 9999,   "Empty" },
    { 0, NULL }
};


// Assemble generic headers
static void build_frame_header(tvbuff_t* tvb, proto_tree* tree, frame_header_t* pdu_header)
{
  pdu_header->rr_tag = tvb_get_letohs(tvb, FFXIV_PDU_HEADER_OFFSET_TAG);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_magic, tvb, FFXIV_PDU_HEADER_OFFSET_TAG, sizeof(pdu_header->rr_tag), ENC_LITTLE_ENDIAN);

  tvb_memcpy(tvb, pdu_header->magic1, FFXIV_PDU_HEADER_OFFSET_MAGIC1, sizeof(pdu_header->magic1)); // Not of interest. Part of the eye-catcher.

  pdu_header->utc_time_ms = tvb_get_letoh64(tvb, FFXIV_PDU_HEADER_OFFSET_UTC_MS);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_timestamp, tvb, FFXIV_PDU_HEADER_OFFSET_UTC_MS, sizeof(pdu_header->utc_time_ms), ENC_LITTLE_ENDIAN | ENC_TIME_MSECS);

  pdu_header->length = tvb_get_letohl(tvb, FFXIV_PDU_HEADER_OFFSET_PDU_LEN);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_length, tvb, FFXIV_PDU_HEADER_OFFSET_PDU_LEN, sizeof(pdu_header->length), ENC_LITTLE_ENDIAN);

  pdu_header->magic2 = tvb_get_letohs(tvb, FFXIV_PDU_HEADER_OFFSET_MAGIC2);
  proto_tree_add_item(tree, hf_ffxiv_frame_magic2, tvb, FFXIV_PDU_HEADER_OFFSET_MAGIC2, sizeof(pdu_header->magic2), ENC_LITTLE_ENDIAN);

  pdu_header->msg_count = tvb_get_letohs(tvb, FFXIV_PDU_HEADER_OFFSET_NUM_MSG);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_count, tvb, FFXIV_PDU_HEADER_OFFSET_NUM_MSG, sizeof(pdu_header->msg_count), ENC_LITTLE_ENDIAN);

  pdu_header->magic3 = tvb_get_guint8(tvb, FFXIV_PDU_HEADER_OFFSET_MAGIC3);
  proto_tree_add_item(tree, hf_ffxiv_frame_magic3, tvb, FFXIV_PDU_HEADER_OFFSET_MAGIC3, sizeof(pdu_header->magic3), ENC_LITTLE_ENDIAN);

  pdu_header->encoding = tvb_get_guint8(tvb, FFXIV_PDU_HEADER_OFFSET_ENCODE);
  proto_tree_add_item(tree, hf_ffxiv_frame_flag_compressed, tvb, FFXIV_PDU_HEADER_OFFSET_ENCODE, sizeof(pdu_header->encoding), ENC_LITTLE_ENDIAN);

  tvb_memcpy(tvb, pdu_header->magic4, FFXIV_PDU_HEADER_OFFSET_MAGIC4, sizeof(pdu_header->magic4));
  proto_tree_add_item(tree, hf_ffxiv_frame_magic4, tvb, FFXIV_PDU_HEADER_OFFSET_MAGIC4, sizeof(pdu_header->magic4), ENC_LITTLE_ENDIAN);
}

static void decode_message_header(tvbuff_t *tvb, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_length, tvb, FFXIV_MSG_HEADER_OFFSET_MSG_LEN, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_send_id, tvb, FFXIV_MSG_HEADER_OFFSET_SEND_ID, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_recv_id, tvb, FFXIV_MSG_HEADER_OFFSET_RECEIVE_ID, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_header_unknown1, tvb, FFXIV_MSG_HEADER_OFFSET_UNKNOWN1, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_header_unknown2, tvb, FFXIV_MSG_HEADER_OFFSET_UNKNOWN2, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_opcode, tvb, FFXIV_MSG_HEADER_OFFSET_OPCODE, 2, ENC_LITTLE_ENDIAN);
}

static void decode_data_timestamp(tvbuff_t* tvb, proto_tree* tree)
{
    gint length = tvb_captured_length_remaining(tvb, 0); 
    if (length < 8)
        proto_report_dissector_bug("Error: Message data is too short for a timestamp. (%i < 8)", length);
    // TODO Encoding for milleseconds
    proto_tree_add_item(tree, hf_ffxiv_data_epoch_seconds, tvb, 4, 4, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
}

static void decode_msg_data(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, message_type type, guint data_length)
{
    switch (type)
    {
    case opcode_change_gearset:
        decode_msg_data_chg_gearset(msgbuf, pinfo, tree, data_length);
        break;
    case opcode_player_movement:
        decode_data_player_move(msgbuf, pinfo, tree, data_length);
        break;
    case opcode_relative_time:
        decode_data_some_relative_time(msgbuf, pinfo, tree, data_length);
        break;
    case opcode_heartbeat:
        decode_msg_data_heartbeat(msgbuf, pinfo, tree, data_length);
        break;
    default:
        decode_msg_data_unknown(msgbuf, pinfo, tree, data_length);
        break;
    }
}

static void decode_msg_data_unknown(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length)
{
    proto_tree_add_item(tree, hf_ffxiv_generic_data, msgbuf, 0, data_length, ENC_STR_HEX);
    col_add_str(pinfo->cinfo, COL_INFO, "Unknown; ");
}

static void decode_msg_data_heartbeat(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length)
{
    if (data_length != 4)
        proto_report_dissector_bug("Unknown content. Size do not match. (%i != 4)", data_length);
    proto_tree_add_item(tree, hf_ffxiv_data_epoch_seconds, msgbuf, 0, data_length, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
    col_add_str(pinfo->cinfo, COL_INFO, "Heartbeat; ");
}

static void decode_msg_data_chg_gearset(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length)
{
    if (data_length != 76)
        proto_report_dissector_bug("Unknown content. Size do not match. (%i != 76)", data_length);

    col_add_str(pinfo->cinfo, COL_INFO, "Change gearset; ");
    decode_data_timestamp(msgbuf, tree);

    guint offset = 12; // 8 timestamp + 4 padding
    proto_tree_add_item(tree, hf_ffxiv_data_set_id, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    // Gearset Action Array
    proto_item* action_array = proto_tree_add_item(tree, hf_ffxiv_data_set_ac_array, msgbuf, offset, 28, ENC_NA);
    proto_tree* action_entry = proto_item_add_subtree(action_array, ett_ffxiv);

    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // Gearset Source Armory Slot Index
    proto_item* slot_array = proto_tree_add_item(tree, hf_ffxiv_data_set_slot_array, msgbuf, offset, 28, ENC_NA);
    proto_tree* slot_entry = proto_item_add_subtree(slot_array, ett_ffxiv);

    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    // Unknown
    proto_tree_add_item(tree, hf_ffxiv_message_header_unknown1, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_ffxiv_message_header_unknown2, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);

}

static void decode_data_some_relative_time(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length)
{
    if (data_length < 18)
        proto_report_dissector_bug("Unknown content. Size is too small. (%i < 18)", data_length);

    col_add_str(pinfo->cinfo, COL_INFO, "Relative time sync; ");
    decode_data_timestamp(msgbuf, tree);

    guint offset = 12; // 8 timestamp + 4 padding
    proto_tree_add_item(tree, hf_ffxiv_data_rel_time, msgbuf, offset, 4, ENC_LITTLE_ENDIAN | ENC_TIME_MSECS);
    offset += 4;
    proto_tree_add_item(tree, hf_ffxiv_message_header_unknown1, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);

}

static void decode_data_player_move(tvbuff_t* msgbuf, packet_info* pinfo, proto_tree* tree, guint data_length)
{
    if (data_length != 36)
        proto_report_dissector_bug("Unknown content. Size do not match. (%i != 36)", data_length);

    col_add_str(pinfo->cinfo, COL_INFO, "Move request; ");
    decode_data_timestamp(msgbuf, tree);

    guint offset = 12; // 8 timestamp + 4 padding
    proto_tree_add_item(tree, hf_ffxiv_data_los, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_ffxiv_data_move_flags, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_ffxiv_data_pos_x, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_ffxiv_data_pos_z, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_ffxiv_data_pos_y, msgbuf, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_ffxiv_data_move_unknown, msgbuf, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;


}

// Deal with multiple payloads in a single PDU
static guint32 get_frame_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void* data) {
  return tvb_get_letohl(tvb, offset + 24);
}

static guint32 get_message_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void* data) {
  return tvb_get_letohl(tvb, offset);
}

/**
 * @brief Dissects a single message,
 * The buffered bytes are checked against the reported message size from the protocol
 * @return Number of bytes remaining in the buffer for further dissection
 */
static int dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint all_remaining_bytes = tvb_captured_length_remaining(tvb, 0);

  if (all_remaining_bytes < 0)
  {
    proto_report_dissector_bug("Negative capture length detected (%i).", all_remaining_bytes);
  }

  if (all_remaining_bytes < FFXIV_MSG_HEADER_LEN)
    proto_report_dissector_bug("Message too short (%i < %i)", all_remaining_bytes, FFXIV_MSG_HEADER_LEN);

  gint msg_len = tvb_get_letohl(tvb, FFXIV_MSG_HEADER_OFFSET_MSG_LEN);
  gint data_len = msg_len - FFXIV_MSG_HEADER_LEN;
 
  if (msg_len > all_remaining_bytes || data_len < 0 || msg_len < 0)
  {
    proto_report_dissector_bug("Message invalid (Captured: %i Bytes, Reported message length: %i Bytes, Minimum Message length: %i Bytes.)",
                               all_remaining_bytes, msg_len, FFXIV_MSG_HEADER_LEN);
  }

  proto_item* item = proto_tree_add_item(tree, hf_ffxiv_message, tvb, 0, msg_len, ENC_NA);
  proto_tree* msg_members = proto_item_add_subtree(item, ett_ffxiv);
  decode_message_header(tvb, msg_members);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo, COL_INFO);
  message_type opcode = (message_type) tvb_get_letohs(tvb, FFXIV_MSG_HEADER_OFFSET_OPCODE);

  tvbuff_t* data_tvb = tvb_new_subset_length(tvb, FFXIV_MSG_HEADER_LEN, data_len);
  decode_msg_data(data_tvb, pinfo, msg_members, opcode, data_len);
  add_new_data_source(pinfo, data_tvb, "Message Data");

  return msg_len;
}

// Frame header dissector
static int dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  // Captured APDU
  gint all_frame_bytes = tvb_captured_length_remaining(tvb, 0);
  if (all_frame_bytes < FRAME_HEADER_LEN)
  {
      proto_report_dissector_bug("Invalid frame (Captured: %i Bytes, Expected header length of %i Bytes.)",
                                 all_frame_bytes, FRAME_HEADER_LEN);
  }
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo, COL_INFO);

  proto_item* item = proto_tree_add_item(tree, proto_ffxiv, tvb, 0, -1, ENC_NA); // Frame tree (0 - end)
  proto_tree* frame_tree = proto_item_add_subtree(item, ett_ffxiv);

  frame_header_t pdu_header = {0};
  build_frame_header(tvb, frame_tree, &pdu_header);

  if (pdu_header.length != all_frame_bytes)
  {
      proto_report_dissector_bug("Invalid APDU (Captured: %i Bytes, Reported %i Bytes.)",
                                 all_frame_bytes, pdu_header.length);
  }

  gint payload_len = all_frame_bytes - FRAME_HEADER_LEN;
  tvbuff_t* payload_tvb = tvb_new_subset_remaining(tvb, FRAME_HEADER_LEN);

  // Package is compressed
  if (pdu_header.encoding & FFXIV_COMPRESSED_FLAG)
  {
    payload_tvb = tvb_child_uncompress(tvb, payload_tvb, 0, payload_len);

    if (!payload_tvb)
    {
      proto_report_dissector_bug("Failed to uncompress frame data.");
    }
     add_new_data_source(pinfo, payload_tvb, "Decompressed Payload");
  }

  gint processed = 0;
  for (gint msg = 1; msg <= pdu_header.msg_count; ++msg)
  {
      payload_tvb = tvb_new_subset_remaining(payload_tvb, processed);
      processed = dissect_message(payload_tvb, pinfo, frame_tree);
  }

  if (processed != tvb_captured_length_remaining(payload_tvb, 0))
  {
      proto_report_dissector_bug("Invalid APDU (Processed on last message: %i Bytes. Captured length of last message: %i Bytes.)",
                                 processed, tvb_captured_length_remaining(payload_tvb, 0));
  }
  return tvb_captured_length(payload_tvb);
}

// Main dissection method
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  // Verify we have an actual frame header
  if (!tvb_bytes_exist(tvb, 0, FRAME_HEADER_LEN))
    return 0;

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_frame_length, dissect_frame, data);

  return tvb_captured_length(tvb);
}

// Wireshark standard is to stick these at the end
void proto_register_ffxiv(void)
{
  static hf_register_info hf[] = {
      {&hf_ffxiv_frame_pdu_magic,
       {"RR Tag", "ffxiv.frame.tag", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
      {&hf_ffxiv_frame_pdu_timestamp,
       {"Frame Timestamp", "ffxiv.frame.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
        0x0, NULL, HFILL}},
      {&hf_ffxiv_frame_pdu_length,
       {"Frame Length", "ffxiv.frame.length", FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_ffxiv_frame_magic2,
       {"Unknown 1", "ffxiv.frame.unknown1", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_ffxiv_frame_pdu_count,
       {"Number of messages", "ffxiv.frame.count", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_ffxiv_frame_magic3,
       {"Unknown 2", "ffxiv.frame.unknown2", FT_UINT8, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_ffxiv_frame_flag_compressed,
       {"Compression", "ffxiv.frame.compressed", FT_BOOLEAN, 8, NULL,
        FFXIV_COMPRESSED_FLAG, NULL, HFILL}},
      {&hf_ffxiv_frame_magic4,
       {"Unknown 3", "ffxiv.frame.unknown3", FT_UINT48, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_ffxiv_message,
       {"FFXIV single message", "ffxiv.message", FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_ffxiv_message_pdu_length,
       {"Message Length", "ffxiv.message.length", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_ffxiv_message_pdu_send_id,
       {"Sender ID", "ffxiv.message.sender", FT_UINT32, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_ffxiv_message_pdu_recv_id,
       {"Receiver ID", "ffxiv.message.receiver", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_ffxiv_message_header_unknown1,
      {"Unknown 1", "ffxiv.message.unknown1", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
      {&hf_ffxiv_message_header_unknown2,
      {"Unknown 2", "ffxiv.message.unknown2", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
      {&hf_ffxiv_message_opcode,
       {"OpCode", "ffxiv.message.opcode", FT_UINT16, BASE_HEX, VALS(at_str_opcode_vals), 0x0,
        NULL, HFILL}},

       // Unknown default message
      {&hf_ffxiv_generic_data,
       {"Data", "ffxiv.message.data", FT_BYTES,
        BASE_NONE, NULL, 0x0, "Raw message data",
        HFILL}},
      // Known messages
       {&hf_ffxiv_data_epoch_seconds,
       {"UTC Timestamp", "ffxiv.message.epoch", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_set_id,
       {"Gearset ID", "ffxiv.message.data.gearset.id", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_set_ac_array,
       {"Gearset actions", "ffxiv.message.gearset.actions", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_slot_action,
       {"Gear slot action", "ffxiv.message.data.gearset.actions.action", FT_UINT16, BASE_DEC,
        VALS(str_gearset_actions), 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_set_slot_array,
       {"Armory chest slots", "ffxiv.message.gearset.slots", FT_NONE, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_slot_id,
       {"Armoury chest source slot ID", "ffxiv.message.data.gearset.slots.source_id", FT_INT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_rel_time,
       {"Relative time", "ffxiv.message.data.reltime.time", FT_RELATIVE_TIME, 0x0,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_los,
       {"Line of sight [rad]", "ffxiv.message.data.los", FT_FLOAT, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_move_flags,
       {"Move flags", "ffxiv.data.move.flags", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL}},
       {&hf_ffxiv_data_pos_x,
       {"X Position", "ffxiv.message.data.posX", FT_FLOAT, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_pos_z,
       {"Z Position", "ffxiv.message.data.posZ", FT_FLOAT, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_pos_y,
       {"Y Position", "ffxiv.message.data.posY", FT_FLOAT, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
       {&hf_ffxiv_data_move_unknown,
       {"Unknown", "ffxiv.message.data.unknown", FT_UINT16, BASE_DEC_HEX,
        NULL, 0x0, NULL, HFILL}}
  };

  static gint *ett[] = {
    &ett_ffxiv
  };

  module_t          *ffxiv_module;
  dissector_table_t ffxiv_frame_magic_table;

  proto_ffxiv = proto_register_protocol("Final Fantasy XIV message block", "FFXIV", "ffxiv");
  proto_register_field_array(proto_ffxiv, hf, array_length(hf));

  proto_register_subtree_array(ett, array_length(ett));

  ffxiv_module = prefs_register_protocol(proto_ffxiv, NULL);

  ffxiv_frame_magic_table = register_dissector_table(
    "ffxiv.frame.magic", "FFXIV Magic Byte", proto_ffxiv, FT_UINT16, BASE_DEC
  );

  range_convert_str(wmem_epan_scope(), &global_ffxiv_port_range, FFXIV_PORT_RANGE, 55551);
  prefs_register_range_preference(ffxiv_module, "tcp.port", "FFXIV port range",
    "Range of ports to look for FFXIV traffic on.", &global_ffxiv_port_range, 55551
  );
}

// Setup ranged port handlers
static void ffxiv_tcp_dissector_add(guint32 port, gpointer any) {
  dissector_add_uint("tcp.port", port, ffxiv_handle);
}

static void ffxiv_tcp_dissector_delete(guint32 port) {
  dissector_delete_uint("tcp.port", port, ffxiv_handle);
}

// Register handlers
void proto_reg_handoff_ffxiv(void)
{
  ffxiv_handle = register_dissector("ffxiv", dissect_ffxiv, proto_ffxiv);
  range_foreach(global_ffxiv_port_range, ffxiv_tcp_dissector_add, NULL);
  dissector_add_uint("ffxiv.frame.magic", FFXIV_MAGIC, ffxiv_handle);
}
