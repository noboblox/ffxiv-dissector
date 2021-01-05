#include "config.h"

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

static int proto_ffxiv_id = -1;
static gint ett_ffxiv     = -1;
static dissector_handle_t ffxiv_handle = NULL;
static range_t *ffxiv_port_range       = NULL;

static int hf_ffxiv_frame_header_sign           = -1;
static int hf_ffxiv_frame_header_timestamp      = -1;
static int hf_ffxiv_frame_header_size           = -1;
static int hf_ffxiv_frame_header_unknown_1      = -1;
static int hf_ffxiv_frame_header_msg_count      = -1;
static int hf_ffxiv_frame_header_unknown_2      = -1;
static int hf_ffxiv_frame_header_flags          = -1;
static int hf_ffxiv_frame_header_unknown_3      = -1;

static int hf_ffxiv_message                     = -1;

static int hf_ffxiv_msg_header_size             = -1;
static int hf_ffxiv_msg_header_source           = -1;
static int hf_ffxiv_msg_header_destination      = -1;
static int hf_ffxiv_msg_header_type             = -1;

static int hf_ffxiv_data_msg_header_unknown_2   = -1;
static int hf_ffxiv_data_msg_header_opcode      = -1;

static int hf_ffxiv_data_raw                    = -1;
static int hf_ffxiv_data_unknown_short          = -1;
static int hf_ffxiv_data_epoch_seconds          = -1;
static int hf_ffxiv_data_set_id                 = -1;
static int hf_ffxiv_data_slot_action            = -1;
static int hf_ffxiv_data_slot_id                = -1;
static int hf_ffxiv_data_set_ac_array           = -1;
static int hf_ffxiv_data_set_slot_array         = -1;
static int hf_ffxiv_data_server_clock           = -1;
static int hf_ffxiv_data_los                    = -1;
static int hf_ffxiv_data_move_flags             = -1;
static int hf_ffxiv_data_pos_x                  = -1;
static int hf_ffxiv_data_pos_z                  = -1;
static int hf_ffxiv_data_pos_y                  = -1;
static int hf_ffxiv_data_move_unknown           = -1;
static int hf_ffxiv_data_target_action          = -1;
static int hf_ffxiv_data_emote_id               = -1;
static int hf_ffxiv_data_target_id              = -1;
static int hf_ffxiv_data_target_flag_npc        = -1;

enum { FRAME_HEADER_SIZE = 40 };
enum { MSG_HEADER_SIZE   = 20 };

enum
{
  FRAME_FLAG_DEFLATE = 0x01
};

enum
{
  FFXIV_MSG_INGAME_DATA   = 3,
  FFXIV_MSG_CLIENT_STATUS = 7,
  FFXIV_MSG_SERVER_STATUS = 8
};

static const value_string msg_type_str[] =
{
  { FFXIV_MSG_INGAME_DATA,   "Game data"},
  { FFXIV_MSG_CLIENT_STATUS, "Client ping"},
  { FFXIV_MSG_SERVER_STATUS, "Server ping"},
  { 0, NULL }
};

enum
{
  FFXIV_DATA_MSG_CHANGE_GEARSET  = 0x018A,
  FFXIV_DATA_MSG_TIME_SYNC       = 0x01B0,
  FFXIV_DATA_MSG_MOVE_PLAYER     = 0x023C,
  FFXIV_DATA_MSG_TARGET_INTERACT = 0x02C4,
};

static const value_string data_msg_opcode_str[] =
{
  { FFXIV_DATA_MSG_CHANGE_GEARSET,   "Change Gearset"},
  { FFXIV_DATA_MSG_MOVE_PLAYER,      "Move player"},
  { FFXIV_DATA_MSG_TIME_SYNC,        "Time sync"},
  { FFXIV_DATA_MSG_TARGET_INTERACT,  "Target interaction"},
  { 0, NULL }
};

enum
{
    FFXIV_TARGET_SELECTION = 3,
    FFXIV_TARGET_EMOTE     = 500,
};

static const value_string target_interaction_str[] =
{
    {FFXIV_TARGET_SELECTION, "SELECT"},
    {FFXIV_TARGET_EMOTE,     "EMOTE" },
    {0, NULL}
};

static const value_string gearset_chg_str[] =
{
  { 1000, "Unchanged" },

  { 3200, "Change Offhand" },
  { 3201, "Change Head" },
  { 3202, "Change Body" },
  { 3203, "Change Hands" },
  { 3204, "Change Waist" },
  { 3205, "Change Legs" },
  { 3206, "Change Feet" },
  { 3207, "Change Ears" },
  { 3208, "Change Neck" },
  { 3209, "Change Wrists" },
  { 3300, "Change Ring" },
  { 3400, "Change Job Crystal" },
  { 3500, "Change Main Hand" },

  { 9999, "Unequip slot" },
  { 0,     NULL }
};

static void
data_register(int proto_id)
{
  static hf_register_info field_ids[] =
  {
    {&hf_ffxiv_data_raw,             {"Unknown data",                 "ffxiv.message.data",
        FT_BYTES,         BASE_NONE,         NULL,                      0x0, "Raw message data", HFILL}},
    {&hf_ffxiv_data_unknown_short,   {"Unknown short",                "ffxiv.message.data.unknown1",
        FT_UINT16,        BASE_DEC,          NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_epoch_seconds,   {"UTC Timestamp",                "ffxiv.message.epoch",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,                      0x0, NULL, 	         HFILL}},
    {&hf_ffxiv_data_set_id,          {"Gearset ID",                   "ffxiv.message.data.gearset.id",
        FT_UINT32,        BASE_DEC,          NULL,                      0x0, NULL, 	         HFILL}},
    {&hf_ffxiv_data_set_ac_array,    {"Gearset actions",              "ffxiv.message.gearset.actions",
        FT_NONE,          BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_slot_action,     {"Gear slot action",             "ffxiv.message.data.gearset.actions.action",
        FT_UINT16,        BASE_DEC,          VALS(gearset_chg_str),     0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_set_slot_array,  {"Armory chest slots",           "ffxiv.message.gearset.slots",
        FT_NONE,          BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_slot_id,         {"Armoury chest source slot ID", "ffxiv.message.data.gearset.slots.source_id",
        FT_INT16,         BASE_DEC,          NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_server_clock,    {"Server clock",                 "ffxiv.message.data.timesync.server",
        FT_RELATIVE_TIME, BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_los,             {"Line of sight [rad]",          "ffxiv.message.data.line_of_sight",
        FT_FLOAT,         BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_move_flags,      {"Move flags",                   "ffxiv.data.move.flags",
        FT_BYTES,         BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_pos_x,           {"X Position",                   "ffxiv.message.data.posX",
        FT_FLOAT,         BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_pos_z,           {"Z Position",                   "ffxiv.message.data.posZ",
        FT_FLOAT,         BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_pos_y,           {"Y Position",                   "ffxiv.message.data.posY",
        FT_FLOAT,         BASE_NONE,         NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_move_unknown,    {"Unknown",                      "ffxiv.message.data.unknown",
        FT_UINT16,        BASE_DEC_HEX,      NULL,                      0x0, NULL,               HFILL}},
    {&hf_ffxiv_data_target_action,   {"Action",                       "ffxiv.message.data.target.action",
        FT_UINT32,        BASE_DEC_HEX,      VALS(target_interaction_str),  0x0,   NULL,             HFILL}},
    {&hf_ffxiv_data_emote_id,        {"Emote ID",                     "ffxiv.message.data.emote.id",
        FT_UINT32,         BASE_DEC,         NULL,                      0x0,   NULL,             HFILL}},
    {&hf_ffxiv_data_target_id,       {"Target ID",                    "ffxiv.message.data.target.id",
        FT_UINT32,         BASE_DEC,         NULL,                      0x0,   NULL,             HFILL}},
    {&hf_ffxiv_data_target_flag_npc, {"NPC",                          "ffxiv.message.data.target.flags.npc",
        FT_BOOLEAN,       SEP_DOT,          NULL,                       0x01, NULL,             HFILL}}

  };
  proto_register_field_array(proto_id, field_ids, array_length(field_ids));
}

static void
data_dissect_timestamp(tvbuff_t *tvb, proto_tree *tree, guint* offset)
{
  proto_tree_add_item(tree, hf_ffxiv_data_epoch_seconds, tvb, 4, 4, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
  /* TODO 4 bytes milliseconds */

  *offset += 12; /* 8 bytes timestamp, 4 bytes padding */
}

static void
data_dissect_gearset_change(tvbuff_t *tvb_data, packet_info *pinfo, proto_tree *tree)
{
  guint offset = 0;
  data_dissect_timestamp(tvb_data, tree, &offset);

  proto_tree_add_item(tree, hf_ffxiv_data_set_id, tvb_data, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* Gearset Action Array */
  proto_item* action_array = proto_tree_add_item(tree, hf_ffxiv_data_set_ac_array, tvb_data, offset, 28, ENC_NA);
  proto_tree* action_entry = proto_item_add_subtree(action_array, ett_ffxiv);

  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 0,  2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 2,  2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 4,  2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 6,  2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 8,  2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 10, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 12, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 14, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 16, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 18, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 20, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 22, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 24, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(action_entry, hf_ffxiv_data_slot_action, tvb_data, offset + 26, 2, ENC_LITTLE_ENDIAN);

  /* Gearset Source Armory Slot Index */
  proto_item* slot_array = proto_tree_add_item(tree, hf_ffxiv_data_set_slot_array, tvb_data, offset, 28, ENC_NA);
  proto_tree* slot_entry = proto_item_add_subtree(slot_array, ett_ffxiv);

  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 28, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 30, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 32, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 34, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 36, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 38, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 40, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 42, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 44, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 46, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 48, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 50, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 52, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(slot_entry, hf_ffxiv_data_slot_id, tvb_data, offset + 54, 2, ENC_LITTLE_ENDIAN);

  proto_tree_add_item(tree, hf_ffxiv_data_unknown_short, tvb_data, offset + 56, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_msg_header_unknown_2, tvb_data, offset + 58, 2, ENC_LITTLE_ENDIAN);
}

static void
data_dissect_server_clock_sync(tvbuff_t *tvb_data, packet_info *pinfo, proto_tree *tree)
{
  guint offset = 0;
  data_dissect_timestamp(tvb_data, tree, &offset);

  proto_tree_add_item(tree, hf_ffxiv_data_server_clock,  tvb_data, offset + 0, 4, ENC_LITTLE_ENDIAN | ENC_TIME_MSECS);
  proto_tree_add_item(tree, hf_ffxiv_data_unknown_short, tvb_data, offset + 4, 2, ENC_LITTLE_ENDIAN);
}

static void
data_dissect_target_interact(tvbuff_t *tvb_data, packet_info *pinfo, proto_tree *tree)
{
    static const guint32 NO_TARGET = 0xE0000000;

    guint offset = 0;
    data_dissect_timestamp(tvb_data, tree, &offset);

    const guint32 action = tvb_get_guint32(tvb_data, offset + 0, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_ffxiv_data_target_action, tvb_data, offset + 0, 4, ENC_LITTLE_ENDIAN);

    switch (action)
    {
        case FFXIV_TARGET_SELECTION:
        {
            proto_tree_add_item(tree, hf_ffxiv_data_target_id, tvb_data, offset + 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_ffxiv_data_target_flag_npc, tvb_data, offset + 8, 2, ENC_LITTLE_ENDIAN);

            const guint32 target = tvb_get_guint32(tvb_data, offset + 4, ENC_LITTLE_ENDIAN);

            if (target == NO_TARGET)
                col_append_str(pinfo->cinfo, COL_INFO, " [Unselect]");
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Select -> %u]", target);

            break;
        }

        case FFXIV_TARGET_EMOTE:
        {
            proto_tree_add_item(tree, hf_ffxiv_data_emote_id, tvb_data,        offset + 4,  4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_ffxiv_data_target_id, tvb_data,       offset + 24, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, hf_ffxiv_data_target_flag_npc, tvb_data, offset + 28, 2, ENC_LITTLE_ENDIAN);

            const guint32 emote  = tvb_get_guint32(tvb_data, offset + 4, ENC_LITTLE_ENDIAN);
            const guint32 target = tvb_get_guint32(tvb_data, offset + 24, ENC_LITTLE_ENDIAN);

            if (target == NO_TARGET)
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Emote ID=%u]", emote);
            else
                col_append_fstr(pinfo->cinfo, COL_INFO, " [Emote ID=%u -> %u]", emote, target);

            break;
        }

        default:
             col_append_fstr(pinfo->cinfo, COL_INFO," [Unknown (%u)]", action);
             proto_tree_add_item(tree, hf_ffxiv_data_raw, tvb_data, 0, tvb_reported_length(tvb_data), ENC_STR_HEX);
    }

}

static void
data_dissect_player_move(tvbuff_t *tvb_data, packet_info *pinfo, proto_tree *tree)
{
  guint offset = 0;
  data_dissect_timestamp(tvb_data, tree, &offset);

  proto_tree_add_item(tree, hf_ffxiv_data_los,          tvb_data, offset + 0,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_move_flags,   tvb_data, offset + 4,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_pos_x,        tvb_data, offset + 8,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_pos_z,        tvb_data, offset + 12, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_pos_y,        tvb_data, offset + 16, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_move_unknown, tvb_data, offset + 20, 2, ENC_LITTLE_ENDIAN);

  const gfloat los = tvb_get_ieee_float(tvb_data, offset + 0, ENC_LITTLE_ENDIAN);
  const gfloat x = tvb_get_ieee_float(tvb_data, offset   + 8, ENC_LITTLE_ENDIAN);
  const gfloat z = tvb_get_ieee_float(tvb_data, offset   + 12, ENC_LITTLE_ENDIAN);
  const gfloat y = tvb_get_ieee_float(tvb_data, offset   + 16, ENC_LITTLE_ENDIAN);

  col_append_fstr(pinfo->cinfo, COL_INFO, " (X=%.2f, Y=%.2f, Z=%.2f, LoS=%.2f)", x, y, z, los);
}

static void
data_msg_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 type)
{
  col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(type, &data_msg_opcode_str, "Unknown data (0x%04x)"));

  switch (type)
  {
  case FFXIV_DATA_MSG_CHANGE_GEARSET:
    data_dissect_gearset_change(tvb, pinfo, tree);
    break;
  case FFXIV_DATA_MSG_MOVE_PLAYER:
    data_dissect_player_move(tvb, pinfo, tree);
    break;
  case FFXIV_DATA_MSG_TIME_SYNC:
    data_dissect_server_clock_sync(tvb, pinfo, tree);
    break;

  case FFXIV_DATA_MSG_TARGET_INTERACT:
    data_dissect_target_interact(tvb, pinfo, tree);
    break;

  default:
    proto_tree_add_item(tree, hf_ffxiv_data_raw, tvb, 0, tvb_reported_length(tvb), ENC_STR_HEX);
    break;
  }
}

static guint16
data_msg_get_opcode(tvbuff_t *tvb)
{
  return tvb_get_letohs(tvb, 18);
}

static void
status_message_dissect_data(tvbuff_t *tvb_msg, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_ffxiv_data_epoch_seconds, tvb_msg, 0, 4, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
}

static void
msg_register_header(int proto_id)
{
  static hf_register_info field_ids[] =
  {
    {&hf_ffxiv_message,                     {"Message",        "ffxiv.message",
        FT_NONE,   BASE_NONE, NULL,                          0x0, "", HFILL}},
    {&hf_ffxiv_msg_header_size,             {"Size",           "ffxiv.message.size",
        FT_UINT32, BASE_DEC,  NULL,                          0x0, "", HFILL}},
    {&hf_ffxiv_msg_header_source,           {"Source ID",      "ffxiv.message.source",
        FT_UINT32, BASE_DEC,  NULL,                          0x0, "", HFILL}},
    {&hf_ffxiv_msg_header_destination,      {"Destination ID", "ffxiv.message.destination",
        FT_UINT32, BASE_DEC,  NULL,                          0x0, "", HFILL}},
    {&hf_ffxiv_msg_header_type,             {"Message type",   "ffxiv.message.type",
        FT_UINT32, BASE_DEC,  VALS(msg_type_str),            0x0, "", HFILL}},
    {&hf_ffxiv_data_msg_header_unknown_2,   {"Unknown 2",      "ffxiv.datamessage.unknown2",
        FT_UINT16, BASE_HEX,  NULL,                          0x0, "", HFILL}},
    {&hf_ffxiv_data_msg_header_opcode,      {"Opcode",         "ffxiv.datamessage.opcode",
        FT_UINT16, BASE_HEX,  VALS(data_msg_opcode_str),     0x0, "", HFILL}}
  };

  proto_register_field_array(proto_id, field_ids, array_length(field_ids));
}

static void
msg_dissect_header(tvbuff_t *tvb, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_ffxiv_msg_header_size,             tvb, 0,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_msg_header_source,           tvb, 4,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_msg_header_destination,      tvb, 8,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_msg_header_type,             tvb, 12, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_msg_header_unknown_2,   tvb, 16, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_data_msg_header_opcode,      tvb, 18, 2, ENC_LITTLE_ENDIAN);
}

static guint
msg_get_type(tvbuff_t *tvb)
{
  return tvb_get_letohl(tvb, 12);
}

static guint
msg_get_size(tvbuff_t *tvb)
{
  return tvb_get_letohl(tvb, 0);
}

static void
msg_dissect_any(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint msg_size)
{
  proto_item *heading = proto_tree_add_item(tree, hf_ffxiv_message, tvb, 0, msg_size, ENC_NA);
  proto_tree *msg_tree = proto_item_add_subtree(heading, ett_ffxiv);

  /* TODO Opcode and "unknown2" seem to have different meaning for each message type. */
  msg_dissect_header(tvb, msg_tree);
  const guint msg_type = msg_get_type(tvb);
  tvbuff_t *msg_data = tvb_new_subset_length(tvb, MSG_HEADER_SIZE, msg_size - MSG_HEADER_SIZE);

  switch (msg_type)
  {
    case FFXIV_MSG_CLIENT_STATUS:
    case FFXIV_MSG_SERVER_STATUS:
      // Special case: Display message type in COL_INFO
      col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_type, &msg_type_str, "Unknown service (%u)"));
      status_message_dissect_data(msg_data, tree);
      break;

    case FFXIV_MSG_INGAME_DATA:
      // Common case: Message contains game data. Msg decides what to display inside COL_INFO
      data_msg_dissect_data(msg_data, pinfo, msg_tree, data_msg_get_opcode(tvb));
      break;

    default:
      // Special case: Service is unknown. Append raw data and add COL_INFO
      col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_type, &msg_type_str, "Unknown service (%u)"));
      proto_tree_add_item(tree, hf_ffxiv_data_raw, tvb, 0, tvb_reported_length(tvb), ENC_STR_HEX);
  }
}

static void
frame_register_header(int proto_id)
{
  static hf_register_info field_ids[] =
  {
    {&hf_ffxiv_frame_header_sign,      {"Signature",          "ffxiv.frame.sign",
        FT_UINT16,        BASE_HEX,          NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_timestamp, {"Frame timestamp",    "ffxiv.frame.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_size,      {"Frame size"  ,       "ffxiv.frame.size",
        FT_UINT32,        BASE_DEC,          NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_unknown_1, {"Unknown 1",          "ffxiv.frame.unknown1",
        FT_UINT16,        BASE_DEC,          NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_msg_count, {"Number of messages", "ffxiv.frame.count",
        FT_UINT16,        BASE_DEC,          NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_unknown_2, {"Unknown 2",          "ffxiv.frame.unknown2",
        FT_UINT8,         BASE_DEC,          NULL, 0x00,   "", HFILL}},
    {&hf_ffxiv_frame_header_flags,     {"Compressed" ,        "ffxiv.frame.compressed",
        FT_BOOLEAN,       SEP_DOT,           NULL, 0x01,   "", HFILL}},
    {&hf_ffxiv_frame_header_unknown_3, {"Unknown 3",          "ffxiv.frame.unknown3",
        FT_UINT48,        BASE_DEC,          NULL, 0x00,   "", HFILL}}
  };

  proto_register_field_array(proto_id, field_ids, array_length(field_ids));
}

static guint
frame_get_size(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  return tvb_get_letohl(tvb, offset + 24);
}

static guint
frame_get_msg_count(tvbuff_t *tvb)
{
  return tvb_get_letohs(tvb, 30);
}

static void
frame_dissect_header(tvbuff_t *tvb, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_ffxiv_frame_header_sign,      tvb,  0, 2, ENC_LITTLE_ENDIAN);
  /* ... 14 bytes ignored ... */
  proto_tree_add_item(tree, hf_ffxiv_frame_header_timestamp, tvb, 16, 8, ENC_LITTLE_ENDIAN | ENC_TIME_MSECS);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_size,      tvb, 24, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_unknown_1, tvb, 28, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_msg_count, tvb, 30, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_unknown_2, tvb, 32, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_flags,     tvb, 33, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_header_unknown_3, tvb, 34, 6, ENC_LITTLE_ENDIAN);
}

static guint8
frame_is_compressed(tvbuff_t *tvb)
{
  return tvb_get_guint8(tvb, 33) & FRAME_FLAG_DEFLATE;
}

static tvbuff_t*
frame_decompress_payload(tvbuff_t *tvb, packet_info *pinfo)
{
  tvbuff_t *result = tvb_child_uncompress(tvb, tvb, 0, tvb_reported_length(tvb));

  if (!result)
    proto_report_dissector_bug("Payload deflate failed.");

  add_new_data_source(pinfo, result, "Decompressed payload");
  return result;
}


static void
frame_dissect_payload(tvbuff_t *payload_tvb, packet_info *pinfo, proto_tree *tree, gint messages)
{
  int i = 0;
  guint next_msg_at = 0;

  for (; i < messages; ++i)
  {
    if (next_msg_at > tvb_reported_length(payload_tvb))
      proto_report_dissector_bug("Out of range access: %u > %u", next_msg_at, tvb_reported_length(payload_tvb));

    tvbuff_t *msg = tvb_new_subset_remaining(payload_tvb, next_msg_at);
    const guint msg_size = msg_get_size(msg);
    next_msg_at += msg_size;

    msg_dissect_any(msg, pinfo, tree, msg_size);
  }
}

static int
dissect_ffxiv_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (tvb_captured_length(tvb) < tvb_reported_length(tvb))
    proto_report_dissector_bug("Captured frame is sliced: %u < %u", tvb_captured_length(tvb), tvb_reported_length(tvb));

  if (tvb_captured_length(tvb) < FRAME_HEADER_SIZE)
    proto_report_dissector_bug("Frame too small: %u < %u", tvb_reported_length(tvb), FRAME_HEADER_SIZE);

  proto_item *ffxiv_root = proto_tree_add_item(tree, proto_ffxiv_id, tvb, 0, -1, ENC_NA);
  proto_tree *ffxiv_tree = proto_item_add_subtree(ffxiv_root, ett_ffxiv);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo, COL_INFO);

  frame_dissect_header(tvb, ffxiv_tree);

  tvbuff_t* payload = tvb_new_subset_remaining(tvb, FRAME_HEADER_SIZE);

  if (frame_is_compressed(tvb))
    payload = frame_decompress_payload(payload, pinfo);

  const int messages = frame_get_msg_count(tvb);

  frame_dissect_payload(payload, pinfo, ffxiv_tree, messages);

  return tvb_captured_length(tvb);
}

static void
register_ffxiv_tcp_port(guint32 port, gpointer ptr _U_)
{
  dissector_add_uint("tcp.port", port, ffxiv_handle);
}


static void
proto_ffxiv_register_prefs(void)
{
  static module_t *ffxiv_prefs = NULL;

  ffxiv_prefs = prefs_register_protocol(proto_ffxiv_id, NULL);

  range_convert_str(wmem_epan_scope(), &ffxiv_port_range, "54992-54994,55006,55007,55021-55040", 55040);
  prefs_register_range_preference(ffxiv_prefs, "tcp.port", "FFXIV port range",
      "Range of ports to look for FFXIV traffic on", &ffxiv_port_range, 55551);
}

static int
dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_SIZE, frame_get_size, dissect_ffxiv_frame, data);
  return tvb_captured_length(tvb);
}

void
proto_register_ffxiv(void)
{
  static gint *ett[] = { &ett_ffxiv };
  proto_register_subtree_array(ett, array_length(ett));

  proto_ffxiv_id = proto_register_protocol("Final Fantasy XIV protocol", "FFXIV", "ffxiv");
  proto_ffxiv_register_prefs();

  frame_register_header(proto_ffxiv_id);
  msg_register_header(proto_ffxiv_id);
  data_register(proto_ffxiv_id);
}

void
proto_reg_handoff_ffxiv(void)
{
  ffxiv_handle = register_dissector("ffxiv", dissect_ffxiv, proto_ffxiv_id);
  range_foreach(ffxiv_port_range, register_ffxiv_tcp_port, NULL);
}
