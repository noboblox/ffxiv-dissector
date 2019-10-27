#include <stdint.h>
#include <stdio.h>

#define FRAME_HEADER_LEN 40
#define BLOCK_HEADER_LEN 24

static dissector_handle_t ffxiv_handle;
static gint ett_ffxiv = -1;


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

/*
  So the block type could be uint16_t[14:15] in which case the mystery1 is
  uint16_t[12:13] and the subsequent mystery data resumes
  for some subset of uint128_t[16:31], ie:

  typedef struct {
    uint32_t  block_length;  // [0:3]
    uint64_t  entity_id;     // [4:11]
    uint16_t  mystery1;      // [12:13]
    uint16_t  block_type;    // [14:15]
    uint32_t  mystery2;      // [16:19]
    uint32_t  mystery3;      // [20:23]
    uint64_t  mystery4;      // [24:31]
  } block_header_t;
*/
typedef struct {
  uint32_t length;      // [0:3]
  uint32_t send_id;     // [4:7]
  uint32_t recv_id;     // [8:11]
  uint32_t mystery1;    // [12:15]
  uint32_t block_type;  // [16:19]
  uint32_t mystery2;    // these could be smaller, no idea what's after header[20:]
  uint64_t timestamp;   // [24:31]
} block_header_t;

// Utility methods
static guint32 get_frame_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static guint32 get_message_length(packet_info* pinfo, tvbuff_t *tvb, int offset, void* data);
static void build_frame_header(tvbuff_t *tvb, int offset, packet_info*, proto_tree *tree, frame_header_t *eh_ptr);
static void build_message_header(tvbuff_t *tvb, int offset, packet_info*, proto_tree *tree, block_header_t *eh_ptr);

// Dissection methods
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
