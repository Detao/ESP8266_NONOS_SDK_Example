#include "functions.h"
#include "esp_log.h"
#include "esp_wifi_types.h"

uint8_t broadcast1[3] = { 0x01, 0x00, 0x5e };
uint8_t broadcast2[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t broadcast3[3] = { 0x33, 0x33, 0x00 };
#define MAX_APS_TRACKED 50
#define MAX_CLIENTS_TRACKED 100
#undef PRINT_RAW_HEADER   // define this to print raw packet headers
#undef PERIODIC  //define this to get summary of new and expired entries periodically

extern int aps_known_count ; 

extern beaconinfo aps_known[MAX_APS_TRACKED];                    // Array to save MACs of known APs
extern int nothing_new;
extern clientinfo clients_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
extern int clients_known_count;                              // Number of known CLIENTs
extern probeinfo probes_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
extern int probes_known_count ;

//parse out details of client frame
struct clientinfo parse_data(uint8_t *frame, uint16_t framelen, signed rssi, unsigned channel)
{
  // takes 36 byte frame control frame
  struct clientinfo ci;
  ci.channel = channel;
  ci.err = 0;
  ci.rssi = rssi;
  ci.header=frame[0];
  //ci.last_heard=millis()/1000;    //dt
  ci.reported=0;
  //int pos = 36;
  uint8_t *bssid=NULL;
  uint8_t *station=NULL;
  uint8_t *ap=NULL;
  uint8_t ds;
  ds = frame[1] & 3;    //Set first 6 bits to 0
  switch (ds) {
    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
    case 0:
      bssid = frame + 16;
      station = frame + 10;
      ap = frame + 4;
      break;
    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
    case 1:
      bssid = frame + 4;
      station = frame + 10;
      ap = frame + 16;
      break;
    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
    case 2:
      bssid = frame + 10;
      // hack - don't know why it works like this...
      if (memcmp(frame + 4, broadcast1, 3) || memcmp(frame + 4, broadcast2, 3) || memcmp(frame + 4, broadcast3, 3)) {
        station = frame + 16;
        ap = frame + 4;
      } else {
        station = frame + 4;
        ap = frame + 16;
      }
      break;
    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
    case 3:
      bssid = frame + 10;
      station = frame + 4;
      ap = frame + 4;
      break;
  }

  memcpy(ci.station, station, ETH_MAC_LEN);
  memcpy(ci.bssid, bssid, ETH_MAC_LEN);
  memcpy(ci.ap, ap, ETH_MAC_LEN);

  ci.seq_n = frame[23] * 0xFF + (frame[22] & 0xF0);
  return ci;
}



struct beaconinfo parse_beacon(uint8_t *frame, uint16_t framelen, signed rssi)
{
  // takes 112 byte beacon frame
  struct beaconinfo bi;
  bi.ssid_len = 0;
  bi.channel = 0;
  bi.err = 0;
  bi.rssi = rssi;
  //bi.last_heard=millis()/1000;
  bi.reported=0;
  bi.header=frame[0];
  int pos = 36;
  uint8_t frame_type= (frame[0] & 0x0C)>>2;
  uint8_t frame_subtype= (frame[0] & 0xF0)>>4;
  if (frame[pos] == 0x00) {
    while (pos < framelen) {
      switch (frame[pos]) {
        case 0x00: //SSID
          bi.ssid_len = (int) frame[pos + 1];
          if (bi.ssid_len == 0) {
            memset(bi.ssid, '\x00', 33);
            break;
          }
          if (bi.ssid_len < 0) {
            bi.err = -1;
            break;
          }
          if (bi.ssid_len > 32) {
            bi.err = -2;
            break;
          }
          memset(bi.ssid, '\x00', 33);
          memcpy(bi.ssid, frame + pos + 2, bi.ssid_len);
          bi.err = 0;  // before was error??
          break;
        case 0x03: //Channel
          bi.channel = (int) frame[pos + 2];
          pos = -1;
          break;
        default:
          break;
      }
      if (pos < 0) break;
      pos += (int) frame[pos + 1] + 2;
    }
  } else {
    bi.err = -3;
  }

  bi.capa[0] = frame[34];
  bi.capa[1] = frame[35];
  memcpy(bi.bssid, frame + 10, ETH_MAC_LEN);
  return bi;
};

struct probeinfo parse_probe(uint8_t *frame, uint16_t framelen, signed rssi)
{
  // takes 112 byte probe request frame
  struct probeinfo pi;
  pi.ssid_len = 0;
  pi.channel = 0;
  pi.err = 0;
  pi.rssi = rssi;
  //pi.last_heard=millis()/1000;
  pi.reported=0;
  pi.header=frame[0];
  int pos = 24;
  uint8_t frame_type= (frame[0] & 0x0C)>>2;
  uint8_t frame_subtype= (frame[0] & 0xF0)>>4;
   
  if (frame[pos] == 0x00) {
    pi.ssid_len = (int) frame[pos + 1];
    if (pi.ssid_len == 0) {
      memset(pi.ssid, '\x00', 33);
    }
    if (pi.ssid_len < 0) {
      pi.err = -1;
    }
    if (pi.ssid_len > 32) {
      pi.err = -2;
    }
    memset(pi.ssid, '\x00', 33);
    memcpy(pi.ssid, frame + pos + 2, pi.ssid_len);
    pi.err = 0;  // before was error??
  } else {
    pi.err = -3;
  }
  
  if (pi.err!=0){
    printf("Error parsing PROBE %d",(int)pi.err);
  }
  memcpy(pi.ap, frame+4, ETH_MAC_LEN);
  memcpy(pi.station, frame+10, ETH_MAC_LEN);
  memcpy(pi.bssid, frame+16, ETH_MAC_LEN);
  return pi;
}


int register_beacon(beaconinfo beacon)
{
  // add beacon to list if not already included
  int known = 0;   // Clear known flag
  for (int u = 0; u < aps_known_count; u++)
  {
    if (! memcmp(aps_known[u].bssid, beacon.bssid, ETH_MAC_LEN)) {
      known = 1;
      aps_known[u].last_heard = beacon.last_heard;
      break;
    }   // AP known => Set known flag
  }
  if (! known)  // AP is NEW, copy MAC to array and return it
  {
    memcpy(&aps_known[aps_known_count], &beacon, sizeof(beacon));
    aps_known_count++;

    if ((unsigned int) aps_known_count >=
        sizeof (aps_known) / sizeof (aps_known[0]) ) {
      printf("exceeded max aps_known\n");
      aps_known_count = 0;
    }
  }
  return known;
}

int register_client(clientinfo ci)
{
  // add client to list if not already included
  int known = 0;   // Clear known flag
  for (int u = 0; u < clients_known_count; u++)
  {
    if (! memcmp(clients_known[u].station, ci.station, ETH_MAC_LEN)) {
      known = 1;
      clients_known[u].last_heard = ci.last_heard;
      break;
    }
  }
  if (! known)
  {
    memcpy(&clients_known[clients_known_count], &ci, sizeof(ci));
    clients_known_count++;

    if ((unsigned int) clients_known_count >=
        sizeof (clients_known) / sizeof (clients_known[0]) ) {
      printf("exceeded max clients_known\n");
      clients_known_count = 0;
    }
  }
  return known;
}

int register_probe(probeinfo pi)
{
  //add probe to list if not already included.
  int known = 0;   // Clear known flag
  for (int u = 0; u < probes_known_count; u++)
  {
    if ((memcmp(probes_known[u].station, pi.station, ETH_MAC_LEN)==0)
       && (memcmp(probes_known[u].bssid, pi.bssid, ETH_MAC_LEN)==0 )
       && (strncmp((char*)probes_known[u].ssid, (char*)pi.ssid, sizeof(pi.ssid)) ==0 )) {
      known = 1;
      probes_known[u].last_heard = pi.last_heard;
      break;
    }
  }
  if (! known)
  {
    memcpy(&probes_known[probes_known_count], &pi, sizeof(pi));
    probes_known_count++;

    if ((unsigned int) probes_known_count >=
        sizeof (probes_known) / sizeof (probes_known[0]) ) {
      printf("exceeded max probes_known\n");
      probes_known_count = 0;
    }
  }
  return known;
}

void print_beacon(beaconinfo beacon)
{
 int now = 1000;//millis()/1000;
  if (beacon.err != 0) {
    printf("BEACON ERR: (%d)  \r\n", beacon.err);
  } else {
    printf("BEACON: <=============== [%32s]  ", beacon.ssid);
    for (int i = 0; i < 6; i++) printf("%02x", beacon.bssid[i]);
    //printf(" %02x", beacon.header);
    printf(" %3d", beacon.channel);
    printf("   %d", (now - beacon.last_heard));
    printf("   %d", (beacon.reported));
    printf("   %4d\r\n", beacon.rssi);

  }
}

void print_client(clientinfo ci)
{
  int u = 0;
  int known = 0;   // Clear known flag
  //uint64_t now = millis()/1000; //by bt
  int now = 1000;
  if (ci.err != 0) {
    printf("ci.err %02d", ci.err);
    printf("\r\n");
  } else {
    printf("DEVICE: ");
    for (int i = 0; i < 6; i++) printf("%02x", ci.station[i]);
    printf(" ==> ");

    for (u = 0; u < aps_known_count; u++)
    {
      if (! memcmp(aps_known[u].bssid, ci.bssid, ETH_MAC_LEN)) {
        printf("[%32s]  ", aps_known[u].ssid);
        known = 1;     // AP known => Set known flag
        break;
      }
    }

    if (! known)  {
      printf("[%32s]  ", "??");    
    };
    for (int i = 0; i < 6; i++) printf("%02x", ci.bssid[i]);
    printf(" %3d", ci.channel);
    printf("   %d", (now - ci.last_heard));
    printf("   %d", (ci.reported));      
    printf("   %4d\r\n", ci.rssi);
  }
}

void print_probe(probeinfo ci)
{
  int u = 0;
  int known = 0;   // Clear known flag
  int now = 1000;//millis()/1000;
  if (ci.err != 0) {
    printf("ci.err %02d", ci.err);
    printf("\r\n");
  } else {
    printf("PROBE:  ");
    for (int i = 0; i < 6; i++) printf("%02x", ci.station[i]);
    printf(" ==> ");
    printf("[%32s]  ", ci.ssid);
    for (int i = 0; i < 6; i++) printf("%02x", ci.bssid[i]);
    printf(" %3d", ci.channel); 
    printf("   %d", (now - ci.last_heard));
    printf("   %d", (ci.reported));      
    printf("   %4d\r\n", ci.rssi);
  }
};


void print_pkt_header(uint8_t *buf, uint16_t len, char *pkt_type)
{
  char ssid_name[33];
  memset(ssid_name, '\x00', 33);
  printf("%s", pkt_type);
  uint8_t frame_control_pkt = buf[12]; // just after the RxControl Structure
  uint8_t protocol_version = frame_control_pkt & 0x03; // should always be 0x00
  uint8_t frame_type = (frame_control_pkt & 0x0C) >> 2;
  uint8_t frame_subtype = (frame_control_pkt & 0xF0) >> 4;
  uint8_t ds= buf[13] & 0x3;
  
  // print the 3 MAC-address fields
  printf("%02x %02x %02x ", frame_type, frame_subtype, ds);
  if (len<35) {
    printf("Short Packet!! %d\r\n",len);
    return;
  }
  for (int n = 16; n < 22; n++) {
    printf("%02x", buf[n]);
  };
  printf(" ");
  for (int n = 22; n < 28; n++) {
    printf("%02x", buf[n]);
  };
  printf(" ");
  for (int n = 28; n < 34; n++) {
    printf("%02x", buf[n]);
  };
  //ACTION frames are 112 long but contain nothing useful
  if (len>=112 && !( frame_type==0 && frame_subtype==13)) {
    
    int pos=49;
    if (frame_type==0 && frame_subtype==4) {
      pos=37; // probe request frames
    }
    
    int bssid_len=(int) buf[pos];
    if(bssid_len<0 || bssid_len>32) {
      printf(" Bad ssid len %d!!\r\n",bssid_len);
      return;
    };
    if (bssid_len==0) {
      printf(" <open>");
    } else {
      memcpy(ssid_name,&(buf[pos+1]),bssid_len);
      printf(" %s",ssid_name);
    };
    printf(":%d %d %d ",(int)buf[pos+bssid_len+1],(int)buf[pos+bssid_len+2],(int)buf[pos+bssid_len+3]);
  
  };
  printf("\r\n");
}

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    uint16_t seq_n_new = 0;
    wifi_pkt_rx_ctrl_t* rx_ctrl = (wifi_pkt_rx_ctrl_t*)buf;
    uint8_t* frame = (uint8_t*)(rx_ctrl + 1);
    uint32_t len = rx_ctrl->sig_mode ? rx_ctrl->HT_length : rx_ctrl->legacy_length;
    uint32_t i;

    uint8_t total_num = 1, count = 0;
    uint16_t seq_buf = 0;

    // if ((rx_ctrl->aggregation) && (type != WIFI_PKT_MISC)) {
    //     total_num = rx_ctrl->ampdu_cnt;
    // }

    // for (count = 0; count < total_num; count++) {
    //     if (total_num > 1) {
    //         len = *((uint16_t*)(frame + MAC_HDR_LEN_MAX + 2 * count));

    //         if (seq_buf == 0) {
    //             seq_buf = *((uint16_t*)(frame + 22)) >> 4;
    //         }

    //         ESP_LOGI(TAG, "seq_num:%d, total_num:%d\r\n", seq_buf, total_num);
    //     }
   
#ifdef PRINT_RAW_HEADER
  //if (len >= 35) {
    uint8_t frame_control_pkt = *((uint8_t*)buf+12); // just after the RxControl Structure
    uint8_t protocol_version = frame_control_pkt & 0x03; // should always be 0x00
    uint8_t frame_type = (frame_control_pkt & 0x0C) >> 2;
    uint8_t frame_subtype = (frame_control_pkt & 0xF0) >> 4;
    
    struct control_frame *cf=(struct control_frame *)&buf[12];
      
         switch (type) {
           case WIFI_PKT_MGMT: /**< Management frame, indicates 'buf' argument is wifi_promiscuous_pkt_t */
            switch (cf->subtype) {
              case 0:
               print_pkt_header(buf,len,"ASREQ:");
               break;
              case 1:
               print_pkt_header(buf,len,"ASRSP:");
               break;
              case 2:
               print_pkt_header(buf,len,"RSRSP:");
               break;
              case 3:
               print_pkt_header(buf,len,"RSRSP:");
               break;
              case 4:
               print_pkt_header(buf,len,"PRREQ:");
               break;
              case 5:
               print_pkt_header(buf,len,"PRRSP:");
               break;
              case 8:
               print_pkt_header(buf,len,"BECON:");
               break;
              case 9:
               print_pkt_header(buf,len,"ATIM :");
               break;
              case 10:
               print_pkt_header(buf,len,"DASSO:");
               break;
              case 11:
               print_pkt_header(buf,len,"AUTH :");
               break;
              case 12:
               print_pkt_header(buf,len,"DAUTH:");
               break;
              case 13:
               print_pkt_header(buf,len,"ACTON:");
               break;
              default:
               print_pkt_header(buf,len,"MGMT?:");
               break;
            };
            break;
           case WIFI_PKT_CTRL: /**< Control frame, indicates 'buf' argument is wifi_promiscuous_pkt_t */
             print_pkt_header(buf,len,"CONTR:");
             break;
           case WIFI_PKT_DATA:
             print_pkt_header(buf,len,"DATA :");
             break;
           default:
             print_pkt_header(buf,len,"UNKNOW:");
         }
    
  //}
  #endif

  if (type == 12) {
    struct RxControl *sniffer = (struct RxControl*) buf;
  } else if (type == WIFI_PKT_MGMT || type ==WIFI_PKT_CTRL) {
    uint8_t frame_control_pkt = *((uint8_t*)buf+12); // just after the RxControl Structure
    uint8_t frame_type = (frame_control_pkt & 0x0C) >> 2;
    uint8_t frame_subtype = (frame_control_pkt & 0xF0) >> 4;
    struct sniffer_buf2 *sniffer = (struct sniffer_buf2*) buf;
    if (frame_type == 0 && (frame_subtype == 8 || frame_subtype == 5))
      {
        struct beaconinfo beacon = parse_beacon(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
        if (register_beacon(beacon) == 0)
        {
          print_beacon(beacon);
          nothing_new = 0;
        };
      } else if (frame_type ==0 && frame_subtype==4) {
        struct probeinfo probe = parse_probe(sniffer->buf, 112, sniffer->rx_ctrl.rssi);
        if (register_probe(probe) == 0)
        {
          print_probe(probe);
          nothing_new = 0;
        };
      } else {
       // print_pkt_header(buf,112,"UKNOWN:");
      };
  } else{
    struct sniffer_buf *sniffer = (struct sniffer_buf*) buf;
    struct clientinfo ci = parse_data(sniffer->buf, 36, sniffer->rx_ctrl.rssi, sniffer->rx_ctrl.channel);
    if (register_client(ci) == 0) {
      print_client(ci);
      nothing_new = 0;
    }
  }
}