// include ESP8266 SDK functions
 #ifdef __cplusplus
extern "C" {
#endif
//#include "user_interface.h"
  // typedef void (*freedom_outside_cb_t)(uint8 status);
  // int  wifi_register_send_pkt_freedom_cb(freedom_outside_cb_t cb);
  // void wifi_unregister_send_pkt_freedom_cb(void);
  // int  wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);

#ifdef __cplusplus
}
#endif
#include "esp_wifi_types.h"
#include "structures.h"
struct clientinfo parse_data(uint8_t *frame, uint16_t framelen, signed rssi, unsigned channel);
struct beaconinfo parse_beacon(uint8_t *frame, uint16_t framelen, signed rssi);
struct probeinfo parse_probe(uint8_t *frame, uint16_t framelen, signed rssi);

int register_beacon(struct beaconinfo beacon);
int register_client(struct clientinfo ci);
int register_probe(struct probeinfo pi);

void print_beacon(struct beaconinfo beacon);
void print_client(struct clientinfo ci);
void print_probe(struct probeinfo ci);

void print_pkt_header(uint8_t *buf, uint16_t len, char *pkt_type);

void promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type);