/* sniffer example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_libc.h"
#include "functions.h"
#define TAG "sniffer"

#define MAX_APS_TRACKED 50
#define MAX_CLIENTS_TRACKED 100
#undef PRINT_RAW_HEADER   // define this to print raw packet headers
#undef PERIODIC  //define this to get summary of new and expired entries periodically

beaconinfo aps_known[MAX_APS_TRACKED];                    // Array to save MACs of known APs
int aps_known_count = 0;                                  // Number of known APs
int nothing_new = 0;
clientinfo clients_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
int clients_known_count = 0;                              // Number of known CLIENTs
probeinfo probes_known[MAX_CLIENTS_TRACKED];            // Array to save MACs of known CLIENTs
int probes_known_count = 0;

static EventGroupHandle_t wifi_event_group;

static const int START_BIT = BIT0;

static char printbuf[100];

unsigned int channel = 1;

static esp_err_t event_handler(void* ctx, system_event_t* event)
{
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            xEventGroupSetBits(wifi_event_group, START_BIT);
            break;

        default:
            break;
    }

    return ESP_OK;
}

static void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
}
void loop(void* pvParameters)
{
    channel = 1;
  esp_wifi_set_channel(channel,0);
  while (true) {
    nothing_new++;                          // Array is not finite, check bounds and adjust if required
    if (nothing_new > 200) {
      nothing_new = 0;
      channel++;
      if (channel == 15) break;             // Only scan channels 1 to 14
      esp_wifi_set_channel(channel,0);
    }
    vTaskDelay(2);   // critical processing timeslice for NONOS SDK! No delay(0) yield()
    // Press keyboard ENTER in console with NL active to repaint the screen
    
    //  printf("\n-------------------------------------------------------------------------------------\n");
    //   for (int u = 0; u < clients_known_count; u++) print_client(clients_known[u]);
    //   for (int u = 0; u < aps_known_count; u++) print_beacon(aps_known[u]);
    //   for (int u = 0; u < probes_known_count; u++) print_probe(probes_known[u]);
    //   printf("\n-------------------------------------------------------------------------------------\n");
  }

    
}
void app_main()
{
    ESP_ERROR_CHECK(nvs_flash_init());
    initialise_wifi();
    xEventGroupWaitBits(wifi_event_group, START_BIT,
                        false, true, portMAX_DELAY);
    printf("\n\nSDK version:%s\n\r", esp_get_idf_version());
    printf("ESP8266 mini-sniff\r\n");
    printf("Type:   /-------MAC------/-----WiFi Access Point SSID-----/  /----MAC---/  Chnl  RSSI\r\n");
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_CHANNEL, 0));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promisc_cb));
    //ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&sniffer_filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    xTaskCreate(&loop,"loop",2048,NULL,10,NULL);
   // vTaskDelete(NULL);
   // xTaskCreate(&sniffer_task, "sniffer_task", 2048, NULL, 10, NULL);
    
}