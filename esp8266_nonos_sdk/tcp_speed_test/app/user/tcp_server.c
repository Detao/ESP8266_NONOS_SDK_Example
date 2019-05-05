/*
 * tcp_server.c
 *
 *  Created on: 2019��4��3��
 *      Author: Deive
 */




/*
 * tcp_server.c
 */

#include "ets_sys.h"
#include "osapi.h"
#include "user_interface.h"
#include "mem.h"
#include "espconn.h"

#include "tcp_server.h"
#include "user_hw_timer.h"

#define TCP_BUFF_SIZE		2000
static u8 g_tcp_buff[TCP_BUFF_SIZE];

u32 tcp_recv_byte_count = 0;

/*
 * function: tcp_server_sent_cb
 * parameter: void *arg - ���ӽṹ��
 * return: void
 * description: TCP Server���ͻص�
 */
static void ICACHE_FLASH_ATTR
tcp_server_sent_cb(void *arg) {
// TODO:
}

/*
 * function:tcp_server_discon_cb
 * parameter: void *arg - ���ӽṹ��
 * return:void
 * description: TCP Server�Ͽ��ص�
 */
static void ICACHE_FLASH_ATTR
tcp_server_discon_cb(void *arg) {
	// TODO:
}

/*
 * function: tcp_server_recv
 * parameter: void *arg - ���ӽṹ��
 * 	   char *pdata - ���������׵�ַ
 * 	   unsigned short len - �������ݳ���
 * return: void
 * description: TCP Server���ջص�
 */
static void ICACHE_FLASH_ATTR
tcp_server_recv(void *arg, char *pdata, unsigned short len) {
	struct espconn *pesp_conn = arg;
	u16 send_data_len = 0;

// TODO:
	tcp_recv_byte_count += len;
//	espconn_send(pesp_conn, pdata, len);
}

/*
 * function: tcp_server_listen
 * parameter: void *arg - ���ӽṹ��
 * return: void
 * description: TCP Server����
 */
static void ICACHE_FLASH_ATTR
tcp_server_listen(void *arg) {
	struct espconn *pesp_conn = arg;

	espconn_regist_disconcb(pesp_conn, tcp_server_discon_cb);
	espconn_regist_recvcb(pesp_conn, tcp_server_recv);
	espconn_regist_sentcb(pesp_conn, tcp_server_sent_cb);
//espconn_regist_reconcb(pesp_conn, client_recon_cb);

}

/*
 * function: tcp_server_init
 * parameter: void *arg - ���ӽṹ��
 * return: void
 * description: TCP Server init
 */
void ICACHE_FLASH_ATTR
tcp_server_init(uint32 port) {
	static struct espconn s_tcp_server;
	static esp_tcp s_esptcp;

	s_tcp_server.type = ESPCONN_TCP;
	s_tcp_server.state = ESPCONN_NONE;
	s_tcp_server.proto.tcp = &s_esptcp;
	s_tcp_server.proto.tcp->local_port = port;
	espconn_regist_connectcb(&s_tcp_server, tcp_server_listen);

	espconn_accept(&s_tcp_server);
	espconn_regist_time(&s_tcp_server, 60, 0);			// TCP server timeout

	os_printf("tcp_server_init\r\n");
}
