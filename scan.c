//
//  Intel Edison Playground
//  Copyright (c) 2015 Damian Kołakowski. All rights reserved.
//

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define LE_LINK		0x80

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */
#define EIR_MANUFACTURER_SPECIFIC   0xFF  /* Manufacturer specific data */

struct hci_request ble_hci_request(uint16_t ocf, int clen, void * status, void * cparam)
{
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LE_CTL;
	rq.ocf = ocf;
	rq.cparam = cparam;
	rq.clen = clen;
	rq.rparam = status;
	rq.rlen = 1;
	return rq;
}

static void eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

static void eir_parse_manuf_data(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t manuf_data_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_MANUFACTURER_SPECIFIC:
			manuf_data_len = field_len - 1;
			if (manuf_data_len > buf_len)
				goto failed;

			buf[0] = '\0';
			uint8_t i;
			for (i = 0; i < manuf_data_len && i < buf_len; i++){
				sprintf(buf + (i * 2), "%2.2X", eir[2+i]);
			}
			//memcpy(buf, &eir[2], manuf_data_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}
failed:
	snprintf(buf, buf_len, "(unknown)");
}

/*static void manuf_data_to_str(uint8_t * manuf_data, char *manuf_data_str){
	uint8_t len = 2; //skip manufacturer id
	while( manuf_data[len] != 0){
		len++;
	}
	
	uint8_t i;

	manuf_data_str[len] = '\0';

	for (i = 0; i < len; i++)
		sprintf(manuf_data_str + (i * 2), "%2.2X", manuf_data[i]);
	
	return;
}*/

int main()
{
	int ret, status;

	// Get HCI device.

	const int device = hci_open_dev(hci_get_route(NULL));
	if ( device < 0 ) { 
		perror("Failed to open HCI device.");
		return 0; 
	}

	// Set BLE scan parameters.
	
	le_set_scan_parameters_cp scan_params_cp;
	memset(&scan_params_cp, 0, sizeof(scan_params_cp));
	scan_params_cp.type 			= 0x00; 
	scan_params_cp.interval 		= htobs(0x0010);
	scan_params_cp.window 			= htobs(0x0010);
	scan_params_cp.own_bdaddr_type 	= 0x00; // Public Device Address (default).
	scan_params_cp.filter 			= 0x00; // Accept all.

	struct hci_request scan_params_rq = ble_hci_request(OCF_LE_SET_SCAN_PARAMETERS, LE_SET_SCAN_PARAMETERS_CP_SIZE, &status, &scan_params_cp);
	
	ret = hci_send_req(device, &scan_params_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set scan parameters data.");
		return 0;
	}

	// Set BLE events report mask.

	le_set_event_mask_cp event_mask_cp;
	memset(&event_mask_cp, 0, sizeof(le_set_event_mask_cp));
	int i = 0;
	for ( i = 0 ; i < 8 ; i++ ) event_mask_cp.mask[i] = 0xFF;

	struct hci_request set_mask_rq = ble_hci_request(OCF_LE_SET_EVENT_MASK, LE_SET_EVENT_MASK_CP_SIZE, &status, &event_mask_cp);
	ret = hci_send_req(device, &set_mask_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to set event mask.");
		return 0;
	}

	// Enable scanning.

	le_set_scan_enable_cp scan_cp;
	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable 		= 0x01;	// Enable flag.
	scan_cp.filter_dup 	= 0x00; // Filtering disabled.

	struct hci_request enable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);

	ret = hci_send_req(device, &enable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to enable scan.");
		return 0;
	}

	// Get Results.

	struct hci_filter nf;
	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);
	if ( setsockopt(device, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0 ) {
		hci_close_dev(device);
		perror("Could not set socket options\n");
		return 0;
	}

	printf("Scanning....\n");

	
	time_t rawtime;
	struct tm *time_info;
	char filename[80];
	time( &rawtime );
	time_info = localtime( &rawtime );
	strftime(filename,80,"log_%j_%H.%M.%S.txt", time_info);
	
	FILE * fp;
	fp = fopen( filename, "w+" );
	
	char human_timestamp[80];
	uint32_t timestamp = (unsigned)time(NULL);
	uint64_t timestamp_ms = timestamp*1000; //TODO: find a way to calculate the correct millis
	memset(human_timestamp, 0, sizeof(human_timestamp));
	strftime(human_timestamp,80,"%Y %m %d %H %M %S", time_info);
	fprintf(fp, "%s %d NO_ADDRESS LOCAL_DEVICE TAG Start_Monitoring 0.0.1\n", human_timestamp, timestamp_ms );

	
	uint8_t buf[HCI_MAX_EVENT_SIZE];
	evt_le_meta_event * meta_event;
	le_advertising_info * info;
	int len;

	setvbuf(stdout, NULL, _IONBF, 0);

	while ( 1 ) {
		len = read(device, buf, sizeof(buf));
		if ( len >= HCI_EVENT_HDR_SIZE ) {
			meta_event = (evt_le_meta_event*)(buf+HCI_EVENT_HDR_SIZE+1);
			if ( meta_event->subevent == EVT_LE_ADVERTISING_REPORT ) {
				uint8_t reports_count = meta_event->data[0];
				void * offset = meta_event->data + 1;
				while ( reports_count-- ) {
					info = (le_advertising_info *)offset;
					char addr[18];
					ba2str(&(info->bdaddr), addr);
					char name[30];
					memset(name, 0, sizeof(name));
					eir_parse_name(info->data, info->length, name, sizeof(name) - 1);
					char manuf_data_str[60];
					memset(manuf_data_str, 0, sizeof(manuf_data_str));
					eir_parse_manuf_data(info->data, info->length, manuf_data_str, sizeof(manuf_data_str) - 1);
					/*char manuf_data_str[60];
					manuf_data_to_str(manuf_data,manuf_data_str);*/
					if(strcmp(name, "CLIMBM") == 0 || strcmp(name, "CLIMBC") == 0){
						time( &rawtime );
						time_info = localtime( &rawtime );
											
						memset(human_timestamp, 0, sizeof(human_timestamp));
						strftime(human_timestamp,80,"%Y %m %d %H %M %S", time_info);
						
						printf("%d %s %s ADV %d %s\n", timestamp_ms, addr, name,(signed char)info->data[info->length],&manuf_data_str[4]);
						fprintf(fp, "%s %d %s %s ADV %d %s\n", human_timestamp, timestamp_ms, addr, name,(signed char)info->data[info->length],&manuf_data_str[4]);
					}
					offset = info->data + info->length + 2;
				}
			}
		}
	}

	fclose(fp);
	
	// Disable scanning.

	memset(&scan_cp, 0, sizeof(scan_cp));
	scan_cp.enable = 0x00;	// Disable flag.

	struct hci_request disable_adv_rq = ble_hci_request(OCF_LE_SET_SCAN_ENABLE, LE_SET_SCAN_ENABLE_CP_SIZE, &status, &scan_cp);
	ret = hci_send_req(device, &disable_adv_rq, 1000);
	if ( ret < 0 ) {
		hci_close_dev(device);
		perror("Failed to disable scan.");
		return 0;
	}

	hci_close_dev(device);
	
	return 0;
}