#include<stdio.h>		// printf perror
#include<stdint.h>		// uint8_t
#include<stdlib.h>		// EXIT_FAILURE
#include<unistd.h>		// close
#include<string.h>		// memset
#include<sys/socket.h>		// socket
#include<sys/ioctl.h>		// ioctl
#include<netinet/in.h>		// IPPROTO_RAW
#include<net/if.h>		// struct ifreq
#include<linux/if_packet.h>	// sockaddr_ll
#include<linux/if_ether.h>	// ETH_P_IP
#include <arpa/inet.h>

#define ARP_HDRLEN 28
#define ETH_HDRLEN 14

/*
 *  struct for arp request header
 *  https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
 */
struct ARP_REQUEST_HDR          {
        uint16_t hardware_type;         //      Hardware type for Ethernet is 1
        uint16_t protocol_type;         //      Protocol type for IP is ETH_P_IP ( 0x0800 )
        uint8_t  hardware_length;       //      For Ethernet length is 6
        uint8_t  protocol_length;       //      For IP length is 4
        uint16_t operation_code;        //      Operation_code 1 for Request, 2 for Reply
        uint8_t  sender_mac[6];         //      Physical address for sender
        uint8_t  sender_ip[4];          //      Logical address for sender
        uint8_t  target_mac[6];         //      Field is not set in ARP request
        uint8_t  target_ip[4];          //      Logical address for target
};

void get_interface_info(const char *interface, uint8_t *ip, uint8_t *mac);
void update_device_ll(struct sockaddr_ll *device, const char *interface, const uint8_t *mac);

int main(int argc, char *argv[]){

	char *interface = "wlp0s20f3";
	uint8_t target_ip[4];
	uint8_t target_mac[4];

        int sock_fd, bytes_read, status;

	struct sockaddr_ll device;
  	memset (&device, 0, sizeof (device));

	/*
	 * Creating buffer to hold ethernet header and arp header
	 * and clearing it
	 */
	uint8_t ethernet_frame[1024];
        memset(ethernet_frame, 0, sizeof(ethernet_frame));

	/*
         *  Creating an arp header and clearing it
         */
        struct ARP_REQUEST_HDR arp_request_header;
        memset(&arp_request_header, 0, sizeof(arp_request_header));

	//=========== filling the arp header =======================
        arp_request_header.hardware_type 	= htons(1);
        arp_request_header.protocol_type 	= htons(ETH_P_IP);
        arp_request_header.hardware_length 	= 6;
        arp_request_header.protocol_length 	= 4;
        arp_request_header.operation_code 	= htons(1);

	// Fill interface ip adress and mac address
	get_interface_info(interface, arp_request_header.sender_ip, arp_request_header.sender_mac);

	// sender_ip and target_ip will be same for GARP
	memcpy(arp_request_header.target_ip , arp_request_header.sender_ip,  4 * sizeof(uint8_t));
	memset(arp_request_header.target_mac, 0xff,       6 * sizeof(uint8_t));

	// Prepare frame to be sent
	memcpy(ethernet_frame,     target_mac, 6 * sizeof(uint8_t));
	memcpy(ethernet_frame + 6, arp_request_header.sender_mac, 6 * sizeof(uint8_t));

	ethernet_frame[12] = ETH_P_ARP / 256;
	ethernet_frame[13] = ETH_P_ARP % 256;

	// add arp header
	memcpy(ethernet_frame + ETH_HDRLEN, &arp_request_header, ARP_HDRLEN * sizeof(uint8_t));

	// Raw socket to send request
	if ((sock_fd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
		perror ("socket() failed");
		exit (EXIT_FAILURE);}

	update_device_ll(&device, interface, arp_request_header.sender_mac);

  	if ((bytes_read = sendto(sock_fd, ethernet_frame, ETH_HDRLEN + ARP_HDRLEN, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    		perror ("sendto() failed");
		exit (EXIT_FAILURE);}

	close(sock_fd);
	return 0;
}

void update_device_ll(struct sockaddr_ll *device, const char *interface, const uint8_t *mac){

	device->sll_family = AF_PACKET;
	memcpy(device->sll_addr, mac, 6*sizeof(uint8_t));
	device->sll_halen = htons(6);
	if ((device->sll_ifindex = if_nametoindex (interface)) == 0) {
	    	perror("nametoindex() failed");
    		exit(EXIT_FAILURE);}
	return;
}

/*
 * Function reads the ipaddress on interface and mac address
 * using ioctl and raw socket.
 * Updates mac and ip and device struct.
 */
void get_interface_info(const char *interface, uint8_t *ip, uint8_t *mac){

	int sock_fd;
	struct ifreq interface_info;
	struct sockaddr_in *ipaddr;

	if ((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
		perror("socket error()");
		exit(EXIT_FAILURE);}

	memset(&interface_info, 0, sizeof(interface_info));
	snprintf(interface_info.ifr_name, sizeof(interface_info.ifr_name), "%s", interface);
	if (ioctl(sock_fd, SIOCGIFADDR, &interface_info) < 0){
		perror("ioctl() failed SIOCGIFADDR");
		exit(EXIT_FAILURE);}

	ipaddr = (struct sockaddr_in *)&interface_info.ifr_addr;
	memcpy(ip, &ipaddr->sin_addr, 4*sizeof(uint8_t));

	memset(&interface_info, 0, sizeof(interface_info));
        snprintf(interface_info.ifr_name, sizeof(interface_info.ifr_name), "%s", interface);
        if (ioctl(sock_fd, SIOCGIFHWADDR, &interface_info) < 0){
                perror("ioctl() failed SIOCGIFHWADDR");
                exit(EXIT_FAILURE);}

	memcpy(mac, interface_info.ifr_addr.sa_data, 6*sizeof(uint8_t));
	close(sock_fd);
	return;
}
