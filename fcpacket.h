#include <openssl/sha.h>

#define MAX_FILE_NAME 467
#define MAX_DATA_SIZE 425

struct initialPacket {
	char packet_type = '8';                 // 1
	char checksum[SHA_DIGEST_LENGTH * 2]; // 40
    int numPackets;			              // 4
	char filename[MAX_FILE_NAME];
};

struct dataPacket {
	char packet_type = '9';					  // 1 bytes
	char checksum[SHA_DIGEST_LENGTH * 2];     // 40 bytes
    char fileNameHash[SHA_DIGEST_LENGTH * 2]; // 40 bytes
    int packetNum; 							  // 4 bytes
    char data[MAX_DATA_SIZE];    			  // Up to 425 bytes
    short dataSize;       					  // 2 bytes 
};