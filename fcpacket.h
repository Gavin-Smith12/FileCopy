#include <openssl/sha.h>
#include <iostream>

#define MAX_FILE_NAME 460
#define MAX_DATA_SIZE 420

struct initialPacket {
	char packet_type = '8';               // 1
	char checksum[SHA_DIGEST_LENGTH * 2]; // 40
    char numPackets[16];			      // 4
	char filename[MAX_FILE_NAME];
};

struct dataPacket {
	std::string packet_type = "9";					  // 1 bytes
	std::string checksum;     // 40 bytes
    std::string fileNameHash; // 40 bytes
    std::string packetNum; 					  // 4 bytes
    std::string data;    			  // Up to 425 bytes
};