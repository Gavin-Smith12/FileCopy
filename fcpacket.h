#define MAXFILENAME 484

struct initialPacket {
    string filename;
    int numPackets;
    string packetHash;
};

struct dataPacket {
    string fileNameHash; //20 bytes
    int packetNum; //4 bytes
    char* data; //Up to 466 bytes
    short dataSize; //2 bytes
    string packetHash; //20 bytes
}