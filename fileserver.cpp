// --------------------------------------------------------------
//
//                        pingserver.cpp
//
//        Author: Noah Mendelsohn         
//   
//
//        This is a simple server, designed to illustrate use of:
//
//            * The C150DgmSocket class, which provides 
//              a convenient wrapper for sending and receiving
//              UDP packets in a client/server model
//
//            * The C150NastyDgmSocket class, which is a variant
//              of the socket class described above. The nasty version
//              takes an integer on its constructor, selecting a degree
//              of nastiness. Any nastiness > 0 tells the system
//              to occasionally drop, delay, reorder, duplicate or
//              damage incoming packets. Higher nastiness levels tend
//              to be more aggressive about causing trouble
//
//            * The c150debug interface, which provides a framework for
//              generating a timestamped log of debugging messages.
//              Note that the socket classes described above will
//              write to these same logs, providing information
//              about things like when UDP packets are sent and received.
//              See comments section below for more information on 
//              these logging classes and what they can do.
//
//
//        COMMAND LINE
//
//              pingserver <nastiness_number>
//
//
//        OPERATION
//
//              pingserver will loop receiving UDP packets from
//              any client. The data in each packet should be a null-
//              terminated string. If it is then the server
//              responds with a text message of its own.
//
//              Note that the C150DgmSocket class will select a UDP
//              port automatically based on the users login, so this
//              will (typically) work only on the test machines at Tufts
//              and for COMP 150-IDS who are registered. See documention
//              for getUserPort.
//
//
//       Copyright: 2012 Noah Mendelsohn
//     
// --------------------------------------------------------------

#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include "c150grading.h"
#include "c150nastyfile.h"
#include "fcpacket.h"
#include <fstream>
#include <cstdlib>
#include <stdio.h>
#include <openssl/sha.h> 


using namespace C150NETWORK;  // for all the comp150 utilities 

void setUpDebugLogging(const char *logname, int argc, char *argv[]);
int endCheck(string file_name, string file_hash, string directory);
void sha1file(const char *filename, char *sha1);
int copyfile(struct initialPacket* pckt1, C150DgmSocket *sock, char* directory);
void sha1string(const char *input, char *sha1);
void fileCheck(string currFileName, int packetNum, C150NastyFile& currentFile, string data);

int fileNasty = 0;

#define REQ_CHK  '0' //Client requesting an end to end check
#define CHK_SUCC '2' //End to end check succeeded
#define CHK_FAIL '3' //End to end check failed
#define ACK_SUCC '5' //CLient acknowledging success
#define ACK_FAIL '6' //Client acknowledging failure
#define FIN_ACK  '7' //Server ending end to end check
#define INIT_FCP '8' //Client beginning copying a file
#define INIT_ACK '$' //Server acknowldges the initial packet
#define DATA_FCP '9' //Packets that contain file data
#define PKT_DONE '!' //Server telling client that all packets have been copied
#define PKT_LOST '@' //Server asking for a packet that was not written


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
int
main(int argc, char *argv[])
{

    //
    //  DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    //
  
    GRADEME(argc, argv);

	//
	// Variable declarations
	//
	ssize_t readlen;             // amount of data read from socket
	char incomingMessage[512];   // received message data
	int nastiness;               // how aggressively do we drop packets, etc?
	char *directory = argv[3];

	//
	// Check command line and parse arguments
	//
	if (argc != 4)  {
		fprintf(stderr,"Correct syntxt is: %s <networknastiness> <filenastiness> <targetdir>\n", argv[0]);
		exit(1);
	}
	if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
		fprintf(stderr,"Nastiness %s is not numeric\n", argv[1]);     
		fprintf(stderr,"Correct syntxt is: %s <nastiness_number>\n", argv[0]);     
		exit(4);
	}

	// convert command line strings to integers
	nastiness = atoi(argv[1]);   
	fileNasty = atoi(argv[2]);

	//
	//  Set up debug message logging
	//
	setUpDebugLogging("pingserverdebug.txt",argc, argv);

	//
	// We set a debug output indent in the server only, not the client.
	// That way, if we run both programs and merge the logs this way:
	//
	//    cat pingserverdebug.txt pingserverclient.txt | sort
	//
	// it will be easy to tell the server and client entries apart.
	//
	// Note that the above trick works because at the start of each
	// log entry is a timestamp that sort will indeed arrange in 
	// timestamp order, thus merging the logs by time across 
	// server and client.
	//
	c150debug->setIndent("    ");           	// if we merge client and server
												// logs, server stuff will be indented

	//
	// Create socket, loop receiving and responding
	//
	try {
		//   c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
		//   C150DgmSocket *sock = new C150DgmSocket();

		c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",
				nastiness);
		C150NastyDgmSocket *sock = new C150NastyDgmSocket(nastiness);
		sock -> turnOnTimeouts(1000);
		c150debug->printf(C150APPLICATION,"Ready to accept messages");

		//
		// infinite loop processing messages
		//
		while(1) {

			//
			// Read a packet
			// -1 in size below is to leave room for null
			//

			readlen = sock -> read(incomingMessage, sizeof(incomingMessage) - 1);
			if (readlen == 0) {
				c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
				continue;
    	 	}

		//
		// Clean up the message in case it contained junk
		//
		incomingMessage[readlen] = '\0'; // make sure null terminated
		string incoming(incomingMessage); // Convert to C++ string ...it's slightly
										// easier to work with, and cleanString
										// expects it
		//cleanString(incoming);            // c150ids-supplied utility: changes
										// non-printing characters to .
		c150debug->printf(C150APPLICATION,"Successfully read %d bytes. Message=\"%s\"",
			readlen, incoming.c_str());


		// Check for protocol code REQ_CHK
		// Requests an end to end check for a given file
		if (incoming[0] == REQ_CHK) {
			//Get the hash of the file out of the message
			string file_hash = incoming.substr(1, (SHA_DIGEST_LENGTH * 2));
			//Get the file name out of the message and add .tmp because it 
			//has not been checked yet
			string file_name = incoming.substr((SHA_DIGEST_LENGTH * 2) + 1) + ".tmp";

			// Calls the end to end check which reports 2 with success and 3 with failure
			int file_status = endCheck(file_name, file_hash, (string)directory);

			//Response is the message code with the file name 
			string response = to_string(file_status) + incoming.substr((SHA_DIGEST_LENGTH * 2) + 1);

			c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
					response.c_str());
			sock -> write(response.c_str(), response.length()+1);
		} 

		// If the incoming message is an acknowledgement of success
		else if (incoming[0] == ACK_SUCC) {

			// Prepend protocol message FIN_ACK for the final acknowledgement
			string response = FIN_ACK + incoming.substr(1);

			//Get file name and path
			string file_name = incoming.substr(1);
			string file_path = string(argv[3]) + "/";
			*GRADING << "File: " << file_name << " end-to-end check succeeded" << endl;

			// Rename the file to get rid of the .tmp extension
			if(rename((file_path + file_name + ".tmp").c_str(), (file_path + file_name).c_str()))
				cerr << "Could not rename file\n" << endl;

			c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
					response.c_str());
			sock -> write(response.c_str(), response.length()+1);
		}
		//If the incomine message is an acknowlegement of failure
		else if(incoming[0] == ACK_FAIL) {
			//Attach 7 for the final acknowledgement
			string response = FIN_ACK + incoming.substr(1);
				string file_name = incoming.substr(1);
			*GRADING << "File: " << file_name << " end-to-end check failed" << endl;

			c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
					response.c_str());
			sock -> write(response.c_str(), response.length()+1);
		}
		else if(incoming[0] == INIT_FCP) {

            struct initialPacket pckt1;

            pckt1.packetType = INIT_FCP;
            strncpy(pckt1.numPackets, incoming.substr(1, 16).c_str(), 16);
            strncpy(pckt1.filename, incoming.substr(17).c_str(), MAX_FILE_NAME);

            *GRADING << "File: " << pckt1.filename << " starting to receive file" << endl;

            string initAck = INIT_ACK + string(pckt1.filename);

            c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
                    initAck.c_str());
            sock -> write(initAck.c_str(), initAck.length()+1);

            copyfile(&pckt1, sock, directory);
            *GRADING << "File: " << pckt1.filename << " received, beginning end-to-end check" << endl;
        }
	   	}
    } 

     catch (C150NetworkException& e) {
       // Write to debug log
       c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
			 e.formattedExplanation().c_str());
       // In case we're logging to a file, write to the console too
       cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
     }

     // This only executes if there was an error caught above
     return 4;
}



// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                     setUpDebugLogging
//
//        For COMP 150-IDS, a set of standards utilities
//        are provided for logging timestamped debug messages.
//        You can use them to write your own messages, but 
//        more importantly, the communication libraries provided
//        to you will write into the same logs.
//
//        As shown below, you can use the enableLogging
//        method to choose which classes of messages will show up:
//        You may want to turn on a lot for some debugging, then
//        turn off some when it gets too noisy and your core code is
//        working. You can also make up and use your own flags
//        to create different classes of debug output within your
//        application code
//
//        NEEDSWORK: should be factored and shared w/pingclient
//        NEEDSWORK: document arguments
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
void setUpDebugLogging(const char *logname, int argc, char *argv[]) {

     //   
     //           Choose where debug output should go
     //
     // The default is that debug output goes to cerr.
     //
     // Uncomment the following three lines to direct
     // debug output to a file. Comment them to 
     // default to the console
     //  
     // Note: the new DebugStream and ofstream MUST live after we return
     // from setUpDebugLogging, so we have to allocate
     // them dynamically.
     //
     //
     // Explanation: 
     // 
     //     The first line is ordinary C++ to open a file
     //     as an output stream.
     //
     //     The second line wraps that will all the services
     //     of a comp 150-IDS debug stream, and names that filestreamp.
     //
     //     The third line replaces the global variable c150debug
     //     and sets it to point to the new debugstream. Since c150debug
     //     is what all the c150 debug routines use to find the debug stream,
     //     you've now effectively overridden the default.
     //
     ofstream *outstreamp = new ofstream(logname);
     DebugStream *filestreamp = new DebugStream(outstreamp);
     DebugStream::setDefaultLogger(filestreamp);


     //
     //  Put the program name and a timestamp on each line of the debug log.
     //
     c150debug->setPrefix(argv[0]);
     c150debug->enableTimestamp(); 

     //
     // Ask to receive all classes of debug message
     //
     // See c150debug.h for other classes you can enable. To get more than
     // one class, you can or (|) the flags together and pass the combined
     // mask to c150debug -> enableLogging 
     //
     // By the way, the default is to disable all output except for
     // messages written with the C150ALWAYSLOG flag. Those are typically
     // used only for things like fatal errors. So, the default is
     // for the system to run quietly without producing debug output.
     //
     c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC | 
			      C150NETWORKDELIVERY); 

}

// Function takes in information about the file and returns a status code 
// Status code: 2 for success
// 				3 for failure
int endCheck(string file_name, string file_hash, string directory) {
    // Allocate SHA-1 buffer
    char *sha1 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
    
    file_name = directory + "/" + file_name;
    const char *filename = file_name.c_str();

	// Check the given file against the given sha1
    sha1file(filename, sha1);

    // Return 2 if the files are the same
	// Return 3 if they are different
    if (string(sha1) == file_hash)
        return 2;
    else 
        return 3;
}

void sha1file(const char *filename, char *sha1) {

	//
	// Declare variables
	//
    // ifstream *t;
    // stringstream *buffer;
	unsigned char * buffer;
	C150NastyFile nastyFile(fileNasty);
	unsigned char temp[SHA_DIGEST_LENGTH];
	char ostr[(SHA_DIGEST_LENGTH * 2) + 1];

	//
	// Zero-initalize buffers
	//
	memset(ostr, 0, (SHA_DIGEST_LENGTH * 2) + 1); // Human-readable SHA-1 digest
	memset(temp, 0, SHA_DIGEST_LENGTH);	// Raw SHA-1 digest buffer

	//
	// Open file, read from file, get SHA-1 digest
	//
	void *ret = nastyFile.fopen(filename, "r");
	if (ret == NULL) {
		perror("Cannot open file.");
		exit(1);
	}
	int fsize = 0;
	nastyFile.fseek(0, SEEK_END);
	fsize = nastyFile.ftell();
	buffer = (unsigned char *) malloc(fsize);
	nastyFile.rewind();
	fsize = nastyFile.fread(buffer, 1, fsize);
	
    SHA1(buffer, fsize, temp);
	
	//
	// Write the SHA-1 digest bytes in human-readable form to a string
	// Taken from website https://memset.wordpress.com/2010/10/06/using-sha1-function/
	//
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(ostr[i*2]), "%02x", temp[i]);
    }

	//
	// Copy human-readable output string to function user-returned variable
	//
	memcpy(sha1, ostr, (SHA_DIGEST_LENGTH * 2) + 1);

	//
	// Free alloc'd memory
	//
	free(buffer);
}

int copyfile(struct initialPacket* pckt1, C150DgmSocket *sock, char* directory) {

    C150NastyFile currentFile(fileNasty); //Nastyfile object for file operations
    ssize_t readlen; //Readlen for checking reading length
    char incomingMessage[512]; //Incoming message buffer
    //packetLostNum is number of packet in the sequence that was lost
    //fileNameHash is the hash of the current file name
    //lostPacketMsg is the message sent to the client asking for a packet
    //to be sent again or saying that copying is done
    //data is the data being sent to be written 
	string packetLostNum, fileNameHash, lostPacketMsg, data;
    int numPack = stoi(pckt1->numPackets); //numPack is the number of packets expected 
    int numPacketsReceived[numPack]; //numPacketsReceived keeps track of which packets are lost
    //Set to all zero so that no packet is accidentely seen as written when 
    //it was not been 
    for(int i = 0; i < numPack; i++) {
        numPacketsReceived[i] = 0;
    }
    

	//
	// Get hash of filename from initial packet for comparisons
	//
	char * sha1buf = (char *) malloc((SHA_DIGEST_LENGTH * 2) + 1);
	memset(sha1buf, 0, (SHA_DIGEST_LENGTH * 2) + 1);

	sha1string(pckt1 -> filename, sha1buf);
	string initFileNameHash = string(sha1buf);

	string packet_type; //Checks what type of packet is being received
	int packetNum, packetsLost; //packetNum is the current packet being read
                                //packetsLost is the number of packets lost total
    int packetDone = 0; //Number of packets written successfully
	bool sameFileName; //Used to check if the file being dealt with is correct

    //Loop executes until the server tells the client the file has been fully copied
    while (1) {
		do {
            //If the number of packets that has been successfully written is 
            //equal to or greater than the number of packets expected, don't read
            if(packetDone <= numPack) {
			     readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            }

            //If the read times out or all packets have been received, go into 
            //to either request more packets or tell client copying is done
            if((sock -> timedout() == true) or (packetDone >= numPack)) {
                packetsLost = 0;

                // Loop through the checking array to see if any packets are missing
                for (int i = 0; i < numPack; i++) {
                    if (numPacketsReceived[i+1] != 1) {

                        packetLostNum = to_string(i+1);

                        while(packetLostNum.length() < 16)
                            packetLostNum = "0" + packetLostNum;

                        //Create a packet that tells the client what packet was 
                        //not read
                        lostPacketMsg = PKT_LOST + packetLostNum + fileNameHash;
                        //Iterate that a packet was lost
                        packetsLost++;
                        //Decrement because this packet was not read correctly
                        packetDone--;
                        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"",
                      						"fileclient", lostPacketMsg);
                        sock -> write(lostPacketMsg.c_str(), lostPacketMsg.length());
                    }
                }
                //If all packets were written correctly, tell the client you are 
                //done
                if (packetsLost == 0) {
                    lostPacketMsg = PKT_DONE + fileNameHash;
                    sleep(1);
                    c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"",
                    					"fileclient", lostPacketMsg);
                    sock -> write(lostPacketMsg.c_str(), lostPacketMsg.length());
                    //This is the only time the function should return
                    return 0;
                } else {
                    continue;
                }
            }
			if (readlen == 0) {
				c150debug->printf(C150APPLICATION,"Read zero length message, trying again");
				continue;
			}

			//
			// Clean up the message in case it contained junk
			//
			incomingMessage[readlen] = '\0'; // make sure null terminated
			string incoming(incomingMessage); // Convert to C++ string ...it's slightly
												// easier to work with, and cleanString
												// expects it
			//Have to have this before it is cleaned to preserve newlines

            //Ignore the packet if it is not a data packet
            if(incoming[0] != DATA_FCP)
                continue;

            //If the packet does not contain any data do not read data
			if(incoming.length() > 57)
				data = incoming.substr(57).c_str();

			cleanString(incoming);            // c150ids-supplied utility: changes
												// non-printing characters to .

			c150debug->printf(C150APPLICATION,"Successfully read %d bytes. Message=\"%s\"",
						readlen, incoming.c_str());

            //Read in the packet information
			packet_type         = incoming[0];
			fileNameHash = incoming.substr(1, 40).c_str();
			packetNum           = stoi(incoming.substr(41, 16));
	
            //Check that we are working with the correct file (to meet invariant
            //that one file is copied at a time)
			sameFileName = fileNameHash == initFileNameHash;

		} while(packet_type != "9" or !sameFileName); //Only taking in packets
        //of the correct type and file

        string currFileName = string(directory) + "/" + pckt1->filename + ".tmp";

        fileCheck(currFileName, packetNum, currentFile, data);

        //Acknowledge that the packet was written correctly
        numPacketsReceived[packetNum] = 1;
        packetDone++;
    }
    //This return should never execute.
    return 0;
}

void fileCheck(string currFileName, int packetNum, C150NastyFile& currentFile, string data) {

    void* fileNastyCheck = calloc(MAX_DATA_SIZE-1, 1);
    char *sha1 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
    char *sha2 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
    bool fileCheck = true;

    do {
        //Check if the file exists, if it does already open it for updating,
        //if not open it with "w" so that it is created
        ifstream ifile(currFileName);
        if (ifile) {
            currentFile.fopen(currFileName.c_str(), "r+");
        } else {
            currentFile.fopen(currFileName.c_str(), "w");
        }

        //Seek to the correct place in the file (data is 399 long)
        if (currentFile.fseek(399 * (packetNum - 1), SEEK_SET))
            perror("fseek failed\n");

        if (currentFile.fwrite((void*) data.c_str(), 1, (size_t) data.length()) < data.length())
            perror("Could not write to file\n");

        currentFile.fclose();
        currentFile.fopen(currFileName.c_str(), "r+");

        if (currentFile.fseek(399 * (packetNum - 1), SEEK_SET))
           perror("fseek failed\n");

        if(currentFile.fread(fileNastyCheck, 1, (size_t) data.length()) < data.length())
           perror("Could not read from file\n");

        sha1string((char*) fileNastyCheck, sha1);
        sha1string(data.c_str(), sha2);

        if(string(sha1) == string(sha2)) 
           fileCheck = false;

        currentFile.fclose();
    } while(fileCheck == true);

    free(sha1);
    free(sha2);
    free(fileNastyCheck);
}

void sha1string(const char *input, char *sha1) {
	//
	// Declare variables
	//
	unsigned char temp[SHA_DIGEST_LENGTH];
	char ostr[(SHA_DIGEST_LENGTH * 2) + 1];

	//
	// Zero-initalize buffers
	//
	memset(ostr, 0, (SHA_DIGEST_LENGTH * 2) + 1); // Human-readable SHA-1 digest
	memset(temp, 0, SHA_DIGEST_LENGTH);	// Raw SHA-1 digest buffer

	cout << "STRLEN(INPUT): " << strlen(input) << endl;
    SHA1((const unsigned char *) input, strlen(input), temp);
	
	//
	// Write the SHA-1 digest bytes in human-readable form to a string
	// Taken from website https://memset.wordpress.com/2010/10/06/using-sha1-function/
	//
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(ostr[i*2]), "%02x", temp[i]);
    }

	//
	// Copy human-readable output string to function user-returned variable
	//
	memcpy(sha1, ostr, (SHA_DIGEST_LENGTH * 2) + 1);
}