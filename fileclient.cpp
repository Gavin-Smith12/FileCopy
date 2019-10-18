// --------------------------------------------------------------
//
//                        pingclient.cpp
//
//        Author: Noah Mendelsohn         
//   
//
//        This is a simple client, designed to illustrate use of:
//
//            * The C150DgmSocket class, which provides 
//              a convenient wrapper for sending and receiving
//              UDP packets in a client/server model
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
//              pingclient <servername> <msgtxt>
//
//
//        OPERATION
//
//              pingclient will send a single UDP packet
//              to the named server, and will wait (forever)
//              for a single UDP packet response. The contents
//              of the packet sent will be the msgtxt, including
//              a terminating null. The response message
//              is checked to ensure that it's null terminated.
//              For safety, this application will use a routine 
//              to clean up any garbage characters the server
//              sent us, (so a malicious server can't crash us), and
//              then print the result.
//
//              Note that the C150DgmSocket class will select a UDP
//              port automatically based on the user's login, so this
//              will (typically) work only on the test machines at Tufts
//              and for COMP 150-IDS who are registered. See documention
//              for the comp150ids getUserPort routine if you are 
//              curious, but you shouldn't have to worry about it.
//              The framework automatically runs on a separate port
//              for each user, as long as you are registerd in the
//              the student port mapping table (ask Noah or the TAs if
//              the program dies because you don't have a port).
//
//        LIMITATIONS
//
//              This version does not timeout or retry when packets are lost.
//
//
//       Copyright: 2012 Noah Mendelsohn
//     
// --------------------------------------------------------------

#include "fcpacket.h"
#include "c150nastydgmsocket.h"
#include "c150debug.h"
#include "c150grading.h"
#include "c150nastyfile.h" 
#include <vector>
#include <cassert>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>                
#include <cerrno>
#include <dirent.h>
#include <openssl/sha.h>

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 

// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
void checkDirectory(char *dirname);
string sendMessageToServer(const char *msg, size_t msgSize, C150DgmSocket *sock, bool readRequested);
void sha1file(const char *filename, char *sha1);
void loopFilesInDir(DIR *SRC, string dirName, C150DgmSocket *sock);
void readAndSendFile(C150NastyFile& nastyFile, const char *filename, const char *dirname, C150DgmSocket *sock);
void sha1string(const char *input, char *sha1);
void clientEndToEnd(const char *filename, const char *dirname, C150DgmSocket *sock);
int numPacketsFile(C150NastyFile& nastyFile);
void receiveAndRespond(vector<string> *dataPackets, const char *filename, const char *dirname, C150DgmSocket *sock, string incoming);


// Protocol message codes 
#define REQ_CHK  '0'
#define CHK_SUCC '2'
#define CHK_FAIL '3'
#define ACK_SUCC '5'
#define ACK_FAIL '6'
#define FIN_ACK  '7'
#define INIT_FCP '8'
#define DATA_FCP '9'


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                    Command line arguments
//
// The following are used as subscripts to argv, the command line arguments
// If we want to change the command line syntax, doing this
// symbolically makes it a bit easier.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

const int serverArg = 1;     // server name is 1st arg
//const int msgArg = 2;        // message text is 2nd arg

int fileNasty    = 0;
int networkNasty = 0;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
int 
main(int argc, char *argv[]) {

    //
    //  DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    //
  
    GRADEME(argc, argv);

     // Variable declarations
     DIR *SRC;
     C150NastyDgmSocket *sock;

     // Make sure command line looks right
     if (argc != 5) {
       fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
          exit(1);
     }

    //        Send / receive / print 
    try {

		// Check that directory supplied exists
        checkDirectory(argv[4]);

		string dirName = string(argv[4]) + "/";

		networkNasty = atoi(argv[2]);
		c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",
			 networkNasty);
        sock = new C150NastyDgmSocket(networkNasty);
        sock -> turnOnTimeouts(2000);
        c150debug->printf(C150APPLICATION,"Ready to accept messages");
        sock -> setServerName(argv[1]); 
		//
		// Open the source directory
		//
		SRC = opendir(argv[4]);
		if (SRC == NULL) {
			fprintf(stderr,"Error opening source directory %s\n", argv[4]);     
			exit(8);
      	}

		fileNasty = atoi(argv[3]);
		
		// Loop through files in directory, sending each to the servers
		loopFilesInDir(SRC, dirName, sock);

		// Close the open directory
		closedir(SRC);
	}

    //
    //  Handle networking errors -- for now, just print message and give up!
    //
    catch (C150NetworkException& e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
             e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    } 

	delete sock;
    return 0;
}

/*
 * Loops through a directory, processing each file to another function
 * Returns nothing
 */
void loopFilesInDir(DIR *SRC, string dirName, C150DgmSocket *sock) {

	//  Loop copying the files
	//
	//    copyfile takes name of target file
	//
	struct dirent *sourceFile;
	C150NastyFile nastyFile(fileNasty); // Global variable fileNasty
	void *ret;
	string filePath;

	while ((sourceFile = readdir(SRC)) != NULL) {
		// skip the . and .. names
		if ((strcmp(sourceFile -> d_name, ".") == 0) ||
			(strcmp(sourceFile -> d_name, "..") == 0 )) {
			continue;          // never copy . or ..
		}
		filePath = dirName + string(sourceFile -> d_name);
		ret = nastyFile.fopen(filePath.c_str(), "r");
		if (ret == NULL) {
			perror("Cannot open file.");
		} else {
			readAndSendFile(nastyFile, sourceFile -> d_name, dirName.c_str(), sock);
			nastyFile.fclose();
		}
	}
}

//
// Calculates the number of packets needed to send a given file
// Returns the number of packets needed
//
int numPacketsFile(C150NastyFile& nastyFile) {

	int fsize, numDataPackets;
	nastyFile.fseek(0, SEEK_END);
	fsize = nastyFile.ftell();
	if (fsize == 0) {
		return fsize; // File empty
	}
	if (fsize > MAX_DATA_SIZE - 1) {
		numDataPackets = (int) (fsize / (MAX_DATA_SIZE - 1));
		if (fsize % (MAX_DATA_SIZE - 1) != 0) {
			numDataPackets += 1;
		}
	} else {
		numDataPackets = 1;
	}

	return numDataPackets;
}

/*
 * Creates packets from a single file and begins sending the file
 * Parameters: nastyFile, a C150NastyFile that is open'd
 *             filename, which is the file name
 *             dirname, the directory name where the file is
 *             sock, the open socket
 * Returns: nothing
 *
 */
void readAndSendFile(C150NastyFile& nastyFile, const char *filename, const char *dirname, C150DgmSocket *sock) {
	int numDataPackets;
	bool readRequested = true;
	string incoming;

	numDataPackets = numPacketsFile(nastyFile);

	// If file is empty, make sure one data packet sends
	if(numDataPackets == 0) {
		numDataPackets = 1;
	}

	//
	// Array holds all dataPackets for this file in case need to resend
	//
	vector<string> *dataPackets = new vector<string> (numDataPackets);

	//
	// Seek back to beginning for reading
	//
	nastyFile.rewind();
	struct initialPacket initPkt;


	string numPacketsStr = to_string(numDataPackets);
	if (numPacketsStr.length() > 16)
		perror("Number of packets too large to store in 16 chars.");
	while(numPacketsStr.length() < 16) {
		numPacketsStr = "0" + numPacketsStr;
	}

    *GRADING << "File: " << filename << " , beginning transmission, attempt " << 0 << endl;

    string firstMessage = initPkt.packetType + numPacketsStr + string(filename);
	assert(readRequested == true);
	incoming  = sendMessageToServer(firstMessage.c_str(), firstMessage.length(), sock, readRequested);
	while (incoming[0] != '$') {
		// Resend initial packet, server did not receive
		incoming= sendMessageToServer(firstMessage.c_str(), firstMessage.length(), sock, readRequested);
	}
    readRequested = false;

	//
	// TODO: ADD CONFIRMATION OF RECEIPT OF INITIAL PACKET
	//

	//
	// Create and send data packets
	//
	struct dataPacket dataPkt;

	// Prepare SHA1 digest variables
	char * databuf = (char *) malloc(MAX_DATA_SIZE);
	char * sha1buf = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
    

	//
	// Get hash digest of filename to send
	//
	sha1string(filename, sha1buf);
	dataPkt.fileNameHash = string(sha1buf);

	string dataMessage; 
	int i;
	for(i = 0; i < numDataPackets; i++) {
		dataPkt.packetNum = to_string(i + 1);
		if (dataPkt.packetNum.length() > 16)
			perror("Number of packets too large to store in 16 chars.");
		while(dataPkt.packetNum.length() < 16) {
			dataPkt.packetNum = "0" + dataPkt.packetNum;
		}	
		memset(databuf, 0, MAX_DATA_SIZE);
		
		int read = nastyFile.fread(databuf, 1, MAX_DATA_SIZE - 1);

		if (i == numDataPackets - 1) {
			readRequested = true;
		} else {
			if (read != MAX_DATA_SIZE - 1) {
				cerr << "Not enough bytes read by fread" << endl;
			}
		}

		dataPkt.data = string(databuf);

		//
		// Store and send packet
		//
		dataMessage = dataPkt.packetType + dataPkt.checksum + dataPkt.fileNameHash 
						+ dataPkt.packetNum + dataPkt.data;
		(*dataPackets)[i] = dataMessage;
		
        if((i % 100 == 0) and (i != 0)) {
            usleep(350000);
        }
		incoming = sendMessageToServer(dataMessage.c_str(), dataMessage.length(), sock, readRequested);
    }

	// Free alloc'd memory
	free(databuf);
	free(sha1buf);

	// Pass off to receiveAndRespond function
	receiveAndRespond(dataPackets, filename, dirname, sock, incoming);
}

/*	
 * Receives messages from the server and sends responses
 * Parameters: dataPackets, a list of data packets already sent
 *             filename, a file name
 *             dirname, the directory name in which the file resides
 *             sock, the open socket to server
 *             incoming, the message received from the server
 * Returns: nothing
 */
void receiveAndRespond(vector<string> *dataPackets, const char *filename, const char *dirname, C150DgmSocket *sock, string incoming) {
    char incomingMessage[512];
    int readlen = 0, firstloop = 0;
	string dataMessage;
	bool readRequested = true;

    while(1) {
        if(firstloop) {
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            if(sock ->timedout() == true) {
                break;
            }
            incomingMessage[readlen] = '\0'; // make sure null terminated
            incoming = string(incomingMessage);
        }
        if (incoming[0] == '!') {
            firstloop++;
			// All packets for this file succesfully received
			// Commence end2end check
            *GRADING << "File: " << string(filename) << " transmission complete, waiting for end-to-end check, attempt " << 0 << endl;
			clientEndToEnd(filename, dirname, sock);  
        } else if (incoming[0] == '@') {
            firstloop++;
            do {
				// Packet(s) requested by server
				int requestedPacketNum   = stoi(incoming.substr(1,16));
				string requestedFileName = incoming.substr(16,40);
				// Resend requested packet
				dataMessage = (*dataPackets)[requestedPacketNum - 1];

				assert(readRequested == true);
				incoming = string(sendMessageToServer(dataMessage.c_str(), dataMessage.length(), sock, readRequested));

				if (incoming[0] == '!') {
                    *GRADING << "File: " << string(filename) << " transmission complete, waiting for end-to-end check, attempt " << 0 << endl;
					clientEndToEnd(filename, dirname, sock);
				}
        	} while (incoming[0] == '@');
        } else {
            firstloop++;
        }
    }
	delete dataPackets;
}

/*
 * Initiates the end-to-end protocol, sending protocol messages to server
 * 	and processing received messages.
 * Parameters: filename, the name of a file for which the check is requested,
               dirname, the directory path in which the file resides
		       sock, the C150DgmSocket connected to the server
 * Returns: Nothing
 */
void clientEndToEnd(const char *filename, const char *dirname, C150DgmSocket *sock) {
	
	//
	// Get the SHA-1 of the file
	//
	char *sha1 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
	string filepath = string(dirname) + string(filename);
	sha1file(filepath.c_str(), sha1);

	// Concatenate strings to create message text to send
	string message = REQ_CHK + string(sha1) + string(filename);

	// Send the message REQ_CHK to the server, beginning the end-to-end protocol
	bool readRequested = true;
	string serverResponse = sendMessageToServer(message.c_str(), message.length(), sock, readRequested);

	//
	// Parse server response for end2end protocol code and respond to server
	//
	while (serverResponse[0] != CHK_SUCC and serverResponse[0] != CHK_FAIL) {
		string serverResponse = sendMessageToServer(message.c_str(), message.length(), sock, readRequested);
		if (serverResponse[0] == CHK_SUCC) { // end2end succeeded
			*GRADING << "File: " << filename << " end-to-end check succeeded, attempt " << 0 << endl;
			message = ACK_SUCC + string(filename);
			serverResponse = sendMessageToServer(message.c_str(), message.length(), sock, readRequested);
		} else if (serverResponse[0] == CHK_FAIL) { // end2end failed
			*GRADING << "File: " << filename << " end-to-end check failed, attempt " << 0 << endl;
			message = ACK_FAIL + string(filename);
			serverResponse = sendMessageToServer(message.c_str(), message.length(), sock, readRequested);
		}
	}	

	//
	// Check for FIN_ACK, else exit
	//
	while (serverResponse[0] != FIN_ACK) {
		serverResponse = sendMessageToServer(message.c_str(), message.length(), sock, readRequested);
	}
	cout << "End-to-end check complete." << endl;
	
	free(sha1);
}

/*
 * Writes a string to a C150DgmSocket
 * Returns C++ string of the read() message from the socket
 */
string sendMessageToServer(const char *msg, size_t msgSize, C150DgmSocket *sock, bool readRequested) {
	//
	// Declare variables
	//
    char *incomingMsg = (char *) malloc(512); // MAX_PACKET_SIZE
    ssize_t readlen;
    bool sendMessageAgain = true;

	//
	// Loop until successful read on socket (no timeout)
	//
	
    while(sendMessageAgain == true) {

        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"",
                      "fileclient", msg);

		// Write message to socket
        sock -> write(msg, msgSize);

		//
        // Read the response from the server
		//
		if (readRequested) {
			
			c150debug->printf(C150APPLICATION,"%s: Returned from write, doing read()",
				"pingclient");
			memset(incomingMsg, 0, 512);
			readlen = sock -> read(incomingMsg, 512);
            readlen++;
            readlen--;

			//
			// Keep sending messages if timedout, else check and print messsage
			// 	and return incoming message string.
			//
			if((sock -> timedout() == true)) {
				sendMessageAgain = true;
			} else {
				break;
			}
		} else {
			sendMessageAgain = false;
		}
    }
	string incomingMsgStr = string(incomingMsg);
    free(incomingMsg);

	return incomingMsgStr;
}

void checkDirectory(char *dirname) {
  struct stat statbuf;  
  if (lstat(dirname, &statbuf) != 0) {
    fprintf(stderr,"Error stating supplied source directory %s\n", dirname);
    exit(8);
  }

  if (!S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr,"File %s exists but is not a directory\n", dirname);
    exit(8);
  }
}

/*
 * Produces a 40 byte SHA-1 string of a file from an input filename
 * Output buffer sha1 is caller-managed memory
 * Returns nothing
 */
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
	int fsize  = 0;
	nastyFile.fseek(0, SEEK_END);
	fsize = nastyFile.ftell();
	buffer = (unsigned char *) malloc(fsize * sizeof(unsigned char));
	nastyFile.rewind();
	fsize = nastyFile.fread(buffer, 1, fsize);

    SHA1(buffer, fsize, temp);
	
	//
	// Write the SHA-1 digest bytes in human-readable form to a string
	// Taken from website https://memset.wordpress.com/2010/10/06/using-sha1-function/
	//
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*) &(ostr[i*2]), "%02x", temp[i]);
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

/*
 * Produces a 40 byte SHA-1 string from an input string
 * Output string is caller-managed memory
 * Returns nothing
 */
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