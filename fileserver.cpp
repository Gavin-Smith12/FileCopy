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

#define REQ_CHK  '0'
#define CHK_SUCC '2'
#define CHK_FAIL '3'
#define ACK_SUCC '5'
#define ACK_FAIL '6'
#define FIN_ACK  '7'
#define FST_PCT  '8'


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
     nastiness = atoi(argv[1]);   // convert command line string to integer
       
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
     c150debug->setIndent("    ");              // if we merge client and server
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
       c150debug->printf(C150APPLICATION,"Ready to accept messages");

       //
       // infinite loop processing messages
       //
       while(1)	{

    	  //
              // Read a packet
    	  // -1 in size below is to leave room for null
    	  //
    	  readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
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

            //cout << "INCOMING MESSAGE: " << incomingMessage << endl;

          //If the incoming message is the initial check we have to start the 
          //end-to-end check
          if(incoming[0] == REQ_CHK) {
            //Get the hash of the file out of the message
            string file_hash = incoming.substr(1, (SHA_DIGEST_LENGTH * 2));
            //Get the file name out of the message and add .tmp because it 
            //has not been checked yet
            string file_name = incoming.substr((SHA_DIGEST_LENGTH * 2) + 1) + ".tmp";

            //Grading statements, will be changed once file copy is added
            *GRADING << "File: " << file_name.substr(file_name.length()-4) << " starting to receive file" << endl;
            *GRADING << "File: " << file_name.substr(file_name.length()-4) << " received, beginning end-to-end check" << endl;

            //Calls the end to end check which reports 2 with success and 3 with failure
            int file_status = endCheck(file_name, file_hash, (string)directory);

            //Response is the message code with the file name 
            string response = to_string(file_status) + incoming.substr((SHA_DIGEST_LENGTH * 2) + 1);

            c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
                    response.c_str());
            sock -> write(response.c_str(), response.length()+1);

          } 
          //If the incoming message is an acknowledgement of success
          else if(incoming[0] == ACK_SUCC) {
            //Attach 7 for the final acknowledgement
            string response = FIN_ACK + incoming.substr(1);
            //Get file name and path
            string file_name = incoming.substr(1);
            string file_path = string(argv[3]) + "/";
            *GRADING << "File: " << file_name << " end-to-end check succeeded" << endl;
            //Print a message saying that file passed
            //cout << "File: " << file_name << " passed end-to-end check.\n" << endl;
            //Rename the file to get rid of the .tmp extension
            if(rename((file_path + file_name + ".tmp").c_str(), (file_path + file_name).c_str()))
                cerr << "Could not rename file\n" << endl;

            c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
                    response.c_str());
            sock -> write(response.c_str(), response.length()+1);
          }
          //If the incomine message is an acknowlegement of failure
          else if(incoming[0] == ACK_FAIL) {
            //Attack 7 for the final acknowledgement
            string response = FIN_ACK + incoming.substr(1);
             string file_name = incoming.substr(1);
            *GRADING << "File: " << file_name << " end-to-end check failed" << endl;
            //Print statement of failure
            //cout << "File: " << file_name << " failed end-to-end check.\n" << endl;

            c150debug->printf(C150APPLICATION,"Responding with message=\"%s\"",
                    response.c_str());
            sock -> write(response.c_str(), response.length()+1);
          }
          else if(incoming[0] == FST_PCT) {
            //cout << "In the correct place" << endl;
            struct initialPacket pckt1;
            //cout << "INCOMING IS: " << incoming << endl;
            // cout << "numPackets IS: " << incoming.length() << endl;

            //Set all variables of the initial packet
            // struct initialPacket* pckt = (struct initialPacket*) incoming.c_str();
            // cout << "incoming length: " << incoming.length() << endl;
            // for(int i=0; i<(int)incoming.length(); ++i)
            //     std::cout << std::hex << (int)incoming[i];
            // cout << endl;
            pckt1.packet_type = FST_PCT;
            //cout << "ERROR 1a " << pckt1.packet_type << endl;
            strncpy(pckt1.checksum, incoming.substr(1, 40).c_str(), 40);
            //cout << "ERROR 2a " << pckt1.checksum << endl;
            strncpy(pckt1.numPackets, incoming.substr(41, 16).c_str(), 16);
            //
            //cout << "NUMPACKETS: " << stoi(incoming.substr(41,16)) << endl;
            //pckt1.numPackets = incoming.at(42);
            //cout << "ERROR 3a " << pckt1.numPackets << endl;
            strncpy(pckt1.filename, incoming.substr(57).c_str(), MAX_FILE_NAME);

            copyfile(&pckt1, sock, directory);
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

//Function takes in information about the file and returns a status code 
//of 2 for success and 3 for failure
int endCheck(string file_name, string file_hash, string directory) {
    //Create sha1
    char *sha1 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);
    file_name = directory + "/" + file_name;
    const char *filename = file_name.c_str();

	//Check the given file against the given sha1
    sha1file(filename, sha1);

    //Return 2 if the files are the same and 3 if they are different
    if(string(sha1) == file_hash)
        return 2;
    else 
        return 3;

}

//Function taken from the sha1 file given to us
void sha1file(const char *filename, char *sha1) {
    ifstream *t;
    stringstream *buffer;
	unsigned char temp[SHA_DIGEST_LENGTH];
	char ostr[(SHA_DIGEST_LENGTH * 2) + 1];

	memset(ostr, 0, (SHA_DIGEST_LENGTH * 2) + 1);
	memset(temp, 0, SHA_DIGEST_LENGTH);

    t = new ifstream(filename);
    buffer = new stringstream;
    *buffer << t->rdbuf();
    SHA1((const unsigned char *)buffer->str().c_str(), 
            (buffer->str()).length(), temp);
	
	// Taken from website https://memset.wordpress.com/2010/10/06/using-sha1-function/
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf((char*)&(ostr[i*2]), "%02x", temp[i]);
    }

	memcpy(sha1, ostr, (SHA_DIGEST_LENGTH * 2) + 1);

    delete t;
    delete buffer;
}

int copyfile(struct initialPacket* pckt1, C150DgmSocket *sock, char* directory) {

    C150NastyFile currentFile(0);
    ssize_t readlen;             
    char incomingMessage[512];
	string checksum = string(pckt1->checksum);
    int intPack = stoi(pckt1->numPackets);
    struct dataPacket filePacket[intPack];

	//
	// Get hash of filename from initial packet for comparisons
	//
	char * sha1buf = (char *) malloc((SHA_DIGEST_LENGTH * 2) + 1);
	memset(sha1buf, 0, (SHA_DIGEST_LENGTH * 2) + 1);

	cout << "FILENAME: " << pckt1 -> filename << endl;
	sha1string(pckt1 -> filename, sha1buf);
	string initFileNameHash = string(sha1buf);
	cout << initFileNameHash << endl;

	string packet_type;
	int packetNum;
	bool sameFileName;
    for(int i = 0; i < intPack; i++) {
		do {
			readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
			//cout << incomingMessage << endl;
			//cout << "READLEN: " << readlen << endl;
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
			if(incoming.length() > 97)
				filePacket[i].data = incoming.substr(97).c_str();
			cleanString(incoming);            // c150ids-supplied utility: changes
												// non-printing characters to .
			c150debug->printf(C150APPLICATION,"Successfully read %d bytes. Message=\"%s\"",
						readlen, incoming.c_str());

			packet_type         = incoming[0];
			string checksum     = incoming.substr(1, 40).c_str();
			string fileNameHash = incoming.substr(41, 40).c_str();
			packetNum           = stoi(incoming.substr(81, 16));
            cout << "Current Packet: " << packetNum << endl;
		
			sameFileName = fileNameHash == initFileNameHash;

		} while(packetNum != i and packet_type != "9" and !sameFileName);
		//cout << "\n\n INCOMING MSG: " << incomingMessage << endl;

        string currFileName = string(directory) + "/" + pckt1->filename + ".tmp";

		ifstream ifile(currFileName);
		if (ifile) {
			currentFile.fopen(currFileName.c_str(), "r+");
		} else {
			currentFile.fopen(currFileName.c_str(), "w");
		}

		currentFile.fseek(399 * (packetNum - 1), SEEK_SET);

        if(!currentFile.fwrite((void*) filePacket[i].data.c_str(), 1, (size_t) filePacket[i].data.length()))
            perror("Could not write to file\n");
        currentFile.fclose();
    }

    return 0;
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