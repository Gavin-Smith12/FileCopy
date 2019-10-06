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


#include "c150dgmsocket.h"
#include "c150debug.h"
#include "c150grading.h"
#include "c150nastyfile.h" 
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
string sendMessageToServer(string msgTxt, char msgCode, C150DgmSocket *sock);
void sha1file(const char *filename, char *sha1);


// End-to-end protocol message codes 
#define REQ_CHK  '0'
#define CHK_SUCC '2'
#define CHK_FAIL '3'
#define ACK_SUCC '5'
#define ACK_FAIL '6'
#define FIN_ACK  '7'


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

     //
     // Variable declarations
     //
     DIR *SRC;
     struct dirent *sourceFile;

     //
     // Make sure command line looks right
     //
     if (argc != 5) {
       fprintf(stderr,"Correct syntxt is: %s <server> <networknastiness> <filenastiness> <srcdir>\n", argv[0]);
          exit(1);
     }

    //
    //
    //        Send / receive / print 
    //
    try {
        // Create the socket
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
        C150DgmSocket *sock = new C150DgmSocket();
        sock -> turnOnTimeouts(3000);

        // Tell the DGMSocket which server to talk to
        sock -> setServerName(argv[serverArg]);  

		/* size_t dirnamelen = strlen(argv[4]);
		char *dirname = (char*) malloc(dirnamelen);
		dirname = strncpy(dirname, argv[4], dirnamelen);
		printf("dirname: %s\n", dirname); */
        checkDirectory(argv[4]);



		//
		// Open the source directory
		//
		SRC = opendir(argv[4]);
		if (SRC == NULL) {
			fprintf(stderr,"Error opening source directory %s\n", argv[2]);     
			exit(8);
      	}
      
		//
		//  Loop copying the files
		//
		//    copyfile takes name of target file
		//
		string dirname = string(argv[4]);
		while ((sourceFile = readdir(SRC)) != NULL) {
			// skip the . and .. names
			if ((strcmp(sourceFile -> d_name, ".") == 0) ||
				(strcmp(sourceFile -> d_name, "..") == 0 )) {
				continue;          // never copy . or ..
			} 
			
			// Get the SHA-1 of the file
			char *sha1 = (char *) calloc((SHA_DIGEST_LENGTH * 2) + 1, 1);

			string filepath = dirname + string(sourceFile -> d_name);
			sha1file(filepath.c_str(), sha1);

			// Concatenate strings to create message text to send
			string msgTxt = string(sha1) + string(sourceFile -> d_name);

			// Send the message REQ_CHK to the server
			string server_response = sendMessageToServer(msgTxt, REQ_CHK, sock);

            if(server_response[0] == CHK_SUCC) {
				*GRADING << "File: " << sourceFile -> d_name << " end-to-end check succeeded, attempt " << 1 << endl;
				server_response = sendMessageToServer(sourceFile -> d_name, ACK_SUCC, sock);
			} else if (server_response[0] == CHK_FAIL) {
                *GRADING << "File: " << sourceFile -> d_name << " end-to-end check failed, attempt " << 1 << endl;
				server_response = sendMessageToServer(sourceFile -> d_name, ACK_FAIL, sock);
            }
			if (server_response[0] == FIN_ACK) {
				// End-to-end check complete
				cout << "End-to-end check complete." << endl;
			}
		}
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

    return 0;
}


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                     checkAndPrintMessage
//
//        Make sure length is OK, clean up response buffer
//        and print it to standard output.
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 


void
checkAndPrintMessage(ssize_t readlen, char *msg, ssize_t bufferlen) {
    // 
    // Except in case of timeouts, we're not expecting
    // a zero length read
    //
    if (readlen == 0) {
      throw C150NetworkException("Unexpected zero length read in client");
    }

    // DEFENSIVE PROGRAMMING: we aren't even trying to read this much
    // We're just being extra careful to check this
    if (readlen > (int)(bufferlen)) {
      throw C150NetworkException("Unexpected over length read in client");
    }

    //
    // Make sure server followed the rules and
    // sent a null-terminated string (well, we could
    // check that it's all legal characters, but 
    // at least we look for the null)
    //
    if(msg[readlen-1] != '\0') {
     throw C150NetworkException("Client received message that was not null terminated");    
    };

    //
    // Use a routine provided in c150utility.cpp to change any control
    // or non-printing characters to "." (this is just defensive programming:
    // if the server maliciously or inadvertently sent us junk characters, then we 
    // won't send them to our terminal -- some 
    // control characters can do nasty things!)
    //
    // Note: cleanString wants a C++ string, not a char*, so we make a temporary one
    // here. Not super-fast, but this is just a demo program.
    string s(msg);
    cleanString(s);

    // Echo the response on the console

    c150debug->printf(C150APPLICATION,"PRINTING RESPONSE: Response received is \"%s\"\n", s.c_str());
    printf("Response received is \"%s\"\n", s.c_str());

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
//        NEEDSWORK: should be factored into shared code w/pingserver
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
     // debug output to a file. Comment them
     // to default to the console.
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

string sendMessageToServer(string msgTxt, char msgCode, C150DgmSocket *sock)
{
    char incomingMsg[512];
    ssize_t readlen; 
    bool send_message_again = true;

    while(send_message_again == true) {
        string msg = msgCode + msgTxt;
        cout << "string message: " << msg << endl;
        c150debug->printf(C150APPLICATION,"%s: Writing message: \"%s\"",
                      "fileclient", msg);
        sock -> write(msg.c_str(), msg.size()+1); // +1 includes the null

		// File: <name>, beginning transmission, attempt <attempt>
		// TODO: FILENAME needs to be variable
		*GRADING << "File: " << "FILENAME" " , beginning transmission, attempt " << 1 << endl;

		// File: <name> transmission complete, waiting for end-to-end check, attempt <attempt>
		// TODO: FILENAME needs to be variable
		*GRADING << "File: " << "FILENAME" << " transmission complete, waiting for end-to-end check, attempt " << 1 << endl;

        // Read the response from the server
		//
        c150debug->printf(C150APPLICATION,"%s: Returned from write, doing read()",
              "pingclient");
        readlen = sock -> read(incomingMsg, sizeof(incomingMsg));

		

        // Iterate counter after timing out of a read
        if((sock -> timedout() == true)) {
            send_message_again = true;
        } else {
            send_message_again = false;
            checkAndPrintMessage(readlen, incomingMsg, sizeof(incomingMsg));
            return string(incomingMsg);
        }
    }
    exit(1);
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

	printf("filename: %s\n", filename);

    delete t;
    delete buffer;
}