/*
	Data Networks Project 3
	CS 4413
	Austen Rozanski

	Created: 09/29/2018
	Last Edited: 11/06/2018

	Description:
	Simulates an 802.11 network. Command line arguments or data input at beginning of program determine which
	file the program reads from to configure itself and what file to read input from. Each server will send data
	from the pcap file specified to all neighbors if the packet sender ip matches that machines ip. When the machine
	receives data, it will drop all packets that do not contain its ip as the destination in the packet.

	The servers send data using UDP. 

	The server sends data by flooding the network. A damping algorithm that sets the maximum number of hops allowed
	for each packet is used. This value is set in the ipv4 header portion for number of hops. The maxTimeToLive global
	variable is set to the number of hops before dropping packet. The packets are also not flooded to the neighbor sent
	from. The 'unused' portion of the linux cooked capture frame is used to store the port number of the neighbor the data
	came from.

	This application uses the external library winpcap to read the pcap files.
	https://www.winpcap.org/

	Command line arguments are:
		None => enter the config file name during program execution, use default pcap file.
		One => the config file name. Use the default pcap file
		Two => the config file name is the first argument. The pcap file name is the second.

	Useful tip for navigating file:
	In visual studio: 
		ctrl+M, ctrl+O (both shortcuts consecutively) - collapse all
		ctrl+M, ctrl+L (both shortcuts consecutively) - expand all
*/

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <WS2tcpip.h>
#include <pcap.h>
#include <iomanip>

// Winsock library file
#pragma comment (lib, "ws2_32.lib")

using namespace std;

///////////////////////////////////////
// Global Variables
///////////////////////////////////////

string fakeIP;
vector<int> vectorFakeIP;
int portNumber;
int numNeighbors;

int maxTimeToLive = 4;
vector<int> framesReceived;

vector<string> neighborFakeIP;
vector<string> neighborRealIP;
vector<int> neighborPort;

// The ID given to the frame that will be sent
int currentFrameID = 0;

// Name of default pcap file
string pcapFileName = "Project2Topo.pcap";

////////////////////////////////////////////////////////////
// GET DIGIT METHODS
////////////////////////////////////////////////////////////
// getHexDigit Method
// Description:
//     Method takes an int value in base 10 and returns a specified digit in base 16.
//     For example, value = 31 (base 10) = 0x1f. The digitNumber specifies which digit
//     to return starting with 0 on the far right side of the hex number. If digitNumber
//     equals 0, the above example would return 15 and if digitNumber = 1, it would return
//     1.
// Parameters:
//     int value - the value to convert to hex and find a digit in
//     int digitNumber - the number of digits to count to starting from the right

int getHexDigit(int value, int digitNumber) {
	return (value >> (4 * digitNumber)) & 0x000F;
}

// getBinaryDigit Method
// Description:
//     Method takes an int value in base 10 and returns a specified digit in base 2.
//     For example, value = 10 (base 10) = 1010 (binary). The digitNumber specifies which
//     digit to return starting with 0 on the far right side of the binary number. If
//     digitNumber = 0, the above example would return 0. If digitNumber = 3, the above
//     example would return 1. 
// Parameters:
//     int value - the value to convert to binary to find a digit in
//     int digitNumber - the number of digits to count to starting from the right
int getBinaryDigit(int value, int digitNumber) {
	return ((value >> (1 * digitNumber)) % 2 == 0) ? (0) : (1);
}


////////////////////////////////////////
// Flood Sender Function
////////////////////////////////////////
void floodSender(u_char * dataToSend, int dataSize, int neighborIndexReceivedFrom) {

	////////////////////////////////////////////////////////////
	// INITIALIZE WINSOCK
	////////////////////////////////////////////////////////////

	// Create a WORD that states we are using WinSock version 2.
	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	WSADATA data;
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		cout << "Can't start Winsock! " << wsOk;
		return;
	}
	////////////////////////////////////////////////////////////
	// CONNECT TO THE SERVERS
	////////////////////////////////////////////////////////////

	// Create a vector that stores all the server sockets to neighbors
	vector<sockaddr_in> servers = vector<sockaddr_in>();
	for (int i = 0; i < numNeighbors; i++) {
		if (i != neighborIndexReceivedFrom) {
			sockaddr_in server;
			server.sin_family = AF_INET; // AF_INET = IPv4 addresses
			server.sin_port = htons(neighborPort[i]); // Little to big endian conversion
			inet_pton(AF_INET, "127.0.0.1", &server.sin_addr); // Convert from string to byte array
			servers.push_back(server);
		}
	}

	// Socket creation, note that the socket type is datagram
	SOCKET out = socket(AF_INET, SOCK_DGRAM, 0);

	// Send data to all neighbors
	for (int i = 0; i < numNeighbors - 1; i++) {
		int sendOk = sendto(out, (const char *)dataToSend, dataSize, 0, (sockaddr*)&servers[i], sizeof(servers[i]));

		// Output error if data failed to send
		if (sendOk == SOCKET_ERROR)
		{
			cout << "That didn't work! " << WSAGetLastError() << endl;
		}
	}

	// Close the socket
	closesocket(out);

	// Close down Winsock
	WSACleanup();
}




///////////////////////////////////////
// Receiver Function
///////////////////////////////////////
//
// Description: Server that receives any packets sent to it and then outputs
//              the data of packets where the destination ip matches its own ip.
//              Drop all other packets.
void receiver() {
	////////////////////////////////////////////////////////////
	// INITIALIZE WINSOCK
	////////////////////////////////////////////////////////////

	// Create a WORD that states we are using WinSock version 2.
	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	WSADATA data;
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		// Not ok! Get out quickly
		cout << "Can't start Winsock! " << wsOk;
		return;
	}

	////////////////////////////////////////////////////////////
	// SOCKET CREATION AND BINDING
	////////////////////////////////////////////////////////////

	// Create a socket, notice that it is a user datagram socket (UDP)
	SOCKET in = socket(AF_INET, SOCK_DGRAM, 0);

	// Create a server hint structure for the server
	sockaddr_in serverHint;
	serverHint.sin_addr.S_un.S_addr = ADDR_ANY; // Us any IP address available on the machine
	serverHint.sin_family = AF_INET; // Address format is IPv4
	serverHint.sin_port = htons(portNumber); // Convert from little to big endian

	// Try and bind the socket to the IP and port
	if (::bind(in, (sockaddr*)&serverHint, sizeof(serverHint)) == SOCKET_ERROR)
	{
		cout << "Can't bind socket! " << WSAGetLastError() << endl;
		return;
	}

	////////////////////////////////////////////////////////////
	// MAIN LOOP
	////////////////////////////////////////////////////////////

	sockaddr_in client; // Use to hold the client information (port / ip address)
	int clientLength = sizeof(client); // The size of the client information

	// Buffer to store the data coming in from the client
	char buf[1024];

	// Enter a loop
	while (true)
	{
		ZeroMemory(&client, clientLength); // Clear the client structure
		ZeroMemory(buf, 1024); // Clear the receive buffer

		// Wait for message
		int bytesIn = recvfrom(in, buf, 1024, 0, (sockaddr*)&client, &clientLength);
		if (bytesIn == SOCKET_ERROR)
		{
			cout << "Error receiving from client " << WSAGetLastError() << endl;
			continue;
		}

		cout << "Received Packet..." << endl;

		// Display message and client info
		char clientIp[256]; // Create enough space to convert the address byte array
		ZeroMemory(clientIp, 256); // to string of characters

		// Convert from byte array to chars
		inet_ntop(AF_INET, &client.sin_addr, clientIp, 256);

		// stores the current index being read in the buf array (data from client)
		int packetIndex = 0;

		// stores the beginning of the current frame. Used when outputting all the hex at the end
		int outputOctetsStart = 0;

		// Each frame must be at least 36 chars long
		if (bytesIn >= 36) {

			// Check to see if the frame has already been received
			int frameID = (256 * (int)((unsigned char)buf[20])) + ((int)((unsigned char)buf[21]));

			cout << "Frame ID: " << frameID << endl;

			bool frameAlreadyReceived = false;
			for (int i = 0; i < framesReceived.size(); i++) {
				if (framesReceived[i] == frameID) {
					frameAlreadyReceived = true;
				}
			}

			if (frameAlreadyReceived == false) {



				// If destination matches fakeIP
				string thisFrameDestIP = to_string((int)((unsigned char)buf[32])) + "." + to_string((int)((unsigned char)buf[33])) + "." +
					to_string((int)((unsigned char)buf[34])) + "." + to_string((int)((unsigned char)buf[35]));

				if (fakeIP == thisFrameDestIP) {

					framesReceived.push_back(frameID);

					////////////////////////////////////////////////////////////
					// Retrieve Data For Headers
					////////////////////////////////////////////////////////////

					///////////////////////////////
					// Frame Variables for Output
					///////////////////////////////

					// Information from Linux Cooked Capture Header
					int lcc_packetType;
					int lcc_addressType;
					int lcc_addressLength;
					unsigned char lcc_sourceMacAddr[6];
					unsigned char lcc_unused[2];
					unsigned char lcc_protocol[2];
					int lcc_packetSize;

					// Information from IP Header
					int ip_version;
					int ip_headerLength;
					unsigned char ip_typeOfService;
					int ip_totalLength;
					int ip_id;
					//int ip_flagHex;
					bool ip_flags[3];
					int ip_fragmentOffset;
					unsigned char ip_flagsOctets[2];
					int ip_timeToLive;
					int ip_protocol;
					unsigned char ip_checksum[2];
					int ip_sourceAddr[4];
					int ip_destAddr[4];

					////////////////////////////////
					// Retreive Linux Cooked Capture Header
					////////////////////////////////
					// Packet Type
					lcc_packetType = (32 * ((int)((unsigned char)buf[packetIndex]))) + ((int)((unsigned char)buf[packetIndex + 1]));
					packetIndex += 2;
					// Address Type
					lcc_addressType = (32 * ((int)((unsigned char)buf[packetIndex]))) + ((int)((unsigned char)buf[packetIndex + 1]));
					packetIndex += 2;
					// Address Length
					lcc_addressLength = (32 * ((int)((unsigned char)buf[packetIndex]))) + ((int)((unsigned char)buf[packetIndex + 1]));
					packetIndex += 2;
					// Source MAC Address
					for (int i = 0; i < 6; i++) {
						lcc_sourceMacAddr[i] = (unsigned char)buf[packetIndex];
						packetIndex++;
					}
					// Unused
					for (int i = 0; i < 2; i++) {
						lcc_unused[i] = (unsigned char)buf[packetIndex];
						packetIndex++;
					}
					// Protocol
					for (int i = 0; i < 2; i++) {
						lcc_protocol[i] = (unsigned char)buf[packetIndex];
						packetIndex++;
					}
					// Assign frame Size when ip header's total length is assigned

					//////////////////////////////
					// Retrieve IP Header Data
					//////////////////////////////

					// Version and Header Length
					ip_version = getHexDigit((int)((unsigned char)buf[packetIndex]), 1);
					ip_headerLength = 4 * getHexDigit((int)((unsigned char)buf[packetIndex]), 0);
					packetIndex++;

					// Type of Service
					ip_typeOfService = (unsigned char)buf[packetIndex];
					packetIndex++;

					// Total Length
					ip_totalLength = (256 * (int)((unsigned char)buf[packetIndex])) + ((int)((unsigned char)buf[packetIndex + 1]));
					lcc_packetSize = ip_totalLength + 16;
					packetIndex += 2;

					// Identification
					ip_id = (256 * (int)((unsigned char)buf[packetIndex])) + ((int)((unsigned char)buf[packetIndex + 1]));
					packetIndex += 2;

					// Flags and Fragment Offset
					// flags = first 3 bits, fragment = next 13 bits
					int tmp_flagsOctet = (int)((unsigned char)buf[packetIndex]);
					int tmp_flagsHex = getHexDigit(tmp_flagsOctet, 1);
					ip_flags[0] = getBinaryDigit(tmp_flagsHex, 3);
					ip_flags[1] = getBinaryDigit(tmp_flagsHex, 2);
					ip_flags[2] = getBinaryDigit(tmp_flagsHex, 1);
					// fragment offset = int value of second octet + 16^2 * (second hex in first octet) + 2^12 * (fourth bit in first hex in first octet)
					ip_fragmentOffset = (int)((unsigned char)buf[packetIndex + 1]) + (256 * getHexDigit(tmp_flagsOctet, 0)) + (4096 * getBinaryDigit(tmp_flagsHex, 0));
					ip_flagsOctets[0] = buf[packetIndex];
					ip_flagsOctets[1] = buf[packetIndex + 1];

					packetIndex += 2;

					// Time to Live
					ip_timeToLive = (int)((unsigned char)buf[packetIndex]);
					packetIndex++;

					// Protocol
					ip_protocol = (int)((unsigned char)buf[packetIndex]);
					packetIndex++;

					// Header Checksum
					ip_checksum[0] = (unsigned char)buf[packetIndex];
					ip_checksum[1] = (unsigned char)buf[packetIndex + 1];
					packetIndex += 2;

					// Source IP Address
					for (int i = 0; i < 4; i++) {
						ip_sourceAddr[i] = (int)((unsigned char)buf[packetIndex]);
						packetIndex++;
					}

					// Distination IP Address
					for (int i = 0; i < 4; i++) {
						ip_destAddr[i] = (int)((unsigned char)buf[packetIndex]);
						packetIndex++;
					}

					// Options and Padding
					// options size = HeaderLength - 20 or until first option terminator
					// padding length = HeaderLength - 20 - optionssize
					packetIndex += (ip_headerLength - 20);

					// Additional Data
					// size = total length - IHL
					packetIndex += (ip_totalLength - ip_headerLength);


					////////////////////////////////////////////////////////////
					// Output Data from above
					////////////////////////////////////////////////////////////

					// Linux Cooked Capture Header
					cout << "LCC:  ----- Linux Cooked Capture Header -----" << endl;
					cout << "\tLCC:  " << endl;

					// packet size
					cout << "\tLCC:  " << left << setfill(' ') << setw(14) << "Packet Size" << ": " << dec << lcc_packetSize << " bytes" << endl;

					// address type
					cout << "\tLCC:  " << left << setfill(' ') << setw(14) << "Addresss Type" << ": " << dec << lcc_addressType << endl;

					// address type
					cout << "\tLCC:  " << left << setfill(' ') << setw(14) << "Addresss Length" << ": " << dec << lcc_addressLength << endl;

					// source mac address
					cout << "\tLCC:  " << left << setfill(' ') << setw(14) << "Source" << ": " << right << setfill('0') << setw(2) << hex << (int)lcc_sourceMacAddr[0];
					for (int i = 1; i < 6; i++) {
						cout << "-" << setfill('0') << setw(2) << hex << (int)lcc_sourceMacAddr[i];
					}
					cout << endl;

					// protocol
					cout << "\tLCC:  " << left << setfill(' ') << setw(14) << "Protocol" << ": " << right << setfill('0') << setw(2) << hex << (int)lcc_protocol[0] << setfill('0') << setw(2) << (int)lcc_protocol[1];
					if ((int)lcc_protocol[0] == 8 && (int)lcc_protocol[1] == 0) {
						cout << " (IP)" << endl;
					}
					else if ((int)lcc_protocol[0] == 0 && (int)lcc_protocol[1] == 0) {
						cout << " (ARP)" << endl;
					}
					else {
						cout << " (UNKNOWN)" << endl;
					}
					cout << "\tLCC: " << endl << endl;

					// IP Header
					cout << "\tIP:  ----- IP Header -----" << endl;
					cout << "\tIP:  " << endl;

					// version
					cout << "\tIP:  Version = " << dec << ip_version << endl;

					// header length
					cout << "\tIP:  Header length = " << dec << ip_headerLength << " bytes" << endl;

					// type of service
					// get the binary digits in the hex stored in ip_typeOfService
					int tmp_tosHex[2];
					tmp_tosHex[0] = getHexDigit((int)ip_typeOfService, 0);
					tmp_tosHex[1] = getHexDigit((int)ip_typeOfService, 1);
					int tmp_precedence = getBinaryDigit(tmp_tosHex[1], 1) + (2 * getBinaryDigit(tmp_tosHex[1], 2)) + (4 * getBinaryDigit(tmp_tosHex[1], 3));
					int tmp_tosBits[5];
					for (int i = 0; i < 4; i++) {
						tmp_tosBits[i] = getBinaryDigit(tmp_tosHex[0], i);
					}
					tmp_tosBits[4] = getBinaryDigit(tmp_tosHex[1], 0);
					//output the type of service and details
					cout << "\tIP:  Type of service = 0x" << setfill('0') << setw(2) << hex << (int)ip_typeOfService << endl;
					if (tmp_tosBits[4] == 0) {
						cout << "\tIP:  \t...0 .... = normal delay" << endl;
					}
					else {
						cout << "\tIP:  \t...1 .... = low delay" << endl;
					}
					if (tmp_tosBits[4] == 0) {
						cout << "\tIP:  \t.... 0... = normal throughput" << endl;
					}
					else {
						cout << "\tIP:  \t....	1... = high throughput" << endl;
					}
					if (tmp_tosBits[4] == 0) {
						cout << "\tIP:  \t.... .0.. = normal reliability" << endl;
					}
					else {
						cout << "\tIP:  \t.... .1.. = high reliability" << endl;
					}

					// total length
					cout << "\tIP:  Total length = " << dec << ip_totalLength << " octets" << endl;

					// identification
					cout << "\tIP:  Identificiation = " << dec << ip_id << endl;

					// flags
					cout << "\tIP:  Flags = 0x" << hex << setw(2) << (int)ip_flagsOctets[0];
					cout << setw(2) << (int)ip_flagsOctets[1] << endl;
					if (ip_flags[1] == 0) {
						cout << "\tIP:  \t.0.. .... = do not fragment" << endl;
					}
					else {
						cout << "\tIP:  \t.1.. .... = fragment" << endl;
					}
					if (ip_flags[2] == 0) {
						cout << "\tIP:  \t..0. .... = last fragment" << endl;
					}
					else {
						cout << "\tIP:  \t..1. .... = last fragment" << endl;
					}

					// fragment offset
					cout << "\tIP:  Fragment offset = " << dec << ip_fragmentOffset << " bytes" << endl;

					// time to live
					cout << "\tIP:  Time to live = " << dec << ip_timeToLive << " seconds/hops" << endl;

					// protocol
					cout << "\tIP:  Protocol = " << dec << ip_protocol;
					if (ip_protocol == 6) {
						cout << " (TCP)" << endl;
					}
					else if (ip_protocol == 17) {
						cout << " (UDP)" << endl;
					}
					else {
						cout << " (UNKNOWN)" << endl;
					}

					// header checksum
					cout << "\tIP:  Header checksum = " << setfill('0') << setw(2) << hex << (int)ip_checksum[0] << setfill('0') << setw(2) << (int)ip_checksum[1] << endl;

					// source ip address
					cout << "\tIP:  Source address = " << dec << ip_sourceAddr[0];
					for (int i = 1; i < 4; i++) {
						cout << "." << dec << ip_sourceAddr[i];
					}
					cout << endl;

					// destination ip address
					cout << "\tIP:  Destination address = " << dec << ip_destAddr[0];
					for (int i = 1; i < 4; i++) {
						cout << "." << dec << ip_destAddr[i];
					}
					cout << endl;

					// options
					if (ip_headerLength > 20) {
						cout << "\tIP:  Some Options";
					}
					else {
						cout << "\tIP:  No Options" << endl;
					}
					cout << "\tIP: " << endl << endl;

					////////////////////////////////////////////////////////////
					// Output hex dump for current frame
					////////////////////////////////////////////////////////////
					int curCol = 1; // index of the current column
					int curRow = 0; // index of the current row
					int i = outputOctetsStart; // the index of the beginning of the frame in the buf array

					cout << "0000 ";

					// loop through all the chars until the end of the frame has been reached, outputting each
					for (; i < packetIndex; i++) {

						// once at the end of the current row, output the char representation of the hex in current row
						// and then move on to the next row.
						if (curCol % 17 == 0) {
							for (int j = i - 16; j < i; j++) {
								if ((int)((unsigned char)buf[j]) >= 33 && (int)((unsigned char)buf[j]) <= 126) {
									cout << dec << (unsigned char)buf[j];
								}
								else {
									cout << ".";
								}
							}
							cout << endl;
							curRow += 16;
							cout << setfill('0') << setw(4) << hex << curRow << " ";
							curCol++;
						}

						// output the hex for the current char
						cout << setfill('0') << setw(2) << hex << (int)((unsigned char)buf[i]) << " ";
						curCol++;
					}

					// for the final row, add whitespace to reach the right side where char representation is output
					cout << setfill(' ') << setw((17 - (curCol % 17)) * 3) << " ";

					// output the char respresentation for final row
					for (int j = i - (curCol % 17) + 1; j < i; j++) {
						if ((int)((unsigned char)buf[j]) >= 33 && (int)((unsigned char)buf[j]) <= 126) {
							cout << dec << (unsigned char)buf[j];
						}
						else {
							cout << ".";
						}
					}

					// assign the beginning of the next frame
					outputOctetsStart = packetIndex;

					cout << endl << endl;
				}

				// Flood the packet to neighbors if a packet was receied that was not addressed to this server
				else {
					string thisFrameSourceIP = to_string((int)((unsigned char)buf[28])) + "." + to_string((int)((unsigned char)buf[29])) + "." +
						to_string((int)((unsigned char)buf[30])) + "." + to_string((int)((unsigned char)buf[31]));
					string thisFrameDestIP = to_string((int)((unsigned char)buf[32])) + "." + to_string((int)((unsigned char)buf[33])) + "." +
						to_string((int)((unsigned char)buf[34])) + "." + to_string((int)((unsigned char)buf[35]));

					cout << "Received packet from " << thisFrameSourceIP << " to " << thisFrameDestIP << endl;

					// Update the Time to Live and drop packet if lived too long
					int timeToLive = (int)((unsigned char)buf[24]);
					if (timeToLive > 0) {
						timeToLive--;
						buf[24] = (char)((unsigned char)timeToLive);

						int sentFromPortNumber = (256 * (int)((unsigned char)buf[12])) + ((int)((unsigned char)buf[13]));
						//cout << "SENDING Frame ID: " << frameID << endl;

						// Update the sentFromPortNumber
						int part_pn = portNumber % 256;
						buf[13] = (char)((unsigned char)(part_pn));
						buf[12] = (char)((unsigned char)((portNumber - part_pn) / 256));

						int neighborIndexReceivedFrom = -1;

						// Get the index of thisFrameSourceIP neighbor
						for (int i = 0; i < neighborPort.size(); i++) {
							if (neighborPort[i] == sentFromPortNumber) {
								neighborIndexReceivedFrom = i;
								break;
							}

						}

						// Send the packet
						floodSender((u_char*)buf, bytesIn, neighborIndexReceivedFrom);
					}
				}


			}
		}


	}

	// Close socket
	closesocket(in);

	// Shutdown winsock
	WSACleanup();
}

///////////////////////////////////////
// Initial Sender Function
///////////////////////////////////////
//
// Description: Retrieve the data from the pcap file and then check the source ip address.
//              If this machines ip matches the ip address, send the data to all neighbors.
void initialSender() {

	// Wait for all servers to be open before sending data
	// Data will send when user inputs any key to unpause the system.
	cout << "Sender function paused. Hit any button to send data..." << endl;
	system("PAUSE");

	////////////////////////////////////////////////////////////
	// INITIALIZE WINSOCK
	////////////////////////////////////////////////////////////

	// Create a WORD that states we are using WinSock version 2.
	WORD version = MAKEWORD(2, 2);

	// Start WinSock
	WSADATA data;
	int wsOk = WSAStartup(version, &data);
	if (wsOk != 0)
	{
		cout << "Can't start Winsock! " << wsOk;
		return;
	}
	////////////////////////////////////////////////////////////
	// CONNECT TO THE SERVERS
	////////////////////////////////////////////////////////////

	// Create a vector that stores all the server sockets to neighbors
	vector<sockaddr_in> servers = vector<sockaddr_in>();
	for (int i = 0; i < numNeighbors; i++) {
		sockaddr_in server;
		server.sin_family = AF_INET; // AF_INET = IPv4 addresses
		server.sin_port = htons(neighborPort[i]); // Little to big endian conversion
		inet_pton(AF_INET, "127.0.0.1", &server.sin_addr); // Convert from string to byte array
		servers.push_back(server);
	}

	// Socket creation, note that the socket type is datagram
	SOCKET out = socket(AF_INET, SOCK_DGRAM, 0);

	////////////////////////////////////////////////////////////
	// PCAP FILE PROCESSING AND SENDING DATA TO ALL NEIGHBORS
	////////////////////////////////////////////////////////////

	// The file to be read from
	string file = pcapFileName;

	// array to store errors
	char errbuff[PCAP_ERRBUF_SIZE];

	// Open the pcap file
	pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

	// Variables to store data from each frame read in
	struct pcap_pkthdr *header; // stores pcap header for current frame
	const u_char *pcapData; // stores pcap data for current frame

	cout << "Sending data..." << endl << endl;

	// Read in all frames from the pcap file, storing only the data and not the headers
	// into the dataVector.
	while (int returnValue = pcap_next_ex(pcap, &header, &pcapData) >= 0)
	{
		// Use a vector to store all the characters read in from the pcap file.
		vector<u_char> dataVector = vector<u_char>();

		// store body into dataVector
		for (u_int i = 0; (i < header->caplen); i++)
		{
			dataVector.push_back(pcapData[i]);
		}

		string thisFrameSourceIP = to_string((int)dataVector[28]) + "." + to_string((int)dataVector[29]) + "." +
			to_string((int)dataVector[30]) + "." + to_string((int)dataVector[31]);

		// Check the source address
		if (thisFrameSourceIP == fakeIP) {

			/*
			// Output the data inside dataVector
			for (int i = 0; i < dataVector.size(); i++) {
				if ((i % 16) == 0) printf("\n");
				printf("%.2x ", dataVector[i]);
			}
			cout << endl << endl;
			*/

			// Set the time to live
			cout << "Sending data..." << endl;
			dataVector[24] = (u_char)maxTimeToLive;

			// Set the frame id
			dataVector[20] = (u_char)(vectorFakeIP[3]);
			dataVector[21] = (u_char)(currentFrameID);
			currentFrameID++;

			int frameID = (256 * (int)((unsigned char)dataVector[20])) + ((int)((unsigned char)dataVector[21]));
			cout << "SENDING Frame ID: " << frameID << endl;

			// Update the sentFromPortNumber
			int part_pn = portNumber % 256;
			dataVector[13] = (u_char)(part_pn);
			dataVector[12] = (u_char)((portNumber - part_pn) / 256);

			// convert the vector to a u_char (unsigned char) array. Because the vector is still pointing to
			// the addresses of the values inside this array, there is no need for manual garbage collection
			// at the end.
			u_char * dataToSend = &dataVector[0];

			// Send data to all neighbors
			for (int i = 0; i < numNeighbors; i++) {
				int sendOk = sendto(out, (const char *)dataToSend, dataVector.size(), 0, (sockaddr*)&servers[i], sizeof(servers[i]));

				// Output error if data failed to send
				if (sendOk == SOCKET_ERROR)
				{
					cout << "That didn't work! " << WSAGetLastError() << endl;
				}
			}
		}
	}

	cout << "finished reading pcap file" << endl << endl;
	// Close the socket
	closesocket(out);

	// Close down Winsock
	WSACleanup();

}


///////////////////////////////////////
// Main Program
////////////////////////////////////////
int main(int argc, char** argv) {

	//////////////////////////////////////////////
	// READING FROM CONFIG FILE
	//////////////////////////////////////////////
	string configFilePath;

	// There is 1 command line argument by default that points to where the project is being run from.
	// Ignore this one when analyzing command line args.

	// no command line arguments
	// have user enter the config file path
	// use default pcap file
	if (argc == 1 || argc == 0) {

		cout << "Enter the name of the config file (Not including file extension): " << endl;
		cin >> configFilePath;
		configFilePath += ".txt";
	}
	// 1 command line argument
	// use argument as config file name
	// use default pcap file
	else if (argc == 2) {
		configFilePath = argv[1];
	}
	// 2 command line arguments
	// use argument 1 as config file name
	// use argument 2 as pcap file name
	else {
		configFilePath = argv[1];
		pcapFileName = argv[2];
	}

	// open the file
	ifstream configFile;
	configFile.open(configFilePath);

	// loop through config file and assign all global variables to values in the file.
	/*
		configFileIndex Key:
		0 => fakeIP
		1 => portNum
		2 => numNeighbors
		3 => neighbor fake IP
		4 => neighbor real IP
		5 => neighbor port number
		all past this repeat the 3 through 5
	*/
	int configFileIndex = 0; // index of the current data entry being read
	if (configFile.is_open()) {
		while (!configFile.eof()) {
			// This hosts fake ip address
			if (configFileIndex == 0) {
				configFile >> fakeIP;

				// Parse the fake ip
				int j = 0;
				for (int i = 0; i < fakeIP.size(); i++) {
					if (fakeIP[i] == '.') {
						vectorFakeIP.push_back(stoi(fakeIP.substr(j, i - j)));
						j = i+1;
					}
				}
				vectorFakeIP.push_back(stoi(fakeIP.substr(j, fakeIP.size() - j)));
			}
			// This hosts port number
			else if (configFileIndex == 1) {
				configFile >> portNumber;
			}
			// The number of neighbors
			else if (configFileIndex == 2) {
				configFile >> numNeighbors;
			}
			// Neighbor fake ip address
			else if ((configFileIndex-3)%3 == 0) {
				string configOut;
				configFile >> configOut;
				neighborFakeIP.push_back(configOut);
			}
			// Neighbor real ip address
			else if ((configFileIndex - 3) % 3 == 1) {
				string configOut;
				configFile >> configOut;
				neighborRealIP.push_back(configOut);
			}
			// Neighbor port number
			else if ((configFileIndex - 3) % 3 == 2) {
				int tempNeighborPort = 0;
				configFile >> tempNeighborPort;
				neighborPort.push_back(tempNeighborPort);
			}
			configFileIndex++;
		}
	}
	configFile.close();

	// output data from config file
	cout << "Server Information: " << endl << endl;
	cout << "IP Address: " << fakeIP << endl;
	cout << "Port Number: " << portNumber << endl;
	cout << "Number of Neighbors: " << numNeighbors << endl;
	for (int i = 0; i < numNeighbors; i++) {
		cout << "Neighbor " << i << " Fake IP: " << neighborFakeIP[i] << endl;
		cout << "Neighbor " << i << " Real IP: " << neighborRealIP[i] << endl;
		cout << "Neighbor " << i << " Port Num: " << neighborPort[i] << endl;
	}

	//////////////////////////////////////////////
	// Thread Management
	//////////////////////////////////////////////

	// Create thread for sender and receiver
	thread senderThread(initialSender);
	thread receiverThread(receiver);

	// join all threads
	senderThread.join();
	receiverThread.join();

	// pause the system before exiting
	system("PAUSE");
	return 0;
}