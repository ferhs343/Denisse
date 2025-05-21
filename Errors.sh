#!/bin/bash

#This error occurs when a dependency cannot be installed. If this error persists, 
#it is recommended to perform the installation manually.
function instalation_error() {

	echo -e "${red} [x] An unexpected error ocurred"
	echo -e "     if this persists, it is recommended to perform the installation manually.\n${default}"
}

#This error occurs when the entered pcap file does not exist, verify that the name is correct
function input_pcap_error() {

	echo -e "${red}\n [x] Error, the file does not exist, try again.${default}"
}

#This error is caused by the PcapPlusPlus dependency when a pcap is cut. At the time of 
#Denisse publication, it is unknown if this error occurs on all computers. However, 
#if this error persists on yours, follow the steps described in the documentation to solve it.
function pcapplusplus_error() {

	echo -e "${red}\n [x] An error occurred while processing the pcap file."
	echo -e " If this error persists, follow the steps in the documentation.${default}"
}

#This error occurs when the user provides an unsupported protocol as an argument
#Supported protocols: [tcp,udp,http,dns,smb2,rpc,dcerpc,ntlm,kerberos,ftp,ssh]
function input_protocol_error() {

	echo -e "${red}\n ERROR, one of the specified protocols is not valid.\n${default}"
}

#This error occurs when the tool is not run as root user
function root_error() {

	echo -e "${red}\n [x] ERROR, to run this you must be root. \n${default}"
}
