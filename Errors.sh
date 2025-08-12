#!/bin/bash

#This error occurs when a dependency cannot be installed. If this error persists, 
#it is recommended to perform the installation manually.
function instalation_error() 
{

	echo -e "${r} [x] An unexpected error ocurred"
	echo -e "     if this persists, it is recommended to perform the installation manually.\n${d}"
}

#This error occurs when the entered pcap file does not exist, verify that the name is correct
function input_pcap_error() 
{

	echo -e "${r}\n [x] Error, the file does not exist, try again.\n${d}"
}

#This error occurs when the user provides an unsupported protocol as an argument
#Supported protocols: [tcp,udp,http,dns,smb2,rpc,dcerpc,ntlm,kerberos,ftp,ssh]
function input_protocol_error() 
{
	array=("$@")
	echo -e "${r}\n [x] ERROR, one of the specified protocols is not valid. 
    Supported protocols ==> [${array[*]}] \n${d}"
}

#This error occurs when the tool is not run as root user
function root_error() 
{

	echo -e "${r}\n [x] ERROR, to run this you must be root. \n${d}"
}

function option_error() 
{

	echo -e "${r}\n [x] ERROR, enter a valid option. \n${d}"
}

function protocols_error() 
{

	echo -e "${r}\n [x] An error occurred while finding compatible protocols in the pcap file.\n${d}"
}

function process_error()
{

	echo -e "${r}\n [x] ERROR, the specified number of processes is greater, your CPU has: ${1}.\n${d}"
}

function limit_error()
{

	echo -e "${r}\n [x] ERROR, It was not possible to configure the system limits.\n${d}"
}
