#!/bin/bash

function tcp_json_logs() {

    awk '{
            json = "{"
            json = json " \"Session_Id\": " $1
            json = json ", \"Timestamp\": \"" $2 "\""
            json = json ", \"Src_Ip\": \"" $3 "\""
            json = json ", \"Dst_Ip\": \"" $4 "\""
            json = json ", \"Src_Port\": \"" $5 "\""
            json = json ", \"Dst_Port\": \"" $6 "\""
            json = json ", \"Flags_History\": \"" $7 "\""
            json = json ", \"Total_Packets\": \"" $8 "\"" 
            json = json ", \"Src_Packets\": \"" $9 "\""
            json = json ", \"Dst_Packets\": \"" $10 "\""
            json = json ", \"Total_Bytes\": \"" $11 "\""
            json = json ", \"Src_Bytes\": \"" $12 "\""
            json = json ", \"Dst_Bytes\": \"" $13 "\""
            json = json ", \"Connection_Duration\": \"" $14 "\""
            json = json ", \"PlainText_Payload\": \"" $15 "\""
            json = json ", \"Connection_Status\": \"" $16 "\""
            json = json " }"
            print json
        }' ./Results/.result_logs.data > ./Results/$1
}

function udp_json_logs() {

        awk '{
            json = "{"
            json = json " \"Session_Id\": " $1
            json = json ", \"Timestamp\": \"" $2 "\""
            json = json ", \"Src_Ip\": \"" $3 "\""
            json = json ", \"Dst_Ip\": \"" $4 "\""
            json = json ", \"Src_Port\": \"" $5 "\""
            json = json ", \"Dst_Port\": \"" $6 "\""
            json = json ", \"Total_Packets\": \"" $7 "\""
            json = json ", \"Src_Packets\": \"" $8 "\""
            json = json ", \"Dst_Packets\": \"" $9 "\""
            json = json ", \"Total_Bytes\": \"" $10 "\""
            json = json ", \"Src_Bytes\": \"" $11 "\""
            json = json ", \"Dst_Bytes\": \"" $12 "\""
            json = json ", \"ICMP_Type\": \"" $13 "\""
            json = json ", \"ICMP_Code\": \"" $14 "\""
            json = json ", \"Connection_Duration\": \"" $15 "\""
            json = json ", \"PlainText_Payload\": \"" $16 "\""
            json = json ", \"ICMP_Status\": \"" $17 "\""
            json = json " }"
            print json
        }' ./Results/.result_logs.data > ./Results/$1
}
