#!/bin/bash

function import_to_table() {

    sqlite3 ./Databases/$db_file 2>> .logs.log <<EOF
.mode csv
.separator ","
.import data.csv $table
EOF

    rm data.csv
}

function csv_convert() {

    awk '
    {
        for (i = 1; i <= NF; i++)
        {
            printf("%s%s", $i, (i<NF ? "," : "\n"))
        }
    } 
    ' $sample_data > data.csv
}

function import_tcp_data() {

    sqlite3 ./Databases/"$db_file" 2>> .logs.log <<EOF
    CREATE TABLE IF NOT EXISTS $table (
        Session_Id INTEGER,
        Timestamp REAL,
        Src_Ip TEXT,
        Dst_Ip TEXT,
        Src_Port INTEGER,
        Dst_Port INTEGER,
        Flags_History TEXT,
        Total_Packets INTEGER,
        Src_Packets INTEGER,
        Dst_Packets INTEGER,
        Total_Bytes INTEGER,
        Src_Bytes INTEGER,
        Dst_Bytes INTEGER,
        Connection_Duration REAL,
        PlainText_Payload TEXT,
        Connection_Status TEXT
    );
EOF
}

function import_udp_data() {

    sqlite3 ./Databases/"$db_file" 2>> .logs.log <<EOF
    CREATE TABLE IF NOT EXISTS $table (
        Session_Id INTEGER,
        Timestamp REAL,
        Src_Ip TEXT,
        Dst_Ip TEXT,
        Src_Port INTEGER,
        Dst_Port INTEGER,
        Total_Packets INTEGER,
        Src_Packets INTEGER,
        Dst_Packets INTEGER,
        Total_Bytes INTEGER,
        Src_Bytes INTEGER,
        Dst_Bytes INTEGER,
        ICMP_Type INTEGER,
        ICMP_Code INTEGER,
        Connection_Duration REAL,
        PlainText_Payload TEXT,
        ICMP_Status TEXT
    );
EOF
}

function import_http_data() {

    sqlite3 ./Databases/"$db_file" 2>> .logs.log <<EOF
    CREATE TABLE IF NOT EXISTS $table (
        Session_Id INTEGER,
        Timestamp REAL,
        Src_Ip TEXT,
        Dst_Ip TEXT,
        Src_Port INTEGER,
        Dst_Port INTEGER,
        Method TEXT,
        URI TEXT,
        User_Agent TEXT,
        Referer TEXT,
        Request_Content_Type TEXT,
        Request_Content_Length INTEGER,
        Request_File_Type TEXT,
        Request_File_Raw TEXT,
        Form_Content_Type TEXT,
        Form_File_Names TEXT,
        Form_File_Types TEXT,
        Form_File_Data TEXT,
        Response_Code INTEGER,
        Response_Content_Type TEXT,
        Response_Content_Length INTEGER,
        Response_File_Type TEXT,
        Response_File_Raw TEXT,
        Additional_Info TEXT
    );
EOF
}

function import_dns_data() {

    sqlite3 ./Databases/"$db_file" 2>> .logs.log <<EOF
    CREATE TABLE IF NOT EXISTS $table(
        Session_Id INTEGER,
        Timestamp TEXT,
        Src_Ip TEXT,
        Dst_Ip TEXT,
        Src_Port INTEGER,
        Dst_Port INTEGER,
        Transaction_ID TEXT,
        Domain TEXT,
        Domain_Length INTEGER,
        Query_Type_Code INTEGER,
        Query_Type_String TEXT,
        Answers_Packets INTEGER,
        Response_Code INTEGER,
        Response_String TEXT,
        Answers_Codes TEXT,
        Answers_Strings TEXT,
        Is_Authoritative TEXT,
        Is_Recdesired TEXT,
        Is_Recavail TEXT,
        Resp_Names TEXT,
        Answers TEXT,
        TTL TEXT,
        Additional_Info TEXT
    );
EOF
}

function import_data() {

    sample_data="./Results/${3}_${4}.parsed"
    db_file="$2"
    table="Flow_${1}_${3}"
    csv_convert

    if [ "$3" == "tcp" ]; then
        import_tcp_data
    elif [ "$3" == "udp" ]; then
        import_udp_data
    elif [ "$3" == "dns" ]; then
        import_dns_data
    elif [ "$3" == "http" ]; then
        import_http_data
    elif [ "$3" == "ssh" ]; then
        import_ssh_data
    elif [ "$3" == "smb2" ]; then
        import_smb2_data
    elif [ "$3" == "kerberos" ]; then
        import_kerberos_data
    elif [ "$3" == "ftp" ]; then
        import_ftp_data
    elif [ "$3" == "rpc" ]; then
        import_rpc_data
    elif [ "$3" == "dcerpc" ]; then
        import_dcerpc_data
    elif [ "$3" == "ntlm" ]; then
        import_ntlm_data; fi

    import_to_table
}



