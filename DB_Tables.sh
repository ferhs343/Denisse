#!/bin/bash

function import_to_table() {

    sqlite3 "$1" 2>> .logs.log <<EOF
.mode csv
.separator ","
.import data.csv $2
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
    ' $1 > data.csv
}

function import_tcp_data() {

    sample_data="./Results/.sample.data"
    db_file="$2"
    table="Flow_${1}_TCP"
    csv_convert "$sample_data"

    sqlite3 "$db_file" 2>> .logs.log <<EOF
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

    import_to_table "$db_file" "$table"
}

function import_udp_data() {

    sample_data="./Results/.sample1.data"
    db_file="$2"
    table="Flow_${1}_UDP"
    csv_convert "$sample_data"

    sqlite3 "$db_file" 2>> .logs.log <<EOF
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

    import_to_table "$db_file" "$table"
}
