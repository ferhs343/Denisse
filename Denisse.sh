#!/bin/bash
 
# 'The Denisse's Project' v.1.0.0
# By: Luis Fernando Herrera - luis.herrera@scitum.com.mx
 
source Errors.sh
source Alerts.sh
source Json_Logs.sh
source DB_Tables.sh
source Banners.sh
source Rules.sh
 
r="\e[0;31m\033[1m"
d="\033[0m\e[0m"
y="\e[0;33m\033[1m"
g="\033[92m"
c="\e[0;36m"
p="\e[1;95m"
o="\e[38;5;208m"
f="\e[38;5;226m"
s="\e[38;5;240m"
 
dependencies=(
    "libpcap-dev"
    "build-essential"
    "libssl-dev"
    "libboost-all-dev"
    "tshark" #Request ==> v4.2.2
    "cmake"
    "g++"
    "dpkg"
    "git"
    "sqlite3"
    "PcapSplitter" #Request ==> v23.09
    "zstd"
)

function LocToLoc_regex() {

    awk '($3 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/ && $4 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/)' \
    ./Results/$filename 2> /dev/null > ./Results/$filename.tmp
}

function PubToLoc_regex() {

    awk '($3 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/' \
    ./Results/$filename 2> /dev/null > ./Results/$filename.tmp
}

function tcp_parser() 
{

    awk '
        function flag_name(f) 
        {
            if ( f ~ /02$/ ) { return "Syn" }
            else if ( f ~ /12$/ ) { return "SynAck" }
            else if ( f ~ /10$/ ) { return "Ack" }
            else if ( f ~ /04$/ ) { return "Rst" }
            else if ( f ~ /14$/ ) { return "RstAck" }
            else if ( f ~ /01$/ ) { return "Fin" }
            else if ( f ~ /11$/ ) { return "FinAck" }
            else if ( f ~ /00$/ ) { return "Null" }
            else if ( f ~ /08$/ ) { return "Push" }
            else if ( f ~ /18$/ ) { return "PushAck" }
            else if ( f ~ /29$/ ) { return "Fin;Push;Urg" }
            return "NPI"
        }

        function get_status(s) 
        {
            has_syn = has_synack = has_ack = has_rst = has_rstack = has_fin = has_finack = has_null = has_push = has_pushack = has_xmas = 0
            split(flags_list[s], arr, " ")

            for ( i in arr ) 
            {
                if ( arr[i] == "Syn" ) { has_syn = 1 }
                else if ( arr[i] == "SynAck" ) { has_synack = 1 }
                else if ( arr[i] == "Ack" ) { has_ack = 1 }
                else if ( arr[i] == "Rst" ) { has_rst = 1 }
                else if ( arr[i] == "RstAck" ) { has_rstack = 1 }
                else if ( arr[i] == "Fin" ) { has_fin = 1 }
                else if ( arr[i] == "FinAck" ) { has_finack = 1 }
                else if ( arr[i] == "Null" ) { has_null = 1 }
                else if ( arr[i] == "Push" ) { has_push = 1 }
                else if ( arr[i] == "PushAck" ) { has_pushack = 1 }
                else if ( arr[i] == "Fin;Push;Urg" ) { has_xmas = 1 }
            }

            if ((has_syn && has_rstack) &&
                (!has_synack && !has_ack && !has_rst && !has_fin &&
                !has_finack && !has_null && !has_push && !has_pushack && !has_xmas))
                    return "Started-Rejected"

            if ((has_syn && has_synack && has_ack && has_rstack) &&
                (!has_rst && !has_fin && !has_finack && !has_null && !has_push &&
                !has_pushack && !!has_xmas))
                    return "Completed-Reset"

            if ((has_syn && has_synack && has_ack && has_pushack && has_finack) &&
                (!has_rstack && !has_fin && !has_null && !has_push && !has_xmas))
                    return "Finished-payload"

            if ((has_syn && has_synack && has_ack && has_pushack && has_rstack) &&
                (!has_finack && !has_fin && !has_null && !has_push && !has_xmas))
                    return "Reseted-payload"

            if ((has_syn && has_synack && has_ack && has_rstack) &&
                (!has_fin && !has_finack && !has_null && !has_push && !has_pushack &&
                !has_xmas))
                    return "SemiCompleted-Reset"

            if ((has_syn) &&
                (!has_synack && !has_ack && !has_rst && !has_rstack && !has_fin &&
                !has_finack && !has_null && !has_push && !has_pushack && !has_xmas))
                    return "Syn-only"

            if ((has_xmas) &&
                (!has_synack && !has_ack && !has_rst && !has_rstack && !has_fin &&
                !has_finack && !has_null && !has_push && !has_pushack && !has_syn))
                    return "Xmas"

            if ((has_null) &&
                (!has_synack && !has_ack && !has_rst && !has_rstack && !has_fin &&
                !has_finack && !has_syn && !has_push && !has_pushack && !has_xmas))
                    return "Null"

            if ((has_finack) &&
                (!has_synack && !has_ack && !has_rst && !has_rstack && !has_fin &&
                !has_syn && !has_null && !has_push && !has_pushack && !has_xmas))
                    return "Maimon"

            if ((has_ack) &&
                (!has_synack && !has_syn && !has_rst && !has_rstack && !has_fin &&
                !has_finack && !has_null && !has_push && !has_pushack && !has_xmas))
                    return "Ack-only"

            if ((has_fin) &&
                (!has_synack && !has_ack && !has_rst && !has_rstack && !has_syn &&
                !has_finack && !has_null && !has_push && !has_pushack && !has_xmas))
                    return "Fin-only"

            else return "NPI"
        }

        {
            session = $1

            if ( !( session in seen ) ) 
            {
                seen[session] = $0
                src_ip[session] = $3
                dst_ip[session] = $4
            }

            if ( !( session in timestamp_start ) ) 
            {
                timestamp_start[session] = $2
            }
            
            timestamp_end[session] = $2

            flag_key = session "|" $5

            if ( !( flag_key in flag_seen ) ) 
            {
                flag_seen[flag_key] = 1
                fname = flag_name($5)
                flags_list[session] = flags_list[session] " " fname
            }

            if ( $3 == src_ip[session] ) 
            {
                src_size[session] += $6
                src_pkts[session] ++
            }

            if ( $3 == dst_ip[session] ) 
            {
                dst_size[session] += $6
                dst_pkts[session] ++
            }

            total_size[session] += $6
            total_pkts[session] ++

            if ( NF > 8 ) 
            {
                payload = ""

                for ( i = 9; i <= NF; i++ ) 
                {
                    payload = ( payload == "" ) ? $i : payload ";" $i
                }

                if ( payloads[session] == "" ) 
                {
                    payloads[session] = "[" payload 
                } 
                else 
                {
                    payloads[session] = payloads[session] ";" payload
                }
            }
        }

        END {
            for ( s in seen ) 
            {
                split(seen[s], fields)
                status = get_status(s)
                duration = timestamp_end[s] - timestamp_start[s]

                if ( payloads[s] != "" ) 
                {
                    payloads[s] = payloads[s] "]"
                } 
                else 
                {
                    payloads[s] = "[Null]"
                }

                gsub(/^ +| +$/, "", flags_list[s])
                gsub(/ +/, ";", flags_list[s])

                print fields[1], fields[2], fields[3], fields[4], fields[7], fields[8], flags_list[s], 
                total_pkts[s]+0, src_pkts[s]+0, dst_pkts[s]+0, total_size[s]+0, src_size[s]+0, dst_size[s]+0, 
                duration, payloads[s], status
            }
        }' ./Results/"$data" > "./Results/${data_dir}/Data/${id_pcap_file}_${type}.parsed"
}

function pre_rule_tcp_Port_Scan() {

    conn_status=($(awk '{print $NF}' ./Results/$data_pcap_f/Data/$1 | sort -u))
    src=()
    dst=()

    echo -e "\n [+] TCP/UDP Connection Status ==> [${conn_status[*]}]" >> .logs.log

    for ((l = 0; l < ${#conn_status[@]}; l++)); do
        status="${conn_status[$l]}"
        if [[ "$status" != "NPI" &&
              "$status" != "Finished-payload" &&
              "$status" != "Reseted-payload"
            ]]; then
            src=($(
                awk -v status="$status" '$NF == status {print $3}' \
                    ./Results/$data_pcap_f/Data/$1 | sort | uniq -c | sort -rn |
                    awk '$1 > 2 {print $2}'
            ))
            for ((m = 0; m <= ${#src[@]} - 1; m++)); do
                src_ip="${src[$m]}"
                dst=($(
                    awk -v status="$status" \
                        -v src_ip="$src_ip" \
                        '$NF == status && $3 == src_ip {print $4}' \
                        ./Results/$data_pcap_f/Data/$1 | sort -u
                ))
                #case 1 : 1 ==> 1
                if [ ${#dst[@]} -eq 1 ]; then
                    dst_ip="${dst[0]}"
                    n_ports=$(
                        awk -v status="$status" \
                            -v src_ip="$src_ip" \
                            -v dst_ip="$dst_ip" \
                            '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                            ./Results/$data_pcap_f/Data/$1 | sort -u | wc -l
                    )

                    echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

                    if [ "$n_ports" -gt 10 ]; then
                        vertical_scan=1
                        alert="${src_type} ${VPS}"
                        echo $alert
                        #generate_results_tcp "$dst_ip";
                    fi
                else
                    #case 2 : 1 ==> N
                    ports_a=()
                    for ((n = 0; n <= ${#dst[@]} - 1; n++)); do
                        dst_ip="${dst[$n]}"
                        n_ports=$(
                            awk -v status="$status" \
                                -v src_ip="$src_ip" \
                                -v dst_ip="$dst_ip" \
                                '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                                ./Results/$data_pcap_f/Data/$1 | sort -u | wc -l
                        )

                        echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

                        if [ "$n_ports" -gt 10 ]; then
                            vertical_scan=1
                            alert="${src_type} ${VPS}"
                            echo $alert
                            #generate_results_tcp "$dst_ip"
                        else
                            ports=$(
                                awk -v status="$status" \
                                    -v src_ip="$src_ip" \
                                    -v dst_ip="$dst_ip" \
                                    '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                                    ./Results/$data_pcap_f/Data/$1 | sort -u
                            )
                            ports_a+=("$ports"); fi; done

                    echo -e "\n [+] TCP/UDP Horizontal Scan proof - Ports ==> [${ports_a[*]}]" >> .logs.log
                    echo -e "\n [+] TCP/UDP Horizontal Scan proof - Dst IP's [${dst[*]}]" >> .logs.log

                    multiple_dst=()
                    for ((n = 0; n <= ${#ports_a[@]} - 1; n++)); do
                        current="${ports_a[$n]}"
                        for ((o = $n + 1; o <= ${#ports_a[@]} - 1; o++)); do
                            next="${ports_a[$o]}"
                            if [ "$current" == "$next" ]; then
                                if [ "${ports_a[$n]}" != "1" ]; then
                                    ports_a[$n]="1"; fi
                                    ports_a[$o]="1"; fi; done; done

                    echo -e "\n [+] TCP/UDP Horizontal Scan proof - Result [${ports_a[*]}]" >> .logs.log

                    for ((n = 0; n <= ${#ports_a[@]} - 1; n++)); do
                        if [ "${ports_a[$n]}" == "1" ]; then
                            multiple_dst+=("${dst[$n]}"); fi; done

                    echo -e "\n [+] TCP/UDP Horizontal Scan proof - Result [${multiple_dst[*]}]" >> .logs.log

                    if [ "${#multiple_dst[@]}" -gt 0 ]; then
                        horizontal_scan=1
                        alert="${src_type} ${HPS}"
                        echo $alert
                        #generate_results_tcp "${multiple_dst[@]}"; 
                        fi
                        fi; done; fi; done
}

function udp_parser() 
{

    if [ -s "./Results/${id_pcap_file}_icmp.data" ]; then
        tr ',' ' ' < ./Results/${id_pcap_file}_icmp.data | \
        awk '{print $1 " " $3 " " $5 " " $6 " " $7 " " $8 " " $9}' \
        2> /dev/null > ./Results/${id_pcap_file}_icmp1.data
    else
        echo "0 0.0.0.0 0.0.0.0 1 1 3 3" > ./Results/${id_pcap_file}_icmp1.data; fi

    awk '
        #first data file ==> icmp data

        FNR==NR {
            #key ==> session_id, src_ip, dst_ip, src_port, dst_port
            key = $1 FS $2 FS $3 FS $4 FS $5

            #value key ==> icmp_type, icmp_code
            extra[key] = $6 FS $7

            next
        }

        #second data file ==> udp data (without icmp data)

        {
            #key ==> session_id, src_ip, dst_ip, src_port, dst_port
            key = $1 FS $3 FS $4 FS $6 FS $7

            if ( key in extra )
            {
                print $0, extra[key]
            }
            else
            {
                print $0, "NA NA"
            }
        }
    ' ./Results/${id_pcap_file}_icmp1.data ./Results/$data > ./Results/${id_pcap_file}_sample.data

    awk '
        function icmp_flag_name(type, code) 
        {
            if ( type == 3 )
            {
                if ( code == 3 ) { return "port-unreachable" }
                else { return "unreachable" }
            }

            else return "other"
        }

        function get_icmp_status(s) 
        {
            has_unreachable = 0
            split(icmp_flags_list[s], arr, " ")

            for ( i in arr ) 
            {
                if ( arr[i] == "port-unreachable" ) { has_unreachable = 1 }
            }

            if ( has_unreachable ) { return "Unreachable" }
            return "NPI"
        }

        {
            #key 1 ==> src_ip, dst_ip, src_port, dst_port (A -> B)
            fwd_key = $3 " " $4 " " $6 " " $7
            #key 2 ==> dst_ip, src_ip, dst_port, src_port (B -> A)
            rev_key = $4 " " $3 " " $7 " " $6

            if ( !( fwd_key in first_seen ) && !( rev_key in first_seen ) ) 
            {
                key = fwd_key
                first_seen[key] = $0
                session_id[key] = $1
                timestamp[key] = $2
            } 
            else 
            {
                key = ( fwd_key in first_seen ) ? fwd_key : rev_key
            }

            if ( !( key in src_ip ) ) 
            {
                split(key, parts, " ")
                src_ip[key] = parts[1]
                dst_ip[key] = parts[2]
                src_port[key] = parts[3]
                dst_port[key] = parts[4]
            }

            if ( $3 == src_ip[key] ) 
            {
                src_size[key] += $5
                src_pkts[key] ++
            } 
            else 
            {
                dst_size[key] += $5
                dst_pkts[key] ++
            }

            total_size[key] += $5
            total_pkts[key] ++

            if ( !( key in timestamp_start ) ) 
            {
                timestamp_start[key] = $2
            }

            timestamp_end[key] = $2

            if ( $(NF - 1) ~ /^[0-9]+$/ && $NF ~ /^[0-9]+$/ ) 
            {
                icmp_type_val = $(NF - 1)
                icmp_code_val = $NF

                if ( !( key in icmp_type_first ) ) 
                {
                    icmp_type_first[key] = icmp_type_val
                    icmp_code_first[key] = icmp_code_val
                }

                flag_key = key "|" icmp_type_val "|" icmp_code_val
                if ( !( flag_key in flag_seen ) ) 
                {
                    flag_seen[flag_key] = 1
                    fname = icmp_flag_name(icmp_type_val, icmp_code_val)
                    icmp_flags_list[key] = icmp_flags_list[key] " " fname
                }
            }

            if ( NF > 9 )
            {
                payload = ""

                for ( i = 8; i < NF - 1; i++ ) 
                {
                    payload = ( payload == "" ) ? $i : payload ";" $i
                }

                if ( payloads[key] == "" ) 
                {
                    payloads[key] = "[" payload
                } 
                else 
                {
                    payloads[key] = payloads[key] ";" payload
                }
            }
        }

        END {
            for ( k in first_seen ) 
            {
                icmp_type_out = ( k in icmp_type_first ) ? icmp_type_first[k] : "NA"
                icmp_code_out = ( k in icmp_code_first ) ? icmp_code_first[k] : "NA"
                status = get_icmp_status(k)
                duration = ( timestamp_end[k] - timestamp_start[k] )

                if ( payloads[k] != "" ) 
                {
                    payloads[k] = payloads[k] "]"
                } 
                else 
                {
                    payloads[k] = "[Null]"
                }

                print session_id[k], timestamp[k], src_ip[k], dst_ip[k], src_port[k], dst_port[k], 
                total_pkts[k]+0, src_pkts[k]+0, dst_pkts[k]+0, total_size[k]+0, src_size[k]+0, dst_size[k]+0, 
                icmp_type_out, icmp_code_out, duration, payloads[k], status
            }
        }
    ' ./Results/${id_pcap_file}_sample.data > "./Results/${data_dir}/Data/${id_pcap_file}_${type}.parsed"
}

function http_parser() 
{

    awk '

        function ord(c)
        {
            return index(" !\"#$%&'\''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", c) + 31
        }

        function get_file_type(data)
        {
            if ( substr(data, 1, 8) == "4d534346" ) 
                return "CABInstaller"

            else if ( substr(data, 1, 8) == "25504446" ) 
                return "PDFDocument"

            else if ( substr(data, 1, 4) == "ffd8" ) 
                return "JPEGImage"

            else if ( substr(data, 1, 8) == "47494638" ) 
                return "GIFFile"

            else if ( substr(data, 1, 8) == "89504e47" ) 
                return "PNGImage"

            else if ( substr(data, 1, 8) == "504b0304" ) 
                return "PKZip"

            else if ( substr(data, 1, 6) == "1f8b08" ) 
                return "GZip"

            else if ( substr(data, 1, 10) == "7573746172" ) 
                return "TARFile"

            else if ( substr(data, 1, 16) == "d0cf11e0a1b11ae1" ) 
                return "MicrosoftFile"

            else if ( substr(data, 1, 2) == "4d5a" ) 
                return "ExecutableFile"

            else if ( substr(data, 1, 8) == "504b0304" )    
                return "OfficeFile"

            else if ( substr(data, 1, 14) == "526172211a0700" ) 
                return "RARFile"

            else if ( substr(data, 1, 8) == "7f454c46" ) 
                return "UnixELF"

            else if ( substr(data, 1, 10) == "3c3f706870" ) 
                return "PHPFile"

            else if ( substr(data, 1, 14) == "3c254070616765" )
                return "JSPFile"

            return "NPI"
        }

        {
            if ( $5 != "Null" && $6 != "Null" ) 
            {
                src = $5; dst = $6
            } 
            else if ( $3 != "Null" && $4 != "Null" ) 
            {
                src = $3; dst = $4
            } 
            else 
            {
                next
            }

            if ( $9 != "Null" )
            {
                aux = $NF
            }
            else if ( $15 ~ /^[1-5][0-9][0-9]$/ )
            {
                aux = $(NF - 1)
            }

            key = $1 ":" src ":" dst ":" $7 ":" $8 ":" aux
            rev_key = $1 ":" dst ":" src ":" $8 ":" $7 ":" aux

            if ( $9 != "Null" ) 
            {
                req_seen[key] = 1
                session_id[key] = $1
                timestamp[key] = $2
                src_ip[key] = src
                dst_ip[key] = dst
                src_port[key] = $7
                dst_port[key] = $8
                method[key] = $9
                full_uri[key] = $10
                user_agent[key] = $11
                referer[key] = $12
                req_content_type[key] = $13
                req_content_length[key] = $14
                req_file_data[key] = $16
                req_file_type[key] = ""
                mime_content_type[key] = $17
                form_filenames[key] = ""
                form_files_type[key] = ""
                form_files_data[key] = ""
                boundary = ""

                if ( req_file_data[key] != "Null" )
                {
                    req_file_type[key] = get_file_type(req_file_data[key])
                }

                if ( req_content_type[key] ~ /^multipart\/form-data/ )
                {
                    split(req_content_type[key], parts, "boundary=")
                    boundary = parts[2]
                    delimit = "0d0a0d0a"
                    bound_hex = ""
                    
                    for ( i = 1; i <= length(boundary); i++ )
                    {
                        c = substr(boundary, i, 1)
                        bound_hex = bound_hex sprintf("%02x", ord(c))
                    }

                    file_data = req_file_data[key]

                    while ( match(file_data, bound_hex) )
                    {
                        file_data = substr(file_data, RSTART + RLENGTH)
                        if ( match(file_data, delimit) )
                        {
                            file_data = substr(file_data, RSTART + RLENGTH)
                            if ( match(file_data, bound_hex) )
                            {
                                raw_file = substr(file_data, 1, RSTART - 1)
                                
                                for ( i = length(raw_file); i >= 1; i -= 2 )
                                {
                                    byte = substr(raw_file, i - 1, 2)
                                    if ( byte == "0d" )
                                    {
                                        file = substr(file_data, 1, i - 2)
                                        form_files_type[key] = form_files_type[key] "[" get_file_type(file) "]"
                                        form_files_data[key] = form_files_data[key] "[" file "]"
                                        break
                                    }
                                }
                            }
                        }
                    }

                    if ( $18 != "Null" )
                    {
                        split($18, parts, ";")

                        for ( i = 1; i <= length(parts); ++i )
                        {
                            if ( parts[i] ~ "filename" )
                            {
                                gsub("\"", "", parts[i])
                                gsub("=", " ", parts[i])
                                split(parts[i], two, " ")
                                form_filenames[key] = form_filenames[key] "[" two[2] "]"
                            }
                        }
                    }
                }

                if ( req_file_type[key] == "" )
                {
                    req_file_type[key] = "Null"
                }

                if ( form_filenames[key] == "" )
                {
                    form_filenames[key] = "Null"
                }

                if ( form_files_type[key] == "" )
                {
                    form_files_type[key] = "Null"
                }

                if ( form_files_data[key] == "" )
                {
                    form_files_data[key] = "Null"
                }
            } 
            else if ( $15 ~ /^[1-5][0-9][0-9]$/ )
            {
                resp_seen[rev_key] = 1
                resp_content_type[rev_key] = $13
                resp_content_length[rev_key] = $14
                response_code[rev_key] = $15
                resp_file_data[rev_key] = $16
                resp_file_type[rev_key] = ""

                if ( resp_file_data[rev_key] != "Null" )
                {
                    resp_file_type[rev_key] = get_file_type(resp_file_data[rev_key])
                }

                if ( resp_file_type[rev_key] == "" )
                {
                    resp_file_type[rev_key] = "Null"
                }
            }
        }

        END {

            for ( k in req_seen )
            {
                if ( k in resp_seen )
                {
                    print session_id[k], timestamp[k], src_ip[k], dst_ip[k], src_port[k], dst_port[k], method[k], 
                    full_uri[k], user_agent[k], referer[k], req_content_type[k], req_content_length[k], req_file_type[k]+0,
                    req_file_data[k], mime_content_type[k], form_filenames[k], form_files_type[k], form_files_data[k], 
                    response_code[k], resp_content_type[k], resp_content_length[k]+0, resp_file_type[k], resp_file_data[k], 
                    "Matched"
                }

                if ( !( k in resp_seen ) )
                {
                    print session_id[k], timestamp[k], src_ip[k], dst_ip[k], src_port[k], dst_port[k], 
                    method[k], full_uri[k], user_agent[k], referer[k], req_content_type[k], req_content_length[k]+0, 
                    req_file_type[k], req_file_data[k], mime_content_type[k], form_filenames[k], form_files_type[k], 
                    form_files_data[k], "0", "Null", "0", "Null", "Null", "Only-Request"
                }
            }

            for ( k in resp_seen )
            {
                if ( !( k in req_seen ) )
                {
                    print $1, $2, dst, src, $8, $7, "Null", "Null", "Null", "Null", "Null", "0", "Null", 
                    "Null", "Null", "Null", "Null", "Null", response_code[k], resp_content_type[k], 
                    resp_content_length[k]+0, resp_file_type[k], resp_file_data[k], "Only-Response"
                }
            }
        }
        ' ./Results/"$data" > "./Results/${data_dir}/Data/${id_pcap_file}_${type}.parsed"
}

function dns_parser() 
{

    awk '

        function request_type(req_type)
        {
            if ( req_type == 1 ) { return "A" }
            else if ( req_type == 2 ) { return "NS" }
            else if ( req_type == 5 ) { return "CNAME" }
            else if ( req_type == 12 ) { return "PTR" }
            else if ( req_type == 15 ) { return "MX" }
            else if ( req_type == 16 ) { return "TXT" }
            else if ( req_type == 28 ) { return "AAAA" }
            else if ( req_type == 33 ) { return "SRV" }
            return "NPI"
        }

        function response_type(resp_type)
        {
            if ( resp_type == 0 ) { return "NOERROR" }
            else if ( resp_type == 1 ) { return "FORMERR" }
            else if ( resp_type == 2 ) { return "SERVFAIL" }
            else if ( resp_type == 3 ) { return "NXDOMAIN" }
            else if ( resp_type == 4 ) { return "NOTIMP" }
            else if ( resp_type == 5 ) { return "REFUSED" }
            return "NPI"
        }

        function concat(X, Y, Z)
        {
            old = ( X[Y] == "" ) ? "[Null]" : "[" X[Y] "]"
            new = ( X[Z] == "" ) ? "[Null]" : "[" X[Z] "]"
            return old new
        }

        {
            if ( $3 != "Null" && $4 != "Null" )
            {
                src = $3; dst = $4
            }
            else if ( $5 != "Null" && $6 != "Null" )
            {
                src = $5; dst = $6
            }
            else 
            {
                next
            }

            if ( $9 == "False" )
            {
                aux = $(NF - 3)
            }
            else if ( $9 == "True" )
            {
                aux = ( $( NF - 1 ) == "Null" ) ? $( NF - 2 ) : $NF
            }

            key = src ":" dst ":" $7 ":" $8 ":" $10 ":" aux
            rev_key = dst ":" src ":" $8 ":" $7 ":" $10 ":" aux

            if ( $9 == "False" || $9 == 0 )
            {
                session = src ":" dst ":" $7 ":" $8

                if ( !( session in session_id ) )
                {
                    session_id[key] = $1
                }

                req_seen[key] = 1
                timestamp[key] = $2
                src_ip[key] = src
                dst_ip[key] = dst
                src_port[key] = $7
                dst_port[key] = $8
                trans_id[key] = $10
                domain[key] = $11
                domain_lenght[key] = $12
                rtype_code[key] = $13
                rtype_string[key] = request_type(rtype_code[key])
            }
            else if ( $9 == "True" || $9 == 1 )
            {
                rev_key_resp = dst ":" src ":" $8 ":" $7 ":" $10 ":" ( ( $( NF - 1 ) ==  "Null" ) ? $( NF - 3 ) : $NF )
                count[rev_key_resp] ++
                retransmit[rev_key_resp,count[rev_key_resp]] = rev_key
                resp_seen[rev_key] = 1

                rptype_code[rev_key] = $14
                rptype_string[rev_key] = response_type(rptype_code[rev_key])
                is_authoritative[rev_key] = $15
                is_recdesired[rev_key] = $16
                is_recavail[rev_key] = $17
                rp_type_codes[rev_key] = $18
                resp_names[rev_key] = $19
                ttl[rev_key] = $30
                answers[rev_key] = ""
                separator = ""

                rp_codes = split(rp_type_codes[rev_key], rp, ";")

                if ( rp_codes > 1 )
                {
                    for ( i = 1; i <= rp_codes; i++ )
                    {
                        for ( j = 1; j < rp_codes; j++ )
                        {
                            if ( rp[j] > rp[j+1] )
                            {
                                value_code = rp[j]
                                rp[j] = rp[j+1]
                                rp[j+1] = value_code
                            }
                        }
                    }
                }

                rp_type_codes[rev_key] = ""

                for ( i = 1; i <= rp_codes; i++ )
                {
                    rp_type_codes[rev_key] = rp_type_codes[rev_key] separator rp[i]
                    string_code = request_type(rp[i])
                    rp_type_strings[rev_key] = rp_type_strings[rev_key] (( string_code != "" ) ? separator string_code : "")
                    separator = ";"
                }

                separator = ""

                for ( it = 20; it <= 29; it++ )
                {
                    gsub(";", "/", $it)

                    if ( $it != "Null" )
                    {
                        value = $it

                        if ( it == 27 ) 
                        {
                            value = $27 "->" $28 "->" $29
                            it = 29
                        }

                        answers[rev_key] = answers[rev_key] separator value
                        separator = "/"
                    }   
                }
            }
        }

        END {

            for ( key in count )
            {
                if ( count[key] > 1 )
                {
                    for ( i = 1; i <= count[key]; i++ )
                    {
                        pkt = retransmit[key,i]

                        if ( pkt in req_seen )
                        {
                            request = pkt
                            break
                        }
                    }

                    for ( i = 1; i <= count[key]; i++ )
                    {
                        pkt = retransmit[key,i]

                        if ( !( pkt in req_seen ) )
                        {
                            rptype_string[request] = "[" rptype_string[request] "]" ((rptype_string[pkt] == "") ? "[Null]" : \
                            "[" response_type(rptype_code[pkt]) "]")

                            rptype_code[request] = concat(rptype_code, request, pkt)
                            rp_type_codes[request] = concat(rp_type_codes, request, pkt)
                            rp_type_strings[request] = concat(rp_type_strings, request, pkt)
                            answers[request] = concat(answers, request, pkt)
                            is_authoritative[request] = concat(is_authoritative, request, pkt)
                            is_recdesired[request] = concat(is_recdesired, request, pkt)
                            is_recavail[request] = concat(is_recavail, request, pkt)
                            resp_names[request] = concat(resp_names, request, pkt)
                            ttl[request] = concat(ttl, request, pkt)

                            delete resp_seen[pkt]
                        }
                    }
                }
            }

            for ( k in req_seen )
            {
                clean = answers[k]
                gsub(/\]\[/, " ", clean)
                n_count = split(clean, n, " ")

                for ( i = 1; i <= n_count; i++ )
                {
                    count_n[k] ++
                }
                
                if ( answers[k] == "" )
                {
                    answers[k] = "[Empty]"
                }

                if ( k in resp_seen )
                {
                    add_info = ( count_n[k]+0 > 1) ? "Matched-With-Multiple-Answers" : "Matched"

                    print session_id[k], timestamp[k], src_ip[k], dst_ip[k], src_port[k], dst_port[k],
                    trans_id[k], domain[k], domain_lenght[k], rtype_code[k], rtype_string[k], count_n[k]+0,
                    rptype_code[k], rptype_string[k], rp_type_codes[k], rp_type_strings[k], is_authoritative[k], 
                    is_recdesired[k], is_recavail[k], resp_names[k], answers[k], ttl[k], 
                    add_info
                }

                if ( !( k in resp_seen ) )
                {
                    print session_id[k], timestamp[k], src_ip[k], dst_ip[k], src_port[k], dst_port[k],
                    trans_id[k], domain[k], domain_lenght[k], rtype_code[k], rtype_string[k], count_n[k]+0,
                    "Null", "Null", "Null", "Null", "Null", "Null", "Null", "Null", "Null", "Null", "Only-Query"
                }
            }

            for ( k in resp_seen )
            {
                if ( answers[k] == "" )
                {
                    answers[k] = "[Empty]"
                }
                
                if ( !( k in req_seen ) )
                {
                    print $1, $2, dst, src, $8, $7, $10, $11, $12, $13, request_type($13), "1", rptype_code[k], 
                    rptype_string[k], rp_type_codes[k], rp_type_strings[k], is_authoritative[k], is_recdesired[k],
                    is_recavail[k], resp_names[k], answers[k], ttl[k], "Only-Answer"
                }
            }
        }' ./Results/"$data" > "./Results/${data_dir}/Data/${id_pcap_file}_${type}.parsed"
}

function pcap_ripper() 
{

    if [ "$proto" == "tcp" ]; then
        tshark -r ./Results/${data_dir}/Trims/$file -Y "tcp" -T fields \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "tcp.flags" \
            -e "tcp.len" -e "tcp.srcport" -e "tcp.dstport" -e "data"\
            2> /dev/null > ./Results/${id_pcap_file}_${proto}.data
            pids+=("$!"); fi

    if [ "$proto" == "udp" ]; then
        tshark -r ./Results/${data_dir}/Trims/$file -Y "udp && not icmp" -T fields \
            -e "udp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "udp.length" \
            -e "udp.srcport" -e "udp.dstport" -e "data" \
            2> /dev/null > ./Results/${id_pcap_file}_${proto}.data
            pids+=("$!")

        tshark -r ./Results/${data_dir}/Trims/$file -Y "icmp" -T fields \
            -e "udp.stream" -e "ip.src" -e "ip.dst" \
            -e "udp.srcport" -e "udp.dstport" -e "icmp.type" \
            -e "icmp.code" 2> /dev/null > ./Results/${id_pcap_file}_icmp.data
            pids+=("$!"); fi

    if [ "$proto" == "http" ]; then
        tshark -r ./Results/${data_dir}/Trims/$file -Y "http" -T fields \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "tcp.srcport" \
            -e "tcp.dstport" -e "http.request.method" \
            -e "http.request.full_uri" -e "http.user_agent" \
            -e "http.referer" -e "http.content_type" \
            -e "http.content_length" -e "http.response.code" \
            -e "http.file_data" -e "mime_multipart.header.content-type" \
            -e "mime_multipart.header.content-disposition" \
            -e "http.request_in" -e "frame.number" 2> /dev/null | \
            awk -F'\t' '
                {
                    gsub(/,/, "[comma]")
                    gsub(" ", "[tab]")
                }

                {
                    for ( i = 1; i <= NF; i++ )
                    {
                        if ( $i == "" ) $i = "Null"
                    }

                    OFS="\t"; print
                }' > ./Results/${id_pcap_file}_${proto}.data
                pids+=("$!"); fi

    if [ "$proto" == "dns" ]; then
        tshark -r ./Results/${data_dir}/Trims/$file -Y "dns" -T fields \
            -e "udp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "udp.srcport" \
            -e "udp.dstport" -e "dns.flags.response" -e "dns.id" \
            -e "dns.qry.name" -e "dns.qry.name.len" -e "dns.qry.type" \
            -e "dns.flags.rcode" -e "dns.flags.authoritative" \
            -e "dns.flags.recdesired" -e "dns.flags.recavail" \
            -e "dns.resp.type" -e "dns.resp.name" -e "dns.a" \
            -e "dns.ns" -e "dns.cname" -e "dns.ptr.domain_name" \
            -e "dns.mx.mail_exchange" -e "dns.txt" -e "dns.aaaa" \
            -e "dns.srv.name" -e "dns.srv.service" -e "dns.srv.port" \
            -e "dns.resp.ttl" -e "frame.number" -e "dns.response_to" \
            -e "dns.retransmission" -e "dns.retransmit_response_in" \
            2> /dev/null | awk -F'\t' '
                {
                    gsub(/,/, "[comma]")
                    gsub(" ", "[tab]")
                }

                {
                    for ( i = 1; i <= NF; i++ )
                    {
                        if ( $i == "" ) $i = "Null"
                    }

                    OFS="\t"; print
                }' > ./Results/${id_pcap_file}_${proto}.data; 
                pids+=("$!"); fi

    if [ "$proto" == "smb2" ]; then
        tshark -r ./Results/${data_dir}/Trims/$file -Y "smb2" -T fields -e \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" \
            -e "tcp.srcport" -e "tcp.dstport" -e "smb2.cmd" \
            -e "smb2.tree" -e "smb2.acct" -e "smb2.host" \
            2> /dev/null > ./Results/${id_pcap_file}_${proto}.data 
            pids+=("$!"); fi
}
 
function check_dependencies() 
{
 
    to_install=()
 
    for ((i = 0; i < ${#dependencies[@]}; i++)); 
    do
        remove=0
        dep="${dependencies[$i]}"
 
        if [[ "$i" -ge 4 &&
              "$i" -le 11 ]]; then
            if ! command -v $dep &> /dev/null; then
                remove=1
            else
                if [ "$i" -eq 4 ]; then
                    if ! $dep --v | grep -w '4.2.2' &> /dev/null; then
                        rm $(command -v $dep) && apt-get purge $dep
                        remove=1; fi
 
                elif [ "$i" -eq 10 ]; then
                    if ! $dep --v | grep -w 'v23.09' &> /dev/null; then
                        rm $(command -v $dep)
                        remove=1; fi; fi; fi
 
        elif [[ "$i" -ge 0 &&
                "$i" -le 3 ]]; then
            if ! command -v dpkg &> /dev/null; then
                remove=1
            else
                if ! dpkg -s $dep &> /dev/null; then
                    remove=1; fi; fi; fi
 
        if [ "$remove" -eq 1 ]; then
            to_install+=("$dep"); fi; done
}
 
function install_dependencies() 
{
 
    control=0
 
    for ((i = 0; i < ${#to_install[@]}; i++)); 
    do
        complete=0
        dep="${to_install[$i]}"
        echo -e "\n Installing '${dep}', wait a moment."
        sleep 3
 
        if [[ "$dep" != "PcapSplitter" && 
              "$dep" != "tshark" ]]; then
            if apt install -fy $dep &> /dev/null; then
                complete=1; fi
        else
            if [ "$dep" == "PcapSplitter" ]; then
                control_pcpp=0

                if git clone "https://github.com/seladb/PcapPlusPlus.git" \
                &> /dev/null; then
                    control_pcpp=$((control_pcpp + 1)); fi
 
                cd PcapPlusPlus && mkdir build
 
                if git checkout -b branch tags/v23.09 &> /dev/null; then
                    control_pcpp=$((control_pcpp + 1)); fi
 
                chmod +w build && cd build
 
                if cmake .. &> /dev/null; then
                    control_pcpp=$((control_pcpp + 1)); fi
 
                if make install &> /dev/null; then
                    control_pcpp=$((control_pcpp + 1)); fi
 
                if [ "$control_pcpp" -eq 4 ]; then
                    complete=1; fi
                    
            elif [ "$dep" == "tshark" ]; then
                if ! lsb_release -a | grep -w 'Ubuntu 24.04' &> /dev/null; then
                    control_tsh=0

                    if git clone "https://github.com/wireshark/wireshark.git" \
                    &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    cd wireshark && mkdir build

                    if git checkout -b branch tags/v4.2.2 &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    if DEBIAN_FRONTEND=noninteractive ./tools/debian-setup.sh --install-all \
                    &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    chmod +w build && cd build

                    if cmake .. &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    if make -j$(($(nproc)/2)) &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    if make install &> /dev/null; then
                        control_tsh=$((control_tsh + 1)); fi

                    if [ "$control_tsh" -eq 6 ]; then
                        complete=1; fi

                else
                    if apt install -fy $dep &> /dev/null; then
                        complete=1; fi; fi; fi; fi
 
        if [ "$complete" -eq 1 ]; then
            echo " ${g}[+] Instalation complete.${d}"
            control=$((control + 1))
        else
            instalation_error
            exit 1 && sleep 3; fi; done
}

function exiting() 
{
    eggs=(
        "And remember, packets don't lie. Humans do..."
        "Logging out. We hope the attackers do the same ;)"
        "Tool closed. At least it did something, right?"
        "Denisse is gone, but her name remains in the memory... of the system and the analyst <3."
        "The packets danced under a full moon..."
        "Beep. Boop. Threats taste like marshmallows."
    )

    egg=$(( (RANDOM % 6) + 0 ))
    echo -e "\n ${p}${eggs[$egg]}${d}\n" && sleep 3 && exit
}

function typewriter() 
{
    string="$1"
    for ((i = 0; i < ${#string}; i++)); do
        echo -ne "${2}${string:$i:1}${3}" && sleep 0.02; done 
}

function free_memory()
{

    mem_usage=$(free | awk '/Mem:/ { printf("%.0f"), $3/$2 * 100 }')

    while [ "$mem_usage" -ge "$1" ];
    do
        echo " RAM usage ${mem_usage} >= ${1}%, waiting 1s ...." >> .logs.log
        mem_usage=$(free | awk '/Mem:/ { printf("%.0f"), $3/$2 * 100 }')
        sleep 1
    done
}

function cleaning()
{

    echo -e "\n Interrupted process, exiting ..." | tee -a .logs.log
    p=1

    for ((i = 0; i < ${#pids[@]}; i++)); do
        process="${pids[$i]}"
        if kill -0 "$process" 2> /dev/null; then
            echo -en "\n [!] Killing process ${p} [${process}] ... " | tee -a .logs.log
            sleep 0.5; p=$((p + 1))
            if kill "$process" 2>> .logs.log; then
                echo "[OK]"
            else
                echo "[ERROR]"; fi
            sleep 1; fi; done

    if [ "$main_option" -eq 1 ]; then 
        ulimit -n $default_limit_files 1> /dev/null
        find ./Results/${data_dir}/Trims/ -type f ! -name '[0-9]*' -print0 | xargs -0 rm
        rm ./Results/*.data 2> /dev/null

    elif [ "$main_option" -eq 2 ]; then
        rm -r ./Results/$data_pcap_f/Data/ 2> /dev/null
        rm -r ./Results/$data_pcap_f/Trims/ 2> /dev/null; fi

    exit 130
}

function pcap_threat_detection()
{

    clear && td_banner
    echo -e "${c}\n [*] Menu Options\n${d}"
    echo -e " [1] Back To Main Menu."
    echo -e " [2] Show Help Panel"
    echo -e " [3] Exit."

    mapfile -t data_pcaps < <(ls -1 ./Results/ 2> /dev/null)
    mapfile -t user_rules < <(declare -F | awk '{print $3}' | grep '^rule_')
    mapfile -t predefined_rules < <(declare -F | awk '{print $3}' | grep '^pre_rule_')
    input_msg=" Please, Enter a command or a menu option: "
    hunt_msg=" Come on, man, where are you hiding? ...."

    declare -A data_pcap_dic
    declare -A rules_dic
    width=30

    for ((i = 0; i < 2; i++)); do
        count=1
        if [ "$i" -eq 0 ]; then
            options=("${data_pcaps[@]}")
            echo -e "${c}\n [*] Stored Pcaps Data\n${d}"
            option_id="P"
        else
            options=("${predefined_rules[@]}")
            echo -e "${c}\n [*] Rules\n${d}"
            option_id="R"; fi

        if [ "${#options[@]}" -gt 0 ]; 
        then
            for ((j = 0; j < ${#options[@]}; j++)); do
                [ "$i" -eq 1 ] && value_option=$(echo "${options[$j]}" | tr '_' ' ' | cut -d' ' -f3-) || value_option="${options[$j]}"
                printf " [%s%d] %-*s" "$option_id" "$count" "$width" "$value_option"
                [ "$i" -eq 0 ] && data_pcap_dic[P${count}]=$value_option || rules_dic[R${count}]="${options[$j]}"
                if (( count % 2 == 0 )); then
                    echo; fi
                    count=$((count + 1)); done
            
            if (( count % 2 != 1 )); then
                echo; fi
        else
            echo -e "${f} [!] No stored data found.${d}"; fi; done
            [ "${#user_rules[@]}" -gt 0 ] && echo -e " .... More Rules.\n" || echo -e "\n"

    if [ "${#user_rules[@]}" -gt 0 ]; 
    then
        for ((i = 0; i < ${#user_rules[@]}; i++)); do
            rule_name="${user_rules[$i]}"
            rules_dic[R${count}]=$rule_name
            count=$((count + 1)); done; fi

    while true; do 
        typewriter "$input_msg"
        read option
        case $option in 
            1) main ;;
            2) 
                echo -e "\n ${f}Usage: [ID Pcap Data];[ID's Rule];[Cores To Use]"
                echo -e "\n\t ID Pcap Data : Mandatory, specify only one"
                echo -e "\n\t ID's Rule : Mandatory, specify with commas, if you want to use all of them, specify '*'"
                echo -e "\n\t Cores To Use : Optional, system cores to use, by default they are half"
                echo -e "\n Examples:"
                echo -e "\n\t P2;R1,R4,R8;3"
                echo -e "\n\t P1;*;4"
                echo -e "\n\t P1;*${d}\n"
            ;;
            3) exiting ;;
            P[0-9]*\;*)

                n_proc=$(nproc)
                IFS=';' read -ra parts <<< "${option}"
                data_pcap_f="${data_pcap_dic[${parts[0]}]}"
                trap cleaning SIGINT SIGTSTP

                if [[ -n "$data_pcap_f" ]]; 
                then
                    if [[ -f "./Results/$data_pcap_f/Data.tar.zst" && 
                          -f "./Results/$data_pcap_f/Trims.tar.zst" ]]; then
                        error_r=0; begin=0
                        if [ "${parts[1]}" != "*" ]; then
                            IFS=',' read -ra input_rules <<< "${parts[1]}"
                            for ((i = 0; i < "${#input_rules[@]}"; i++)); do
                                input_rule="${input_rules[$i]}"
                                if [[ ! -n "${rules_dic[$input_rule]}" ]]; then
                                    error_r=$((error_r + 1)); fi ; done
                        else
                            for ((i = 0; i < $((count - 1)); i++)); do
                                input_rules+=("R$((i + 1))"); done ; fi
                    
                        if [[ "$error_r" -eq 0 ||
                              "${parts[1]}" == "*" ]]; then
                            begin=$((begin + 1))
                        else
                            input_rule_error; fi

                        if { [[ "${parts[2]}" =~ ^[0-9]+$ ]] && [ "${parts[2]}" -gt 0 ] && [ "${parts[2]}" -le "$n_proc" ]; } || [ "${parts[2]}" == "" ]; then
                            begin=$((begin + 1))
                        else
                            process_error "$n_proc"; fi

                        if [ "$begin" -eq 2 ]; then
                            echo -e "\n Preparing .... \n"
                            echo -e "\n [+] Data File selected ==> ${data_pcap_f}" >> .logs.log
                            echo -e "\n [+] Rules execution ==> [${input_rules[*]}]" >> .logs.log
                            id_detections_dir=1
                            detections_dir="Detections_${id_detections_dir}"

                            while [ -d "./Results/$data_pcap_f/$detections_dir" ]; do
                                id_detections_dir=$((id_detections_dir + 1))
                                detections_dir="Detections_${id_detections_dir}"; done

                            mkdir ./Results/$data_pcap_f/$detections_dir/
                            chmod -R a+rw ./Results/$data_pcap_f/$detections_dir/
                            tar -I zstd -xf ./Results/$data_pcap_f/Data.tar.zst -C ./Results/$data_pcap_f/
                            tar -I zstd -xf ./Results/$data_pcap_f/Trims.tar.zst -C ./Results/$data_pcap_f/
                            mapfile -t data_files < <(ls -1 ./Results/$data_pcap_f/Data/ 2> /dev/null)

                            typewriter "$hunt_msg" "$r" "$d" && echo -e "\n"
                            [ "${parts[2]}" == "" ] && max_proc=$(($(nproc)/2)) || max_proc="${parts[2]}"

                            for ((i = 0; i < "${#data_files[@]}"; i++)); do
                                data_file="${data_files[$i]}"
                                proto_data_file="${data_file#*_}"
                                proto_data_file="${proto_data_file%%.*}"
                                n_jobs=$(jobs -rp | wc -l)

                                for ((j = 0; j < "${#input_rules[@]}"; j++)); do
                                    in_rl="${input_rules[$j]}"
                                    rule_function="${rules_dic[$in_rl]}"

                                    if [[ "$rule_function" =~ ^rule_ ]]; then
                                        proto_rule=$(echo "$rule_function" | cut -d'_' -f2)

                                    elif [[ "$rule_function" =~ ^pre_rule_ ]]; then
                                        proto_rule=$(echo "$rule_function" | cut -d'_' -f3); fi

                                    if [ "$proto_data_file" == "$proto_rule" ]; 
                                    then
                                        while [ "$n_jobs" -ge "$max_proc" ]; do
                                            wait -n
                                            n_jobs=$(jobs -rp | wc -l); done

                                        $rule_function "$data_file" &
                                        fi ; done ; done

                            wait
                            rm -r ./Results/$data_pcap_f/Data/ 2> /dev/null
                            rm -r ./Results/$data_pcap_f/Trims/ 2> /dev/null; fi
                    else 
                        input_data_file_error_2; fi
                else
                    input_data_file_error_1; fi 
            ;;
            *) option_error ;; esac; done
}

function pcap_log_factory() 
{

    supported_protos=(
        "tcp"
        "udp"
        "http"
        "dns"
        "smb2"
        "rpc"    #encapsulated in smb2
        "dcerpc" #encapsulated in smb2
        "ntlm"   #encapsulated in smb2
        "kerberos"
        "ftp"
        "ssh"
        "llmnr"
        "tftp"
        "dhcp"
        "dhcpv6"
    )
    proto_filter=""

    for ((i = 0; i < ${#supported_protos[@]}; i++)); do
        s_p="${supported_protos[$i]}"
        if (( i == ${#supported_protos[@]} - 1 )); then
            proto_filter+="${s_p}"
        else
            proto_filter+="${s_p}|"; fi; done

    clear && lf_banner
    echo -e "${c}\n\n [*] Menu Options\n${d}"
    echo -e " [1] Back To Main Menu"
    echo -e " [2] Show Help Panel"
    echo -e " [3] Exit"

    mapfile -t pcaps < <(ls -1 ./Pcaps/*.pcap 2> /dev/null)
    input_msg=" Please, Enter a command or a menu option: "
    start=0
    echo -e "${c}\n [*] Stored Pcaps\n${d}"
    declare -A stored_pcaps
    width=30; count=1

    if [ "${#pcaps[@]}" -gt 0 ]; then
        for ((i = 0; i < ${#pcaps[@]}; i++)); do
            pcap_file="${pcaps[$i]}"
            printf " [%s%d] %-*s" "P" "$count" "$width" "$(basename $pcap_file)"
            stored_pcaps[P${count}]=$pcap_file
            if (( count % 2 == 0 )); then
                echo; fi
                count=$((count + 1)); done
        
        if (( count % 2 != 1 )); then
            echo; fi
    else
        echo -e "${f} [!] No stored pcaps found.${d}"; fi
        echo -e "\n"

    while true; do
        typewriter "$input_msg"
        read option
        case $option in 
            1) main ;;
            2) 
                echo -e "\n ${f}Usage: [ID Pcap File];[Protocols];[Cores To Use]"
                echo -e "\n\t ID Pcap File: Mandatory, specify only one"
                echo -e "\n\t Protocols : Mandatory, specify with commas, if you want to use all of them, specify '*'"
                echo -e "\n\t Cores To Use : Optional, system cores to use, by default they are half"
                echo -e "\n\t Supported protocols : [${supported_protos[*]}]"
                echo -e "\n Examples:"
                echo -e "\n\t P2;tcp,udp,http,dns;4"
                echo -e "\n\t P1;*;4"
                echo -e "\n\t P1;*${d}\n"
            ;;
            3) exiting ;;
            P[0-9]*\;*)

                n_proc=$(nproc)
                IFS=';' read -ra parts <<< "${option}"
                pcap_f="${stored_pcaps[${parts[0]}]}"
                trap cleaning SIGINT SIGTSTP

                if [[ -f "$pcap_f" ]]; then
                    error_p=0; begin=0
                    if [ "${parts[1]}" != "*" ]; then
                        IFS=',' read -ra in_protos <<< "${parts[1]}"
                        for ((i = 0; i < ${#in_protos[@]}; ++i)); do
                            proto_arg="${in_protos[$i]}"
                            for ((j = 0; j < ${#supported_protos[@]}; ++j)); do
                                supported_proto="${supported_protos[$j]}"
                                if [ "$proto_arg" == "$supported_proto" ]; then
                                    error_p=$((error_p + 1)); fi ; done ; done ; fi

                    if [[ "$error_p" -eq "${#in_protos[@]}" || 
                          "${parts[1]}" == "*" ]]; then
                        begin=$((begin + 1))
                    else
                        input_protocol_error "${supported_protos[@]}"; fi 

                    if { [[ "${parts[2]}" =~ ^[0-9]+$ ]] && [ "${parts[2]}" -gt 0 ] && [ "${parts[2]}" -le "$n_proc" ]; } || [ "${parts[2]}" == "" ]; then
                        begin=$((begin + 1))
                    else
                        process_error "$n_proc"; fi

                    if [ "$begin" -eq 2 ]; then
                        echo -e "\n [+] Pcap selected ==> ${pcap_f}" >> .logs.log
                        id_data_dir=1
                        data_dir=${pcap_f##*/}_${id_data_dir}

                        while [ -d "./Results/${data_dir}" ]; do
                            id_data_dir=$((id_data_dir + 1))
                            data_dir=${pcap_f##*/}_${id_data_dir}; done

                        mkdir -p "./Results/${data_dir}"/{Data,Trims}
                        chmod -R a+rw "./Results/${data_dir}"
                        echo -e "\n [+] Trimming pcap ...."
                        PcapSplitter -f $pcap_f -o ./Results/${data_dir}/Trims -m connection 1>> .logs.log

                        [ "${parts[2]}" == "" ] && max_proc=$(($(nproc)/2)) || max_proc="${parts[2]}"

                        predefined_proc=$(($(nproc)/2))
                        limit=0

                        hard_limit_files=$(ulimit -Hn)
                        default_limit_files=$(ulimit -n)
                        new_limit_files=$((default_limit_files * predefined_proc))

                        if [ "$new_limit_files" -le "$hard_limit_files" ]; then
                            ulimit -n $new_limit_files
                        else
                            limit=1
                            limit_error; fi

                        if [ "$limit" -eq 0 ]; then 
                            n_pcaps=$(find ./Results/${data_dir}/Trims -type f | wc -l)
                            echo -e "\n [+] Pcap cut to ${n_pcaps} sessions" >> .logs.log
                            trims=()

                            if [ "$n_pcaps" -gt 1000 ]; 
                            then
                                n_process=0
                                pids=()
                                counter=0
                                for pcap in $(ls ./Results/${data_dir}/Trims); do
                                    trims+=("./Results/${data_dir}/Trims/${pcap}")
                                    counter=$((counter + 1))
                                    if [ "$counter" -eq 1000 ]; then
                                        free_memory 40

                                        if [ "$n_process" -ge "$predefined_proc" ]; then
                                            #Limit reached, waiting turn...
                                            wait -n 
                                            n_process=$((n_process - 1)); fi

                                        mergecap -w ./Results/${data_dir}/Trims/$RANDOM.pcap "${trims[@]}" \
                                        2>> .logs.log &
                                        pids+=("$!")
                                        n_process=$((n_process + 1))
                                        trims=()
                                        counter=0; fi  ; done

                                mergecap -w ./Results/${data_dir}/Trims/$RANDOM.pcap "${trims[@]}" \
                                2>> .logs.log
                            else
                                mergecap -w ./Results/${data_dir}/Trims/$RANDOM.pcap ./Results/${data_dir}/Trims/* \
                                2>> .logs.log ; fi

                            wait
                            ulimit -n $default_limit_files 
                            find ./Results/${data_dir}/Trims/ -type f ! -name '[0-9]*' -print0 | xargs -0 rm
                            mapfile -t t_pcaps < <(ls -1 ./Results/${data_dir}/Trims/ 2> /dev/null)
                            echo -e "\n [+] Sessions joined in [${t_pcaps[*]}]" >> .logs.log
                            echo -e "\n [+] Flows to analyze ==> ${#t_pcaps[@]} \n" | tee -a .logs.log
                            flow_id=0
                            id_db=1
                            file_db="${pcap_f##*/}_${id_db}.db"

                            while [ -e "./Databases/${file_db}" ]; do
                                id_db=$((id_db + 1))
                                file_db="${pcap_f##*/}_${id_db}.db"; done

                            declare -A t_protos
                            pids=()

                            for ((i = 0; i < ${#t_pcaps[@]}; i++)); do
                                pcap_file="${t_pcaps[$i]}"
                                free_memory 40
                                n_jobs=$(jobs -rp | wc -l)

                                while [ "$n_jobs" -ge "$max_proc" ]; do
                                    #Limit reached, waiting turn...
                                    wait -n
                                    n_jobs=$(jobs -rp | wc -l); done

                                {
                                    protos=$(tshark -r "./Results/${data_dir}/Trims/${pcap_file}" -T fields -e "frame.protocols" \
                                    2> /dev/null | tr ':' '\n' | sort -u | grep -wE "${proto_filter}" | paste -sd',' -)
                                    echo "${pcap_file}|${protos}" > ./Results/${data_dir}/Trims/${pcap_file}.proto
                                } &

                                pids+=("$!") ; done 

                            wait
                            mapfile -t t_files_p < <(ls -1 ./Results/${data_dir}/Trims/*.proto 2> /dev/null)
                            data_msg=" Gutting pcap, this may take a few minutes."
                            typewriter "$data_msg" "$y" "$d" && echo -e "\n"

                            for ((i = 0; i < ${#t_files_p[@]}; i++)); do
                                t_file_p="${t_files_p[$i]}"
                                IFS="|" read -r pcap protos < "$t_file_p"
                                IFS="," read -ra protocols <<< "$protos"
                                found_p=""

                                for ((j = 0; j < ${#protocols[@]}; j++)); do
                                    protocol="${protocols[$j]}"
                                    if [ "${parts[1]}" != "*" ]; then
                                        for ((k = 0; k < ${#in_protos[@]}; k++)); do
                                            in_proto="${in_protos[$k]}"
                                            if [ "$protocol" == "$in_proto" ]; then
                                                found_p+="$protocol,"; fi ; done
                                    else
                                        found_p+="$protocol,"; fi ; done

                                found_p="${found_p%,}"
                                t_protos[$pcap]="$found_p"
                                rm $t_file_p; done

                            pids=()

                            for file in "${!t_protos[@]}"; 
                            do
                                IFS=',' read -ra protocols <<< "${t_protos[$file]}"
                                id_pcap_file=$(echo "$file" | sed 's/\.pcap$//')
                                flow_id=$((flow_id + 1))
                                free_memory 40
                                n_jobs=$(jobs -rp | wc -l)

                                while [ "$n_jobs" -ge "$max_proc" ]; do
                                    #Limit reached, waiting turn...
                                    wait -n
                                    n_jobs=$(jobs -rp | wc -l); done

                                echo -e "${c} [+]${d} Extracting and parsing data - flow ${flow_id} [${file}]\n" | \
                                tee -a .logs.log
                                echo -e " Protocols found ==> ${g}[${protocols[*]}]${d}\n"

                                {
                                    for ((i = 0; i < ${#protocols[@]}; i++)); do
                                        proto="${protocols[$i]}"
                                        pcap_ripper; done

                                    mapfile -t raw_data < <(ls -1 ./Results/${id_pcap_file}_*.data 2> /dev/null)

                                    for ((i = 0; i < ${#raw_data[@]}; i++)); do
                                        data=$(basename "${raw_data[$i]}")
                                        type=""
                                        if [ -s "./Results/$data" ]; then
                                            case $data in
                                                *_tcp.*) type="tcp"; tcp_parser; pids+=("$!") ;;
                                                *_udp.*) type="udp"; udp_parser; pids+=("$!") ;;
                                                *_dns.*) type="dns"; dns_parser; pids+=("$!") ;;
                                                *_http.*) type="http"; http_parser; pids+=("$!") ;;
                                                *_ssh.*) type="ssh"; ssh_parser; pids+=("$!") ;;
                                                *_smb2.*) type="smb2"; smb2_parser; pids+=("$!") ;;
                                                *_kerberos.*) type="kerberos"; kerberos_parser; pids+=("$!") ;;
                                                *_ftp.*) type="ftp"; ftp_parser; pids+=("$!") ;;
                                                *_rpc.*) type="rpc"; rpc_parser; pids+=("$!") ;;
                                                *_ntlm.*) type="ntlm"; ntlm_parser; pids+=("$!") ;; esac

                                                {
                                                    flock -x 9
                                                    import_data "$flow_id" "$file_db" "$type" "$id_pcap_file" "$data_dir"
                                                } 9>./Databases/"$file_db".lock

                                        fi ; done
                                        rm ./Results/${id_pcap_file}_*.data
                                } &

                                pids+=("$!"); done

                                wait
                                echo -e "${f} [+] Ending... ${d}"

                                tar -cf - -C ./Results/${data_dir} Trims | \
                                zstd -T$(( $(nproc) / 2)) -o ./Results/${data_dir}/Trims.tar.zst \
                                >> .logs.log 2>&1 && rm -rf ./Results/${data_dir}/Trims

                                tar -cf - -C ./Results/${data_dir} Data | \
                                zstd -T$(( $(nproc) / 2)) -o ./Results/${data_dir}/Data.tar.zst \
                                >> .logs.log 2>&1 && rm -rf ./Results/${data_dir}/Data

                                echo -e "\n${g} [+] Complete! ${d}\n"
                                #find ./Pcaps/Trims/ -type f -print0 | xargs -0 rm
                        fi ; fi
                else
                    input_pcap_error; fi 
                ;;
            *) option_error ;; esac; done
}

function main() 
{

    clear && main_banner
    echo -e "${c}\n [*] Menu Options\n${d}"
    echo -e " [1] Enter to PCAP Log Factory"
    echo -e " [2] Enter to PCAP Threat Detection"
    echo -e " [3] Enter to Hunting Center"
    echo -e " [4] Exit \n"

    input_msg=" Please, enter a menu option: "
    enter=0

    while true; do
        typewriter "$input_msg" "$d" "$d"
        read option
        main_option=$option
        case $option in
            1) pcap_log_factory ;;
            2) pcap_threat_detection ;;
            3) hunting_center ;;
            4) exiting ;;
            *) option_error ;; esac; done
}
 
if [ "$(id -u)" == "0" ]; then
    echo -e "\n Loading ... \n" && sleep 2
    check_dependencies
    echo -e "\n$(

        for ((i = 0; i <= 100; ++i)); do 
            echo -n "/"; done
            echo -e "\n\n $(date) \n"

        for ((i = 0; i <= 100; ++i)); do 
            echo -n "/"; done

    )\n" >> .logs.log

    chmod a+rw ./Results/ && chmod -R a+rw ./Pcaps/ && chmod a+rw ./Databases/

    if [ "${#to_install[@]}" -gt 0 ]; then
        echo -e "\n [*] Checking necessary dependencies.... \n"
        sleep 1.5 && echo -e " [${to_install[*]}]" && sleep 3
        install_dependencies
        if [ "$control" -eq "${#to_install[@]}" ]; then
            main; fi
    else
        main; fi
else
    root_error
    exit 3; fi
