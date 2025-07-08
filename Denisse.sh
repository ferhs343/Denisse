#!/bin/bash

# 'The Denisse's Project' v.1.0.0
# By: Luis Fernando Herrera - luis.herrera@scitum.com.mx

source Errors.sh
source Alerts.sh
source Json_Logs.sh
source DB_Tables.sh

red="\e[0;31m\033[1m"
default="\033[0m\e[0m"
yellow="\e[0;33m\033[1m"

dependencies=(
    "tshark"
    "cmake"
    "g++"
    "dpkg"
    "git"
    "sqlite3"
    "libpcap-dev"
    "build-essential"
    "libssl-dev"
    "libboost-all-dev"
    "PcapPlusPlus"
)

arg1=$1
arg2=$2

function show_help() {

    echo -e "\n 'The Denisse's Project' v.1.0.0"
    echo -e "\n Usage: ./Denisse.sh [OPTION] \n"
    echo -e "\n [OPTIONS]"
    echo -e "\n     --help              |  -h : Show this panel."
    echo -e "\n     --all               |  -a : If you are not sure what protocols are in your PCAP, use this option."
    echo -e "\n     --protocols         |  -p : Analyze certain protocols, specify with commas."
    echo -e "\n\n Supported protocols:"
    echo -e "\n [tcp,udp,http,dns,smb2,rpc,dcerpc,ntlm,kerberos,ftp,ssh,llmnr,tftp,dhcp,dhcpv6]"
    echo -e "\n\n Ussage examples:"
    echo -e "\n ./Denisse.sh -a"
    echo -e "\n ./Denisse.sh -p tcp,smb2,dns,kerberos,......\n"
}

function banner() {

    echo ""
    echo "                  /^----^\          Whoo!!"
    echo "                  | 0  0 |     "
    echo "    Whoo!!        |  \/  |       Whoo!!"
    echo "                  /       \ "
    echo "      Whoo!!     |     |;;;| "
    echo "                 |     |;;;|          \   \ "
    echo "                 |      \;;|           \\// "
    echo "                  \       \|           / / "
    echo " +-----------------(((--(((------------\ \--------------------------------+"
    echo " |                                                                        |"
    echo " |  'The Denisse's Project' V.1.0.0                                       |"
    echo " |   By Luis F. Herrera - luis.herrera@scitum.com.mx                      |"
    echo " |                                                                        |"
    echo " |   Welcome to 'The Denisse's Project', your traffic analyst hunting     |"
    echo " |   for anomalies where others don't look.                               |"
    echo " |                                                                        |"
    echo " |   Happy Hunting!! :D                                                   |"
    echo " |                                                                        |"
    echo " +------------------------------------------------------------------------+"
}

function pcap_ripper() {

    if [ "$proto" == "tcp" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "tcp" -T fields \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "tcp.flags" \
            -e "tcp.len" -e "tcp.srcport" -e "tcp.dstport" -e "data"\
            2> /dev/null > ./Results/$proto.data; fi

    if [ "$proto" == "udp" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "udp && not icmp" -T fields \
            -e "udp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "udp.length" \
            -e "udp.srcport" -e "udp.dstport" -e "data" \
            2> /dev/null > ./Results/$proto.data

        tshark -r ./Pcaps/Trims/$pcap_file -Y "icmp" -T fields \
            -e "udp.stream" -e "ip.src" -e "ip.dst" \
            -e "udp.srcport" -e "udp.dstport" -e "icmp.type" \
            -e "icmp.code" 2> /dev/null > ./Results/tr_icmp_udp.data; fi

    if [ "$proto" == "http" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "http" -T fields \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" -e "tcp.srcport" \
            -e "tcp.dstport" -e "http.request.method" \
            -e "http.request.full_uri" -e "http.user_agent" \
            -e "http.referer" -e "http.content_type" \
            -e "http.content_length" -e "http.response.code" \
            -e "http.file_data" -e "mime_multipart.header.content-type" \
            -e "mime_multipart.header.content-disposition" \
            -e "http.request_in" -e "frame.number" 2> /dev/null | \
            tr ',' ';' | tr ' ' ':'| awk -F'\t' '
                {
                    for ( i = 1; i <= NF; i++ )
                    {
                        if ( $i == "" ) $i = "Null"
                    }

                    OFS="\t"; print
                }' > ./Results/$proto.data;  fi

    if [ "$proto" == "dns" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "dns" -T fields \
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
            2> /dev/null | tr ',' ';' | awk -F'\t' '
                {
                    for ( i = 1; i <= NF; i++ )
                    {
                        if ( $i == "" ) $i = "Null"
                    }

                    OFS="\t"; print
                }' > ./Results/$proto.data; fi

    if [ "$proto" == "smb2" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "smb2" -T fields -e \
            -e "tcp.stream" -e "frame.time_epoch" -e "ip.src" \
            -e "ip.dst" -e "ipv6.src" -e "ipv6.dst" \
            -e "tcp.srcport" -e "tcp.dstport" -e "smb2.cmd" \
            -e "smb2.tree" -e "smb2.acct" -e "smb2.host" \
            2> /dev/null > ./Results/$proto.data; fi
}

function LocToLoc_regex() {

    awk '($3 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/ && $4 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/)' \
    ./Results/$filename 2> /dev/null > ./Results/$filename.tmp
}

function PubToLoc_regex() {

    awk '($3 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/' \
    ./Results/$filename 2> /dev/null > ./Results/$filename.tmp
}

function check_dependencies() {

    to_install=()
    for ((i = 0; i <= ${#dependencies[@]} - 1; i++)); do
        remove=0
        dep="${dependencies[$i]}"

        if [[ "$i" -ge 0 &&
              "$i" -le 5 ]]; then
            if ! command -v $dep &> /dev/null; then
                remove=1; fi

        elif [[ "$i" -ge 6 &&
                "$i" -le 9 ]]; then
            if ! command -v dpkg &> /dev/null; then
                remove=1
            else
                if ! dpkg -s $dep &> /dev/null; then
                    remove=1; fi; fi

        elif [ "$i" -eq 10 ]; then
            if ! ls /usr/local/include/ | grep -i "${dep}" \
                &> /dev/null; then
                remove=1; fi; fi

        if [ "$remove" -eq 1 ]; then
            to_install+=("$dep"); fi; done
}

function install_dependencies() {

    control=0

    for ((i = 0; i <= ${#to_install[@]} - 1; i++)); do
        complete=0
        dep="${to_install[$i]}"
        echo -e "\n Installing '${dep}', wait a moment."
        sleep 3

        if [ "$dep" != "PcapPlusPlus" ]; then
            if apt install -fy $dep &> /dev/null; then
                complete=1; fi
        else
            control2=0
            if git clone "https://github.com/seladb/${dep}.git" \
                &> /dev/null; then
                control2=$((control2 + 1)); fi

            cd PcapPlusPlus && mkdir build && chmod +w build && cd build \
            >/dev/null 2>&1

            if cmake .. &> /dev/null; then
                control2=$((control2 + 1)); fi

            if make install &> /dev/null; then
                control2=$((control2 + 1)); fi

            if [ "$control2" -eq 3 ]; then
                complete=1; fi; fi

        if [ "$complete" -eq 1 ]; then
            echo " [+] Instalation complete."
            control=$((control + 1))
        else
            instalation_error
            exit 1 && sleep 3; fi; done
}

function private_and_public() {

    conn_status=($(awk '{print $NF}' ./Results/$filename.tmp | sort -u))
    src=()
    dst=()

    echo -e "\n [+] TCP/UDP Connection Status ==> [${conn_status[*]}]" >> .logs.log

    for ((l = 0; l <= ${#conn_status[@]} - 1; l++)); do
        status="${conn_status[$l]}"
        if [[ ("$filename" == tcp_* && ("$status" != "NPI" &&
               "$status" != "Finished-payload" &&
               "$status" != "Reseted-payload")) ||
              ("$filename" == udp_* && ("$status" == "Established")) 
            ]]; then
            src=($(
                awk -v status="$status" '$NF == status {print $3}' \
                    ./Results/$filename.tmp | sort | uniq -c | sort -rn |
                    awk '$1 > 2 {print $2}'
            ))
            for ((m = 0; m <= ${#src[@]} - 1; m++)); do
                src_ip="${src[$m]}"
                dst=($(
                    awk -v status="$status" \
                        -v src_ip="$src_ip" \
                        '$NF == status && $3 == src_ip {print $4}' \
                        ./Results/$filename.tmp | sort -u
                ))
                #case 1 : 1 ==> 1
                if [ ${#dst[@]} -eq 1 ]; then
                    dst_ip="${dst[0]}"
                    n_ports=$(
                        awk -v status="$status" \
                            -v src_ip="$src_ip" \
                            -v dst_ip="$dst_ip" \
                            '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                            ./Results/$filename.tmp | sort -u | wc -l
                    )

                    echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

                    if [ "$n_ports" -gt 10 ]; then
                        vertical_scan=1
                        if [[ "$filename" == tcp_* ]]; then tcp=1; else udp=1; fi
                        alert="${src_type} ${VPS}"
                        generate_results_tcp "$dst_ip"; fi
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
                                ./Results/$filename.tmp | sort -u | wc -l
                        )

                        echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

                        if [ "$n_ports" -gt 10 ]; then
                            vertical_scan=1
                            if [[ "$filename" == tcp_* ]]; then tcp=1; else udp=1; fi
                            alert="${src_type} ${VPS}"
                            generate_results_tcp "$dst_ip"
                        else
                            ports=$(
                                awk -v status="$status" \
                                    -v src_ip="$src_ip" \
                                    -v dst_ip="$dst_ip" \
                                    '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                                    ./Results/$filename.tmp | sort -u
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
                        if [[ "$filename" == tcp_* ]]; then tcp=1; else udp=1; fi
                        alert="${src_type} ${HPS}"
                        generate_results_tcp "${multiple_dst[@]}"; fi
                        fi; done; fi; done
}

function tcp_data_analysis() {

    sessions=()
    alert=""
    src_type=""
    vertical_scan=0
    horizontal_scan=0
    it=0
    
    while (( it++ < 2 )); do
        if (( it == 1 )); then
            LocToLoc_regex
            src_type="Internal"
        else
            PubToLoc_regex
            src_type="External"; fi 
            private_and_public; done

    #echo "yaaaaaaaaaaaaa" && sleep 3
}

function tcp_parser() {

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

                print fields[1], fields[2], fields[3], fields[4], fields[7], 
                fields[8], flags_list[s], total_pkts[s]+0, src_pkts[s]+0, 
                dst_pkts[s]+0, total_size[s]+0, src_size[s]+0, dst_size[s]+0, 
                duration, payloads[s], status
            }
        }' ./Results/"$data" > "./Results/${type}_${id_pcap_file}.parsed"
}

function udp_data_analysis() {

    #echo "udp" && sleep 5
    it=0
    while (( it++ < 2 )); do
        if (( it == 1 )); then
            LocToLoc_regex
            src_type="Internal"
        else
            PubToLoc_regex
            src_type="External"; fi
            private_and_public; done
}

function udp_parser() {

    if [ -s "./Results/tr_icmp_udp.data" ]; then
        tr ',' ' ' < ./Results/tr_icmp_udp.data | \
        awk '{print $1 " " $3 " " $5 " " $6 " " $7 " " $8 " " $9}' \
        2> /dev/null > ./Results/tr_icmp_udp1.data
    else
        echo "0 0.0.0.0 0.0.0.0 1 1 3 3" > ./Results/tr_icmp_udp1.data; fi

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
    ' ./Results/tr_icmp_udp1.data ./Results/$data > ./Results/sample.data

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

                print session_id[k], timestamp[k], src_ip[k], dst_ip[k], 
                src_port[k], dst_port[k], total_pkts[k]+0, src_pkts[k]+0, 
                dst_pkts[k]+0, total_size[k]+0, src_size[k]+0, dst_size[k]+0, 
                icmp_type_out, icmp_code_out, duration, payloads[k], status
            }
        }
    ' ./Results/sample.data > "./Results/${type}_${id_pcap_file}.parsed"
}

function http_parser() {

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
                    print session_id[k], timestamp[k],
                    src_ip[k], dst_ip[k], src_port[k],
                    dst_port[k], method[k], full_uri[k],
                    user_agent[k], referer[k], req_content_type[k],
                    req_content_length[k], req_file_type[k]+0,
                    req_file_data[k], mime_content_type[k], 
                    form_filenames[k], form_files_type[k], 
                    form_files_data[k], response_code[k], 
                    resp_content_type[k], resp_content_length[k]+0, 
                    resp_file_type[k], resp_file_data[k], "Matched"
                }

                if ( !( k in resp_seen ) )
                {
                    print session_id[k], timestamp[k],
                    src_ip[k], dst_ip[k], src_port[k],
                    dst_port[k], method[k], full_uri[k],
                    user_agent[k], referer[k], req_content_type[k],
                    req_content_length[k]+0, req_file_type[k],
                    req_file_data[k], mime_content_type[k], 
                    form_filenames[k], form_files_type[k], 
                    form_files_data[k], "0", "Null", "0",
                    "Null", "Null", "Only-Request"
                }
            }

            for ( k in resp_seen )
            {
                if ( !( k in req_seen ) )
                {
                    print $1, $2, dst, src, $8, $7,
                    "Null", "Null", "Null", "Null",
                    "Null", "0", "Null", "Null",
                    "Null", "Null", "Null", "Null",
                    response_code[k], resp_content_type[k], 
                    resp_content_length[k]+0, resp_file_type[k], 
                    resp_file_data[k], "Only-Response"
                }
            }
        }
        ' ./Results/"$data" > "./Results/${type}_${id_pcap_file}.parsed"
}

function dns_parser() {

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

            if ( $9 == "False" || $9 == 0 )
            {
                aux = $(NF - 3)
            }
            else if ( $9 == "True" || $9 == 1 )
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

                    print session_id[k],
                    timestamp[k],
                    src_ip[k], dst_ip[k], 
                    src_port[k], dst_port[k],
                    trans_id[k], domain[k], 
                    domain_lenght[k], rtype_code[k], 
                    rtype_string[k], count_n[k]+0,
                    rptype_code[k], rptype_string[k],
                    rp_type_codes[k], rp_type_strings[k],
                    is_authoritative[k], is_recdesired[k],
                    is_recavail[k], resp_names[k],
                    answers[k], ttl[k], add_info
                }

                if ( !( k in resp_seen ) )
                {
                    print session_id[k], 
                    timestamp[k],
                    src_ip[k], dst_ip[k], 
                    src_port[k], dst_port[k],
                    trans_id[k], domain[k], 
                    domain_lenght[k], rtype_code[k], 
                    rtype_string[k], count_n[k]+0,
                    "Null", "Null", "Null", "Null",
                    "Null", "Null", "Null",
                    "Null", "Null", "Null", "Only-Query"
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
                    print $1, $2, dst, src,
                    $8, $7, $10, $11, $12, $13,
                    request_type($13), "1",
                    rptype_code[k], rptype_string[k],
                    rp_type_codes[k], rp_type_strings[k],
                    is_authoritative[k], is_recdesired[k],
                    is_recavail[k], resp_names[k],
                    answers[k], ttl[k], "Only-Answer"
                }
            }
        }' ./Results/"$data" > "./Results/${type}_${id_pcap_file}.parsed"
}

function generate_results_tcp() {

    if [ "$horizontal_scan" -eq 1 ]; then
        filter_dst=""
        input=("$@")

        for ((p = 0; p <= ${#input[@]} - 1; p++)); do
            dst="${input[$p]}"
            if (( p == ${#input[@]} - 1 )); then
                filter_dst+="$dst"
            else
                filter_dst+="$dst|"; fi; done

        sessions=($(
            awk -v status="$status" \
                -v ip_src="$src_ip" \
                -v pattern="^($filter_dst)$" \
                '$NF == status && $3 == ip_src && $4 ~ pattern {print $1}' \
                ./Results/$filename.tmp
        ))
    else
        sessions=($(
            awk -v status="$status" \
                -v ip_src="$src_ip" \
                -v ip_dst="$1" \
                '$NF == status && $3 == ip_src && $4 == ip_dst {print $1}' \
                ./Results/$filename.tmp
        )); fi

    filter_pcap=""
    filter_json=""
    for ((p = 0; p <= ${#sessions[@]} - 1; p++)); do
        stream="${sessions[$p]}"
        if (( p == ${#sessions[@]} - 1 )); then
            if [[ "$filename" == tcp_* ]]; then
                filter_pcap+="tcp.stream eq $stream"
            else
                filter_pcap+="udp.stream eq $stream"; fi

            filter_json+="$stream"
        else
            if [[ "$filename" == tcp_* ]]; then
                filter_pcap+="tcp.stream eq $stream or "
            else
                filter_pcap+="udp.stream eq $stream or "; fi

            filter_json+="$stream|"; fi; done

    output_pcap="ALERT_INFO_${id_result}.pcap"
    output_json="ALERT_INFO_${type}_${id_result}_.json"
    awk -v pattern="^($filter_json)$" '$1 ~ pattern' ./Results/$filename \
    > ./Results/.result_logs.data
    generate_json_logs

    tshark -r "./Pcaps/Trims/${flow_data}.pcap" -Y "${filter_pcap}" \
    -w "./Results/${output_pcap}" 2> /dev/null

    echo -e "\n ${red}[!]${default} [$alert] ==> [$output_pcap] [$output_json]" | \
    tee -a .logs.log
    id_result=$((id_result + 1))
}

function generate_json_logs() {

    if [ "$tcp" -eq 1 ]; then
        tcp_json_logs "$output_json"; fi

    if [ "$udp" -eq 1 ]; then
        udp_json_logs "$output_json"; fi
}

function parse_pcap_data() {

    type=""
    mapfile -t data_file < <(ls -1 ./Results/*.data 2> /dev/null)

    for ((k = 0; k <= ${#data_file[@]} - 1; ++k)); do
        data=$(basename "${data_file[$k]}")
        if [ -s "./Results/$data" ]; then
            if [ "$data" == "tcp.data" ]; then
                type="tcp"
                tcp_parser
            elif [ "$data" == "udp.data" ]; then
                type="udp"
                udp_parser
            elif [ "$data" == "dns.data" ]; then
                type="dns"
                dns_parser
            elif [ "$data" == "http.data" ]; then
                type="http"
                http_parser
            elif [ "$data" == "ssh.data" ]; then
                type="ssh"
                #ssh_parser
            elif [ "$data" == "smb2.data" ]; then
                type="smb2"
                #smb2_parser
            elif [ "$data" == "kerberos.data" ]; then
                type="kerberos"
                #kerberos_parser
            elif [ "$data" == "ftp.data" ]; then
                type="ftp"
                #ftp_parser
            elif [ "$data" == "rpc.data" ]; then
                type="rpc"
                #rpc_parser
            elif [ "$data" == "dcerpc.data" ]; then
                type="dcerpc"
                #dcerpc_parser
            elif [ "$data" == "ntlm.data" ]; then
                type="ntlm"
                #ntlm_parser 
            fi
                import_data "$flow_id" "$file_db" "$type" "$id_pcap_file"; fi; done
}

function analyzer() {

    mapfile -t t_pcaps < <(ls -1 ./Pcaps/Trims/ | grep "^[0-9]" 2> /dev/null)
    echo -e "\n [+] Sessions joined in [${t_pcaps[*]}]" >> .logs.log
    echo -e "\n [+] Flows to analyze ==> ${#t_pcaps[@]} \n" | tee -a .logs.log

    id_result=1
    flow_id=0
    id_db=0
    file_db="Database_${id_db}.db"
    id_pcap_files=()

    tcp=0; udp=0; http=0; dns=0; smb2=0
    rpc=0; dcerpc=0; ntlm=0; kerberos=0
    ftp=0; ssh=0; llmnr=0

    while [ -e "./Databases/${file_db}" ]; do
        id_db=$((id_db + 1))
        file_db="Database_${id_db}.db"; done

    data_msg="Gutting pcap, this may take a few minutes."
    echo -e -n "\n ${yellow}[+] "

    for ((i = 0; i <= ${#data_msg} - 1; i++)); do
        echo -n "${data_msg:$i:1}" && sleep 0.02; done 
        echo -e "${default}\n"

    for ((i = 0; i <= ${#t_pcaps[@]} - 1; i++)); do
        pcap_file="${t_pcaps[$i]}"
        id_pcap_file=$(echo "$pcap_file" | sed 's/\.pcap$//')
        id_pcap_files+=("$id_pcap_file")
        flow_id=$i
        echo -e "\n ${yellow}[+]${default} Extracting and parsing data - flow ${flow_id} [${pcap_file}]" | \
        tee -a .logs.log
        for ((j = 0; j <= ${#protos[@]} - 1; j++)); do
            proto="${protos[$j]}"
            pcap_ripper; done
            parse_pcap_data
            rm ./Results/*.data; done

    hunt_msg="Hunting hidden enemy...."
    echo -e -n "\n\n ${red}[+] "

    for ((i = 0; i <= ${#hunt_msg} - 1; i++)); do
        echo -n "${hunt_msg:$i:1}" && sleep 0.02; done 
        echo -e "${default}\n"

    for ((i = 0; i <= ${#id_pcap_files[@]}; i++)); do 
        flow_data="${id_pcap_files[$i]}"
        for flow in ./Results/*_"$flow_data".parsed; do
            filename=$(basename $flow) 
            if [[ "$filename" == tcp_* ]]; then
                tcp_data_analysis
            elif [[ "$filename" == udp_* ]]; then
                udp_data_analysis; fi; done; done
}

function main() {

    clear && banner
    chmod a+rw ./Results/ && chmod -R a+rw ./Pcaps/ && chmod a+rw ./Databases/
    echo -e "\n [*] Stored pcaps: \n"

    echo -e "\n$(
        for ((i = 0; i <= 100; ++i)); do 
            echo -n "/"; done
            echo -e "\n\n $(date) \n"
        for ((i = 0; i <= 100; ++i)); do 
            echo -n "/"; done
    )\n" >> .logs.log

    mapfile -t pcaps < <(ls -1 ./Pcaps/*.pcap 2> /dev/null)
    input_msg=" Please, enter a pcap file to be analyzed: "

    if [ "${#pcaps[@]}" -ne 0 ]; then
        continue=0

        for ((i = 0; i <= ${#pcaps[@]} - 1; i++)); do
            pcap_file="${pcaps[$i]}"
            if (( i % 2 != 0 )); then
                echo " [$i] $(basename $pcap_file)"
            else
                echo -n " [$i] $(basename $pcap_file)"; fi; done

        while [ "$continue" -eq 0 ]; do
            echo -e " \n " 
            for ((i = 0; i <= ${#input_msg} - 1; i++)); do
                echo -n "${input_msg:$i:1}" && sleep 0.02; done 
                read pcap

            if [[ -f "./Pcaps/$pcap" ]]; then
                continue=1
                echo -e "\n [+] Pcap selected ==> ${pcap}" >> .logs.log
                echo -e "\n Loading..."
                mapfile -t found_p < <(tshark -r ./Pcaps/$pcap -T fields -e "frame.protocols" 2> /dev/null | \
                tr ':' '\n' | sort -u | grep -wE 'tcp|udp|http|dns|smb2|rpc|dcerpc|ntlm|kerberos|ftp|ssh|llmnr|tftp|dhcp|dhcpv6')

                if [ "$arg1" == "--protocols" ] ||
                   [ "$arg1" == "-p" ]; then

                    for ((i = 0; i <= ${#protos[@]} - 1; i++)); do
                        arg_proto="${protos[$i]}"
                        for ((j = 0; j <= ${#found_p[@]} - 1; j++)); do
                            proto_found="${found_p[$j]}"
                            if [ "$arg_proto" == "$proto_found" ]; then
                                protos_found+=($arg_proto); fi; done; done

                    protos=("${protos_found[@]}")
                            
                elif [ "$arg1" == "--all" ] ||
                     [ "$arg1" == "-a" ]; then
                    protos=("${found_p[@]}"); fi          
            else
                input_pcap_error; fi; done

        if [ "${#protos[@]}" -gt 0 ]; 
        then
            echo -e "\n\n [+] Protocols Found ==> [${protos[*]}]"
            echo -e "\n [+] Trimming pcap ...."
            if PcapSplitter -f ./Pcaps/$pcap -o ./Pcaps/Trims -m connection \
                /dev/null 2>&1 | grep 'ERROR'; then
                pcapplusplus_error
                find ./Pcaps/Trims/ -type f -print0 | xargs -0 rm; fi

            n_pcaps=$(ls ./Pcaps/Trims/ | wc -l)
            echo -e "\n [+] Pcap cut to ${n_pcaps} sessions" >> .logs.log
            trims=()

            if [ "$n_pcaps" -gt 1000 ]; then
                n_value=$(ulimit -n)
                n_value_round=$(echo $n_value | \
                awk '{print int($1 / 100) * 100}')
                counter=0
                for pcap in $(ls ./Pcaps/Trims/); do
                    trims+=("./Pcaps/Trims/$pcap")
                    counter=$((counter + 1))
                    if [ "$counter" -eq "$n_value_round" ]; then
                        mergecap -w ./Pcaps/Trims/$RANDOM.pcap "${trims[@]}" \
                        2> /dev/null
                        trims=()
                        counter=0; fi; done

                mergecap -w ./Pcaps/Trims/$RANDOM.pcap "${trims[@]}" \
                2> /dev/null
            else
                mergecap -w ./Pcaps/Trims/$RANDOM.pcap ./Pcaps/Trims/* \
                2> /dev/null; fi
                analyzer
        else
            protocols_error; fi
    else
        echo -e "${red} [!] No stored pcaps found.\n${default}" | \
        tee -a .logs.log
        exit 2; fi
}

function starting() {

    #protos=() #define array, to always keep it in memory when using IFS=
    no_error=0
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

    if [ "$arg1" == "--help" ] ||
       [ "$arg1" == "-h" ] ||
       [ "$arg1" == "" ]; then
        show_help
        exit 1

    elif [ "$arg1" == "--all" ] ||
         [ "$arg1" == "-a" ]; then
        protos=()
        no_error=1

    elif [ "$arg1" == "--protocols" ] ||
         [ "$arg1" == "-p" ]; then

        if [ "$arg2" == "" ]; then
            show_help && exit
        else
            IFS=',' read -ra protos <<< "$arg2"
            protos_found=()
            error=0

            for ((i = 0; i <= ${#protos[@]} - 1; ++i)); do
                proto_arg="${protos[$i]}"
                for ((j = 0; j <= ${#supported_protos[@]} - 1; ++j)); do
                    supported_proto="${supported_protos[$j]}"
                    if [ "$proto_arg" == "$supported_proto" ]; then
                        error=$((error + 1)); fi; done; done; fi

    else
        show_help && exit 1; fi

    if [[ "$no_error" -eq 1 ||
          "$error" -eq "${#protos[@]}" ]]; then
        main
    else
        input_protocol_error
        exit 1 && sleep 3; fi
}

if [ "$(id -u)" == "0" ]; then
    check_dependencies
    if [ "${#to_install[@]}" -gt 0 ]; then
        echo -e "\n [*] Checking necessary dependencies.... \n" 
        sleep 1.5 && echo -e " [${to_install[*]}]" && sleep 3 
        install_dependencies
        if [ "$control" -eq "${#to_install[@]}" ]; then
            starting; fi
    else
        starting; fi
else
    root_error
    exit 3; fi
