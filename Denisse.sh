#!/bin/bash

source Errors.sh
source Alerts.sh

dependencies=(
    "tshark"
    "mergecap"
    "cmake"
    "g++"
    "dpkg"
    "git"
    "libpcap-dev"
    "build-essential"
    "libssl-dev"
    "libboost-all-dev"
    "PcapPlusPlus"
)

arg1=$1
arg2=$2

function show_help() {

    echo -e "\n Denisse V.1.0.0"
    echo -e "\n Usage: ./Tool.sh [OPTION] \n"
    echo -e "\n [OPTIONS]"
    echo -e "\n     --help        |  -h : Show this panel."
    echo -e "\n     --all         |  -a : Analyze all supported protocols."
    echo -e "\n     --protocols   |  -p : Analyze certain protocols, specify with commas."
    echo -e "\n\n Supported protocols: [tcp,udp,http,dns,smb2,rpc,dcerpc,ntlm,kerberos,ftp,ssh]"
    echo -e "\n\n Ussage examples:"
    echo -e "\n ./Tool.sh -a"
    echo -e "\n ./Tool.sh -p tcp,smb2,dns,kerberos,...... \n"
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
    echo " |   Denisse V.1.0.0                                                      |"
    echo " |   By Luis F. Herrera - luis.herrera@scitum.com.mx                      |"
    echo " |                                                                        |"
    echo " |   Welcome to Denisse, your traffic analyst hunting for anomalies       |"
    echo " |   where others don't look.                                             |"
    echo " |                                                                        |"
    echo " |   Happy Hunting!! :D                                                   |"
    echo " |                                                                        |"
    echo " +------------------------------------------------------------------------+"
}

function extract_pcap_data() {

    if [ "$proto" == "tcp" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "tcp" -T fields \
            -e "tcp.stream" \
            -e "frame.time" \
            -e "ip.src" \
            -e "ip.dst" \
            -e "ipv6.src" \
            -e "ipv6.dst" \
            -e "tcp.flags" \
            -e "tcp.len" \
            -e "tcp.srcport" \
            -e "tcp.dstport" 2> /dev/null > ./Results/$proto.data; fi

    if [ "$proto" == "udp" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "udp" -T fields \
            -e "udp.stream" \
            -e "frame.time" \
            -e "ip.src" \
            -e "ip.dst" \
            -e "ipv6.src" \
            -e "ipv6.dst" \
            -e "udp.length" \
            -e "udp.srcport" \
            -e "udp.dstport" 2> /dev/null > ./Results/$proto.data; fi

    if [ "$proto" == "http" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "http" -T fields \
            -e "tcp.stream" \
            -e "frame.time" \
            -e "ip.src" \
            -e "ip.dst" \
            -e "ipv6.src" \
            -e "ipv6.dst" \
            -e "http.request.method" \
            -e "http.request.full_uri" \
            -e "http.content_type" \
            -e "http.content_length" \
            -e "http.user_agent" \
            -e "http.response.code" \
            -e "tcp.reassembled.data" \
            -e "http.file_data" 2> /dev/null > ./Results/$proto.data; fi

    if [ "$proto" == "dns" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "dns" -T fields \
            -e "udp.stream" \
            -e "frame.time" \
            -e "ip.src" \
            -e "ip.dst" \
            -e "ipv6.src" \
            -e "ipv6.dst" \
            -e "dns.qry.name" \
            -e "dns.flags" \
            -e "dns.qry.name.len" \
            -e "dns.resp.type" \
            -e "dns.resp.name" \
            -e "dns.a" \
            -e "dns.aaaa" \
            -e "dns.txt" 2> /dev/null > ./Results/$proto.data; fi

    if [ "$proto" == "smb2" ]; then
        tshark -r ./Pcaps/Trims/$pcap_file -Y "smb2" -T fields -e \
            -e "tcp.stream" \
            -e "frame.time" \
            -e "ip.src" \
            -e "ip.dst" \
            -e "ipv6.src" \
            -e "ipv6.dst" \
            -e "smb2.cmd" \
            -e "smb2.tree" \
            -e "smb2.acct" \
            -e "smb2.host" 2> /dev/null > ./Results/$proto.data; fi
}

function check_dependencies() {

  to_install=()
  for ((i=0;i<=${#dependencies[@]} - 1;i++)); do
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
          if ! ls /usr/local/include/ | grep -i "${dep}"  \
          &> /dev/null; then
              remove=1; fi; fi

    if [ "$remove" -eq 1 ]; then
            to_install+=("$dep"); fi; done 
}

function install_dependencies() {

  control=0

  for ((i=0;i<=${#to_install[@]} - 1;i++)); do
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
          control2=$((control2+1)); fi

        cd PcapPlusPlus && mkdir build && chmod +w build && cd build \
        > /dev/null 2>&1

        if cmake .. &> /dev/null; then
          control2=$((control2+1)); fi

        cd..
        if make install &> /dev/null; then
          control2=$((control2+1)); fi

        if [ "$control2" -eq 3 ]; then
          complete=1; fi; fi

    if [ "$complete" -eq 1 ]; then
        echo " [+] Instalation complete."
        control=$((control+1))
    else
        instalation_error
        exit 1 && sleep 3; fi; done
}

function private_and_public() {

  conn_status=($(awk '{print $NF}' ./Results/.sample1.data | sort -u))

  for ((l=0;l<=${#conn_status[@]} - 1;l++)); do
      status="${conn_status[$l]}"
      if [[ "$status" != "Unknown" &&
            "$status" != "Finished-payload" &&
            "$status" != "Reseted-payload" ]]; then
          src=($(
              awk -v status="$status" '$NF == status {print $3}' \
              ./Results/.sample1.data | sort | uniq -c | sort -rn | \
              awk '$1 > 2 {print $2}'
          ))
          for ((m=0;m<=${#src[@]} - 1;m++)); do
              src_ip="${src[$m]}"
              dst=($(
                  awk -v status="$status" \
                      -v src_ip="$src_ip" \
                      '$NF == status && $3 == src_ip {print $4}' \
                      ./Results/.sample1.data | sort -u
              ))
              #case 1 : 1 ==> 1
              if [ ${#dst[@]} -eq 1 ]; then
                  dst_ip="${dst[0]}"
                  n_ports=$(
                      awk -v status="$status" \
                          -v src_ip="$src_ip" \
                          -v dst_ip="$dst_ip" \
                          '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                          ./Results/.sample1.data | sort -u | wc -l
                  )
                  if [ "$n_ports" -gt 10 ]; then
                      vertical_scan=1; tcp=1
                      alert="${src_type} ${VPS}"
                      generate_results_tcp; fi
              else
                  c=0
                  #case 2 : 1 ==> N
                  for ((n=0;n<=${#dst[@]} - 1;n++)); do
                      dst_ip="${dst[$n]}"
                      n_ports=$(
                          awk -v status="$status" \
                              -v src_ip="$src_ip" \
                              -v dst_ip="$dst_ip" \
                              '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                              ./Results/.sample1.data | sort -u | wc -l
                      )
                      if [ "$n_ports" -gt 10 ]; then
                          vertical_scan=1; tcp=1
                          alert="${src_type} ${VPS}"
                          generate_results_tcp
                      else
                          ports=$(
                              awk -v status="$status" \
                                  -v src_ip="$src_ip" \
                                  -v dst_ip="$dst_ip" \
                                  '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                                  ./Results/.sample1.data | sort -u
                          )
                        if [ "$n" -ne 0 ]; then
                            if [ "$ports" == "$ports_copy" ]; then
                                c=$((c+1)); fi; fi

                        ports_copy="$ports"; fi; done
                        if [ "$c" -gt 0 ]; then
                            horizontal_scan=1; tcp=1
                            alert="${src_type} ${HPS}"
                            generate_results_tcp; fi; fi; done; fi; done
}

function tcp_hunt() {

  sessions=()
  alert=""
  src_type=""
  vertical_scan=0; horizontal_scan=0
  tcp=0; udp=0; http=0; dns=0; smb2=0
  rpc=0; dcerpc=0; ntlm=0; kerberos=0
  ftp=0; ssh=0
  
  tr ' ' '-' < ./Results/"$data" | awk '
    function flag_name(f) {
      if (f ~ /02$/) return "Syn"
      else if (f ~ /12$/) return "SynAck"
      else if (f ~ /10$/) return "Ack"
      else if (f ~ /04$/) return "Rst"
      else if (f ~ /14$/) return "RstAck"
      else if (f ~ /01$/) return "Fin"
      else if (f ~ /11$/) return "FinAck"
      else if (f ~ /00$/) return "Null"
      else if (f ~ /08$/) return "Push"
      else if (f ~ /18$/) return "PushAck"
      else if (f ~ /29$/) return "Xmas"
      return "Unknown"
    }

    function get_status(s) {
      has_syn = has_synack = has_ack = has_rst = has_rstack = has_fin = has_finack = has_null = has_push = has_pushack = has_xmas = 0
      split(flags_list[s], arr, " ")

      for (i in arr) {
        if (arr[i] == "Syn") has_syn = 1
        else if (arr[i] == "SynAck") has_synack = 1
        else if (arr[i] == "Ack") has_ack = 1
        else if (arr[i] == "Rst") has_rst = 1
        else if (arr[i] == "RstAck") has_rstack = 1
        else if (arr[i] == "Fin") has_fin = 1
        else if (arr[i] == "FinAck") has_finack = 1
        else if (arr[i] == "Null") has_null = 1
        else if (arr[i] == "Push") has_push = 1
        else if (arr[i] == "PushAck") has_pushack = 1
        else if (arr[i] == "Xmas") has_xmas = 1
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

      else return "Unknown"
    }

    {
      session = $1
      if (!(session in seen)) {
        seen[session] = $0
      }

      flag_key = session "|" $5
      if (!(flag_key in flag_seen)) {
        flag_seen[flag_key] = 1
        fname = flag_name($5)
        flags_list[session] = flags_list[session] " " fname
      }

      size[session] += $6
      pkts[session] ++
    }

    END {
      for (s in seen) {
        split(seen[s], fields)
        status = get_status(s)

        gsub(/^ +| +$/, "", flags_list[s])
        gsub(/ +/, ",", flags_list[s])

        print fields[1], fields[2], fields[3], fields[4], fields[7], fields[8], flags_list[s], pkts[s], size[s], status
      }
    }
  ' > ./Results/.sample.data

  for ((it=0;it<2;it++)); do
      if [ "$it" -eq 0 ]; then
          awk '($3 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/ && $4 ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/)' \
          ./Results/.sample.data 2> /dev/null > ./Results/.sample1.data
          src_type="Internal"
      else
          awk '($3 !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fd[0-9a-f]{2}:|fc[0-9a-f]{2}:)/' \
          ./Results/.sample.data 2> /dev/null > ./Results/.sample1.data
          src_type="External"; fi
          private_and_public; done
}

function udp_hunt() {

  echo ""
}

function generate_results_tcp() {

  if [[ "$vertical_scan" -eq 1 ||  
        "$horizontal_scan" -eq 1 ]]; then
      sessions=($(
          awk -v status="$status" \
              -v ip_src="$src_ip" \
              '$NF == status && $3 == ip_src {print $1}' \
              ./Results/.sample.data
      )); fi

  filter_pcap=""
  filter_json=""
  for ((p=0;p<=${#sessions[@]} - 1;p++)); do
      stream="${sessions[$p]}"
      if (( p ==  ${#sessions[@]} - 1 )); then
          filter_pcap+="tcp.stream eq $stream"
          filter_json+="$stream"
      else
          filter_pcap+="tcp.stream eq $stream or "
          filter_json+="$stream|"; fi; done

  output_pcap="ALERT_INFO_${id}_.pcap"
  output_json="ALERT_INFO_${type}_${id}_.json"
  awk -v pattern="^($filter_json)$" '$1 ~ pattern' ./Results/.sample.data \
  > ./Results/.sample2.data
  generate_json_logs

  tshark -r ./Pcaps/Trims/$pcap_file -Y "${filter_pcap}" \
  -w "./Results/${output_pcap}" 2> /dev/null

  echo -e "\n\t [!] [$alert] ==> [$output_pcap] [${json_logs[*]}]" | \
  tee -a .logs.log
  id=$((id+1))
}

function generate_json_logs() {

  json_logs=()
  if [ "$tcp" -eq 1 ]; then
    type="tcp"
    
      awk '{
          json = "{"
          json = json " \"sessionId\": " $1
          json = json ", \"timestamp\": \"" $2 "\""
          json = json ", \"sourceIp\": \"" $3 "\""
          json = json ", \"destIp\": \"" $4 "\""
          json = json ", \"portSrc\": \"" $5 "\""
          json = json ", \"portImpacted\": " $6
          json = json ", \"flagsHistory\": \"" $7 "\""
          json = json ", \"packets\": " $8
          json = json ", \"bytes\": " $9
          json = json ", \"connStatus\": \"" $10 "\""
          json = json " }"
          print json
      }' ./Results/.sample2.data > ./Results/$output_json

    json_logs+=("$output_json"); fi
}

function analyze_pcap_data() {

    mapfile -t data_file < <(ls -1 ./Results/ 2> /dev/null)

    for ((k=0;k<=${#data_file[@]} - 1;k++)); do
        data="${data_file[$k]}"
        if [ -s "./Results/$data" ]; then
            if [ "$data" == "tcp.data" ]; then
                tcp_hunt
            elif [ "$data" == "udp.data" ]; then
                udp_hunt; fi; fi; done
}

function analyzer() {

    mapfile -t t_pcaps < <(ls -1 ./Pcaps/Trims/ | grep "^[0-9]" 2> /dev/null)
    echo -e "\n [+] Sessions joined in [${t_pcaps[*]}]" >> .logs.log
    echo -e "\n [+] Flows to analyze ==> ${#t_pcaps[@]}" | tee -a .logs.log
    id=1

    for ((i=0;i<=${#t_pcaps[@]} - 1;i++)); do
        pcap_file="${t_pcaps[$i]}"
        echo -e "\n [+] Analyzing flow ${i} [${pcap_file}]" | \
        tee -a .logs.log
        for ((j=0;j<=${#protos[@]} - 1;j++)); do
            proto="${protos[$j]}"
            extract_pcap_data; done
              analyze_pcap_data; done
}

function main() {

      clear && banner
      chmod a+rw ./Results/ && chmod -R a+rw ./Pcaps/
      echo -e "\n [*] Stored pcaps: \n"
      echo -e "\n$(for ((i=0;i<=100;i++)); do echo -n "="; done; echo -e "\n\n $(date) \n"; \
      for ((i=0;i<=100;i++)); do echo -n "="; done)\n" >> .logs.log
      mapfile -t pcaps < <(ls -1 ./Pcaps/*.pcap 2> /dev/null)

      if [ "${#pcaps[@]}" -ne 0 ]; then
      exists=0

          for ((i=0;i<=${#pcaps[@]} - 1;i++)); do
              pcap_file="${pcaps[$i]}"
              if (( i % 2 != 0 )); then
                  echo " [$i] $(basename $pcap_file)"
              else
                  echo -n " [$i] $(basename $pcap_file)"; fi; done

          while [ "$exists" -eq 0 ]; do
              echo -e " \n\n Please, enter a pcap file to be analyzed: "
              read pcap

              if [[ -f "./Pcaps/$pcap" ]]; then
                  exists=1
                  echo -e "\n [+] Pcap selected ==> ${pcap}" >> .logs.log
              else
                  input_pcap_error; fi; done

          if [ "$exists" -eq 1 ]; then
              echo -e "\n\n [+] Analyzing pcap, this may take a while."
              if PcapSplitter -f ./Pcaps/$pcap -o ./Pcaps/Trims/ -m connection \
              2>&1 /dev/null | grep 'ERROR'; then
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
                      counter=$((counter+1))
                      if [ "$counter" -eq "$n_value_round" ]; then
                          mergecap -w ./Pcaps/Trims/$RANDOM.pcap "${trims[@]}" \
                          2> /dev/null
                          trims=()
                          counter=0; fi; done;

                  mergecap -w ./Pcaps/Trims/$RANDOM.pcap "${trims[@]}" \
                  2> /dev/null
          else
              mergecap -w ./Pcaps/Trims/$RANDOM.pcap ./Pcaps/Trims/* \
              2> /dev/null; fi; fi

          analyzer
      else
          echo -e " [!] No stored pcaps found.\n" | tee -a .logs.log
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
    "rpc" #encapsulated in smb2 
    "dcerpc" #encapsulated in smb2 
    "ntlm" #encapsulated in smb2 
    "kerberos"
    "ftp"
    "ssh"
   )

  if [ "$arg1" == "--help" ] ||
     [ "$arg1" == "-h" ] || 
     [ "$arg1" == "" ]; then
      show_help
      exit 1

  elif [ "$arg1" == "--all" ] ||
       [ "$arg1" == "-a" ]; then
      protos=("${supported_protos[@]}")
      no_error=1
     
  elif [ "$arg1" == "--protocols" ] ||
       [ "$arg1" == "-p" ]; then

    if [ "$arg2" == "" ]; then
          show_help && exit 
      else
          IFS=',' read -ra protos <<< "$arg2"
          error=0

          for ((i=0;i<=${#protos[@]} - 1;i++)); do
              proto_arg="${protos[$i]}"
              if [[ "$proto_arg" == "tcp" || 
                    "$proto_arg" == "udp" || 
                    "$proto_arg" == "http" || 
                    "$proto_arg" == "dns" || 
                    "$proto_arg" == "smb2" || 
                    "$proto_arg" == "rpc" || 
                    "$proto_arg" == "dcercp" || 
                    "$proto_arg" == "ntlm" || 
                    "$proto_arg" == "kerberos" || 
                    "$proto_arg" == "ftp" || 
                    "$proto_arg" == "ssh" 
                  ]]; then
                      error=$((error+1)); fi; done; fi
  else
      show_help; fi

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
        echo -e "\n [*] Checking necessary dependencies.... \n" && sleep 3
        install_dependencies
        if [ "$control" -eq "${#to_install[@]}" ]; then
            starting; fi
    else
        starting; fi
