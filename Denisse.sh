function private_and_public() {

conn_status=($(awk '{print $NF}' ./Results/.sample1.data | sort -u))
	src=()
	dst=()

	echo -e "\n [+] TCP/UDP Connection Status ==> [${conn_status[*]}]" >> .logs.log

	for ((l=0;l<=${#conn_status[@]} - 1;l++)); do
                status="${conn_status[$l]}"
                if [[ ("$data" == "tcp.data" && ("$status" != "Unknown" &&
                       "$status" != "Finished-payload" &&
                       "$status" != "Reseted-payload")) || 
                      ("$data" == "udp.data" && ("$status" == "Established"))
                ]]; then 
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
}
