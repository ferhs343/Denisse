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
                  awk -v status="$status" \
                      -v src_ip="$src_ip" \
                      -v dst_ip="$dst_ip" \
                      '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                      ./Results/.sample1.data | sort -u | wc -l
               )

               echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

               if [ "$n_ports" -gt 10 ]; then
                  vertical_scan=1; tcp=1
                  alert="${src_type} ${VPS}"
                  generate_results_tcp "$dst_ip"; fi
               else 
                  #case 2 : 1 ==> N
                  ports_a=()
                  for ((n=0;n<=${#dst[@]} - 1;n++)); do
                     dst_ip="${dst[$n]}"
                     n_ports=$(
                        awk -v status="$status" \
                            -v src_ip="$src_ip" \
                            -v dst_ip="$dst_ip" \
                            '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                            ./Results/.sample1.data | sort -u | wc -l
                     )

                     echo -e "\n [+] TCP/UDP Vertical Scan proof - No. Ports ==> [$n_ports]" >> .logs.log

                     if [ "$n_ports" -gt 10 ]; then
                        vertical_scan=1
                        if [ "$data" == "tcp.data" ]; then tcp=1; else udp=1; fi
                        alert="${src_type} ${VPS}"
                        generate_results_tcp "$dst_ip"
                     else
                        ports=$(
                           awk -v status="$status" \
                               -v src_ip="$src_ip" \
                               -v dst_ip="$dst_ip" \
                               '$NF == status && $3 == src_ip && $4 == dst_ip {print $6}' \
                               ./Results/.sample1.data | sort -u
                        ); ports_a+=("$ports"); fi; done
   
                  echo -e "\n [+] TCP/UDP Horizontal Scan proof - Ports ==> [${ports_a[*]}]" >> .logs.log
                  echo -e "\n [+] TCP/UDP Horizontal Scan proof - Dst IP's [${dst[*]}]" >> .logs.log

                  multiple_dst=()                  
                  for ((n=0;n<=${#ports_a[@]} - 1;n++)); do
                  	current="${ports_a[$n]}"
                  	for ((o=$n+1;o<=${#ports_a[@]} - 1;o++)); do
                  		next="${ports_a[$o]}"
                  		if [ "$current" == "$next" ]; then
                  			if [ "${ports_a[$n]}" != "x.x" ]; then
                  				ports_a[$n]="x.x"; fi
                  				ports_a[$o]="x.x"; fi; done; done

                  echo -e "\n [+] TCP/UDP Horizontal Scan proof - Result [${ports_a[*]}]" >> .logs.log

                  for ((n=0;n<=${#ports_a[@]} - 1;n++)); do
                  	if [ "${ports_a[$n]}" == "x.x" ]; then
                  		multiple_dst+=("${dst[$n]}"); fi; done

                  echo -e "\n [+] TCP/UDP Horizontal Scan proof - Result [${multiple_dst[*]}]" >> .logs.log
 
                  if [ "${#multiple_dst[@]}" -gt 0 ]; then
                     horizontal_scan=1
                     if [ "$data" == "tcp.data" ]; then tcp=1; else udp=1; fi
                     alert="${src_type} ${HPS}"
                     generate_results_tcp "${multiple_dst[@]}" 
                     fi; fi; done; fi; done
}
