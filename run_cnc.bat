mkdir cnc_data
docker run -it --rm --name cnc `
    --net=ransomware-network `
    -v "${PWD}\sources:/root/ransomware:ro" `
	-v "${PWD}\dist:/root/CNC/bin:ro" `
    -v "${PWD}\cnc_data:/root/CNC ransomware" `
    ransomware `
    python /root/ransomware/cnc.py