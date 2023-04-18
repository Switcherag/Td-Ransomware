docker run -it --rm --name ransomware ^
    --net=ransomware-network ^
    -v "%cd%/sources:/root/ransomware:ro" ^
    -v "%cd%/dist:/root/bin:rw" ^
    ransomware ^
    /bin/bash