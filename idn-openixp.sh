#!/bin/bash

# URL file sumber
NICE_URL="http://ixp.mikrotik.co.id/download/nice.rsc"
APNIC_URL="https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
OUTPUT_FILE="/etc/bind/acl_indonesia.conf"

# Inisialisasi file output
echo 'acl "indonesia" {' > "$OUTPUT_FILE"

# Tambahkan entri IP lokal yang diminta
echo -e "\t10.0.0.0/8;" >> "$OUTPUT_FILE"
echo -e "\t172.16.0.0/12;" >> "$OUTPUT_FILE"
echo -e "\t192.168.0.0/16;" >> "$OUTPUT_FILE"
echo -e "\t127.0.0.0/8;" >> "$OUTPUT_FILE"
echo -e "\t::1/128;" >> "$OUTPUT_FILE"
echo -e "\tlocalhost;" >> "$OUTPUT_FILE"

# Unduh dan proses nice.rsc langsung dengan awk
curl -s "$NICE_URL" | \
awk -F 'address=' '/add list=nice address=/ {
    gsub("\"", "", $2); 
    if ($2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) 
        print "\t" $2 ";"
}' >> "$OUTPUT_FILE"

# Unduh dan proses delegated-apnic-latest langsung dengan awk
curl -s "$APNIC_URL" | \
awk -F '|' '/^apnic\|ID\|ipv4/ { 
    printf "\t%s/%d;\n", $4, 32-log($5)/log(2) 
}' >> "$OUTPUT_FILE"

# Hapus duplikat dan pastikan format konsisten
awk '!seen[$0]++ && NF > 0' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

# Tutup ACL
echo "};" >> "$OUTPUT_FILE"

echo "File ACL Indonesia + NiCe OpenIXP berhasil dibuat: $OUTPUT_FILE"
