#!/bin/bash

# Judul:  
# Bash Script untuk Membuat File ACL Indonesia dengan Data IP dari Nice.rsc dan APNIC

# Fungsi:  
# Script ini digunakan untuk membuat file konfigurasi ACL (Access Control List) untuk Indonesia 
# dengan menggabungkan entri IP lokal dan data IP yang diunduh dari dua sumber eksternal: Nice.rsc dan APNIC. 
# Script ini secara otomatis mengunduh data, memprosesnya, dan menghasilkan file konfigurasi yang siap digunakan 
# untuk pengaturan DNS atau firewall.

# Deskripsi:  
# 1. Inisialisasi URL dan Output:  
#    - Mendefinisikan URL sumber file nice.rsc dan delegated-apnic-latest dari APNIC.
#    - Menentukan lokasi output file konfigurasi ACL di /etc/bind/acl_indonesia.conf.

# 2. Menambahkan Entri IP Lokal:  
#    - Menambahkan entri untuk IP lokal yang umum digunakan seperti 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, dan lainnya.

# 3. Mengunduh dan Memproses Data Nice.rsc:  
#    - Mengunduh file nice.rsc dari URL yang telah ditentukan.
#    - Menggunakan awk untuk mengekstrak alamat IP dan menambahkannya ke file output.

# 4. Mengunduh dan Memproses Data APNIC:  
#    - Mengunduh data delegated-apnic-latest dari APNIC.
#    - Menggunakan awk untuk mengekstrak alamat IP dari data APNIC dan menambahkannya ke file output.

# 5. Menghapus Duplikat dan Menjaga Konsistensi Format:  
#    - Menggunakan awk untuk menghapus duplikat dan memastikan format file output tetap konsisten.

# 6. Menutup Konfigurasi ACL:  
#    - Menambahkan tanda penutup }; pada akhir file ACL.

# 7. Output Informasi:  
#    - Menampilkan pesan bahwa file ACL Indonesia berhasil dibuat.

# Dibuat oleh:  
# HARRY DS ALSYUNDAWY

# Tanggal Dibuat:  
# 25 Desember 2025

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
