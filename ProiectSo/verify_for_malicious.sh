#!/bin/bash

if [ $# -lt 0 ]; then
    echo "Nu exista argumente"
    exit 0
fi


#Lista de cuvinte cheie
keywords=("corrupted" "dangerous" "risk" "attak" "malware" "malicious")

filename=$1 #fisieru care tre sa fie verificat

#Numarul de linii
num_lines=$(wc -l < "$filename")

#Numarul de cuvinte
num_words=$(wc -w < "$filename")

#Numarul de caractere
num_chars=$(wc -m < "$filename")

#verifica daca are mai putin de 3 linii peste 1000 de cuvinte si peste 2000 de cractere
if [ $num_lines -lt 3 ] && [ $num_words -ge 1000 ] && [ $num_chars -ge 2000 ]; then
    echo "$filename"
    exit 1
fi


#verifica daca exista cuvintele cheie in fisiere
for keyword in "${keywords[@]}"; do
    if grep -q "\<$keyword\>" "$filename"; then
        echo "$filename"
        exit 1
    fi 
done

#verifica daca exista caractere non-ascii in fisier
if grep -qP "[^\x00-\x7F]" "$filename"; then
    echo "$filename"
    exit 1
fi


#daca a ajuns aici inseamna ca fisieru nu e corupt sau periculos
# echo "SAFE"
exit 2