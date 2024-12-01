#!/bin/bash
# certutil -d sql:/home/aaron/.pki/nssdb -D -n 
# certutil -d sql:$HOME/.pki/nssdb -L

function add_cert()
{ 
    #国家根证书没有 -----BEGIN CERTIFICATE----- 
    # -----BEGIN CERTIFICATE-----
    #需要脚本添加

    #sed -i '1i\-----BEGIN CERTIFICATE-----' "${2}"
    #sed -i '$a\-----BEGIN CERTIFICATE-----' "${2}"

    echo "${1}: ${2} start"
    certutil -d sql:/home/aaron/.pki/uos_nssdb -A -t "CT,C,c" -n "${1}""-""${2}" -i "${2}"
    echo "${1}: ${2} end"
}

#certutil -d sql:/home/aaron/.pki/nssdb -A -t "CT,C,C" -n 'cacs.crt' -i cacs.crt


function travFolder()
{
  echo "${1}"
  flist=`ls ${1}`
  cd "${1}"
  #echo $flist
  for f in $flist
  do
    if test -d "$f"
    then
      #echo "dir:$f"
      travFolder "$f"
    else
      #echo "file:$f"
      add_cert "${1}" "$f"
    fi
  done
  cd ../
}

#travFolder $1

travFolder ${1}