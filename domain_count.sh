#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "用法：$0 -i <輸入檔案> -o <輸出檔案>"
  echo
  echo "範例："
  echo "  $0 -i resolver.log -o dns_domain_count.txt"
  exit 1
}

input_file=""
output_file=""

while getopts ":i:o:h" opt; do
  case "$opt" in
    i)
      input_file="$OPTARG"
      ;;
    o)
      output_file="$OPTARG"
      ;;
    h)
      usage
      ;;
    :)
      echo "錯誤：選項 -$OPTARG 需要參數。" >&2
      usage
      ;;
    \?)
      echo "錯誤：不支援的選項 -$OPTARG。" >&2
      usage
      ;;
  esac
done

if [[ -z "$input_file" || -z "$output_file" ]]; then
  echo "錯誤：必須指定輸入檔案與輸出檔案。" >&2
  usage
fi

if [[ ! -f "$input_file" ]]; then
  echo "錯誤：找不到輸入檔案：$input_file" >&2
  exit 1
fi

awk '
{
  for (i = 1; i < NF; i++) {
    if ($(i + 1) ~ /^(A|AAAA|CNAME|MX|NS|PTR|SOA|SRV|TXT|CAA|HTTPS|SVCB)$/) {
      domain = $i
      sub(/\.$/, "", domain)
      print domain
      break
    }
  }
}
' "$input_file" |
sort |
uniq -c |
sort -nr > "$output_file"

echo "處理完成：$output_file"

