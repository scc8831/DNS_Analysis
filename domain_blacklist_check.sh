#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
用法：
  ./domain_blacklist_check.sh -i domain_count.txt -b blacklist.txt
  ./domain_blacklist_check.sh -i domain_count.txt -b blacklist1.txt -b blacklist2.txt
  ./domain_blacklist_check.sh -i domain_count.txt -b blacklist.txt -o result

參數：
  -i FILE   輸入的 Domain 統計檔
  -b FILE   黑名單檔案，可重複指定多個
  -o PREFIX 輸出檔名前綴，預設為 blacklist_result
  -h        顯示說明

輸入格式範例：
  16 location.services.mozilla.com
  15 0.opnsense.pool.ntp.org
  12 facebook.com
EOF
}

INPUT_FILE=""
OUTPUT_PREFIX="blacklist_result"
BLACKLIST_FILES=()

while getopts ":i:b:o:h" opt; do
    case "$opt" in
        i)
            INPUT_FILE="$OPTARG"
            ;;
        b)
            BLACKLIST_FILES+=("$OPTARG")
            ;;
        o)
            OUTPUT_PREFIX="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        :)
            echo "錯誤：參數 -$OPTARG 需要指定值。" >&2
            usage
            exit 1
            ;;
        \?)
            echo "錯誤：未知參數 -$OPTARG" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$INPUT_FILE" ]]; then
    echo "錯誤：請使用 -i 指定輸入檔案。" >&2
    usage
    exit 1
fi

if [[ ${#BLACKLIST_FILES[@]} -eq 0 ]]; then
    echo "錯誤：請至少使用一次 -b 指定黑名單檔案。" >&2
    usage
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "錯誤：找不到輸入檔案：$INPUT_FILE" >&2
    exit 1
fi

for blacklist in "${BLACKLIST_FILES[@]}"; do
    if [[ ! -f "$blacklist" ]]; then
        echo "錯誤：找不到黑名單檔案：$blacklist" >&2
        exit 1
    fi
done

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

NORMALIZED_INPUT="$TMP_DIR/input.tsv"
NORMALIZED_BLACKLIST="$TMP_DIR/blacklist.txt"

MATCHED_FILE="${OUTPUT_PREFIX}_matched.txt"
UNMATCHED_FILE="${OUTPUT_PREFIX}_unmatched.txt"
SUMMARY_FILE="${OUTPUT_PREFIX}_summary.txt"

###############################################################################
# 處理輸入檔
#
# 輸入：
#   16 location.services.mozilla.com
#
# 輸出為 TAB 分隔：
#   16    location.services.mozilla.com
###############################################################################

awk '
function normalize(domain) {
    domain = tolower(domain)
    sub(/\.$/, "", domain)
    return domain
}

NF >= 2 {
    count = $1
    domain = normalize($2)

    if (count ~ /^[0-9]+$/ &&
        domain ~ /^[a-z0-9._-]+$/ &&
        domain != "") {
        print count "\t" domain
    }
}
' "$INPUT_FILE" > "$NORMALIZED_INPUT"

###############################################################################
# 正規化黑名單
#
# 支援：
#   facebook.com
#   *.facebook.com
#   ||facebook.com^
#   0.0.0.0 facebook.com
#   127.0.0.1 facebook.com
#   address=/facebook.com/0.0.0.0
###############################################################################

cat "${BLACKLIST_FILES[@]}" |
awk '
function normalize(domain) {
    domain = tolower(domain)

    gsub(/\r/, "", domain)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", domain)

    # Adblock 格式：||example.com^
    sub(/^\|\|/, "", domain)
    sub(/\^.*$/, "", domain)

    # 萬用字元：*.example.com
    sub(/^\*\./, "", domain)

    # URL 格式
    sub(/^https?:\/\//, "", domain)
    sub(/\/.*$/, "", domain)

    # 移除 port
    sub(/:[0-9]+$/, "", domain)

    # 結尾的點
    sub(/\.$/, "", domain)

    return domain
}

{
    line = $0

    gsub(/\r/, "", line)
    sub(/^[[:space:]]+/, "", line)
    sub(/[[:space:]]+$/, "", line)

    # 跳過空白、註解、Adblock 控制規則
    if (line == "" ||
        line ~ /^[#;]/ ||
        line ~ /^!/ ||
        line ~ /^\[/ ||
        line ~ /^@@/) {
        next
    }

    domain = ""

    # Hosts 格式：
    # 0.0.0.0 example.com
    # 127.0.0.1 example.com
    if (line ~ /^(0\.0\.0\.0|127\.0\.0\.1|::1)[[:space:]]+/) {
        split(line, fields, /[[:space:]]+/)
        domain = fields[2]
    }

    # dnsmasq 格式：
    # address=/example.com/0.0.0.0
    else if (line ~ /^address=\//) {
        sub(/^address=\//, "", line)
        split(line, fields, "/")
        domain = fields[1]
    }

    # 一般 Domain、URL 或 Adblock 格式
    else {
        split(line, fields, /[[:space:]]+/)
        domain = fields[1]
    }

    domain = normalize(domain)

    if (domain ~ /^[a-z0-9._-]+\.[a-z0-9_-]+$/) {
        print domain
    }
}
' |
sort -u > "$NORMALIZED_BLACKLIST"

###############################################################################
# 執行比對
###############################################################################

awk -F '\t' \
    -v matched_file="$MATCHED_FILE" \
    -v unmatched_file="$UNMATCHED_FILE" \
    -v summary_file="$SUMMARY_FILE" '
function is_blacklisted(domain,    current) {
    current = domain

    while (current != "") {
        if (current in blacklist) {
            matched_rule = current
            return 1
        }

        # 逐層移除最左側子網域
        # location.services.mozilla.com
        # -> services.mozilla.com
        # -> mozilla.com
        if (current ~ /\./) {
            sub(/^[^.]+\./, "", current)
        } else {
            break
        }
    }

    return 0
}

BEGIN {
    while ((getline line < ARGV[1]) > 0) {
        blacklist[line] = 1
        blacklist_count++
    }

    close(ARGV[1])
    ARGV[1] = ""
}

{
    count = $1 + 0
    domain = $2

    total_domains++
    total_queries += count

    matched_rule = ""

    if (is_blacklisted(domain)) {
        matched_domains++
        matched_queries += count

        printf "%d\t%s\tMATCH\t%s\n",
            count,
            domain,
            matched_rule > matched_file
    } else {
        unmatched_domains++
        unmatched_queries += count

        printf "%d\t%s\tNO_MATCH\n",
            count,
            domain > unmatched_file
    }
}

END {
    domain_match_rate = 0
    query_match_rate = 0

    if (total_domains > 0) {
        domain_match_rate = matched_domains / total_domains * 100
    }

    if (total_queries > 0) {
        query_match_rate = matched_queries / total_queries * 100
    }

    print "===== Domain 黑名單比對統計 =====" > summary_file
    printf "黑名單 Domain 數量：%d\n", blacklist_count >> summary_file
    printf "輸入 Domain 數量：%d\n", total_domains >> summary_file
    printf "輸入查詢總次數：%d\n", total_queries >> summary_file
    print "" >> summary_file

    printf "命中 Domain 數量：%d\n", matched_domains >> summary_file
    printf "未命中 Domain 數量：%d\n", unmatched_domains >> summary_file
    printf "Domain 命中率：%.2f%%\n", domain_match_rate >> summary_file
    print "" >> summary_file

    printf "命中查詢次數：%d\n", matched_queries >> summary_file
    printf "未命中查詢次數：%d\n", unmatched_queries >> summary_file
    printf "查詢次數命中率：%.2f%%\n", query_match_rate >> summary_file
}
' "$NORMALIZED_BLACKLIST" "$NORMALIZED_INPUT"

# 依查詢次數由高至低排序
sort -t $'\t' -k1,1nr "$MATCHED_FILE" -o "$MATCHED_FILE"
sort -t $'\t' -k1,1nr "$UNMATCHED_FILE" -o "$UNMATCHED_FILE"

cat "$SUMMARY_FILE"

echo
echo "輸出檔案："
echo "  命中清單：$MATCHED_FILE"
echo "  未命中清單：$UNMATCHED_FILE"
echo "  統計資訊：$SUMMARY_FILE"
