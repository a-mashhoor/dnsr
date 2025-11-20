#!/usr/bin/env zsh

# I initiated this project as a simple DNS handler but it was so much work,(fucking json in shell) enjoy!

# Enable better zsh options
setopt extendedglob dotglob nullglob nounset

# Check for deps

command -v jq &>/dev/null || {
  print -u2 -- "Err: jq is required (apt/yum/brew install jq)"
  exit 1
}

command -v dig &>/dev/null || {
  print -u2 -- "Err: dig required"
  exit 1
}



WHITE="\e[1;37m"
RED="\e[1;31m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
RESET="\e[0m"

JSON_TEMP_FILE=$(mktemp)
JSON_DATA="{}"


usage() {
  cat <<EOF
Usage: $0 [options]
  -h            Show help
  -v            Verbose
  -o FILE       Output file (required for -j)
  -w FILE       Wordlist for sub-domain brute (parallel --> MAX 200)
  -j            JSON output (requires -o)
  -d DOMAIN     Target domain (required)
  -k SELECTOR   DKIM selector
Examples:
  $0 -d example.com
  $0 -d example.com -j -o out.json
  $0 -d example.com -w subs.txt -v
EOF
}

init_json() {
  JSON_DATA=$(jq -n --arg d "$1" '{domain: $d,dns_records:{},
  zone_transfer:{},reverse_dns:{},subdomains:{},email_security: {}}')
}

update_json() {
  local p=$1 k=$2 v=$3
  if [[ -z $v ]]; then
    JSON_DATA=$(jq --arg k "$k" "$p |= . + {(\$k):null}" <<<"$JSON_DATA")
  else
    JSON_DATA=$(jq --arg k "$k" --arg v "$v" "$p |= . + {(\$k):\$v}" <<<"$JSON_DATA")
  fi
}


escape_json_string() { print -nr -- "$1"; }

query_dns_records() {
  local dom=$1 verbose=$2
  local rtps=(A AAAA CNAME MX TXT NS SOA SRV PTR CAA RP HINFO LOC NAPTR TLSA DNAME)

  local wild=""
  wild=$(dig "*.$dom" A +short +time=5 +tries=2 2>&1)
  [[ $? -eq 0 && -n $wild ]] || wild=""
  update_json '.dns_records' 'wildcard' "$wild"

  for t in $rtps; do
    $verbose && print "${YELLOW}Querying $t${RESET}"
    local ans=""
    ans=$(dig "$dom" "$t" +short +time=5 +tries=2 2>&1 )

    # TXT and NS as an array
    case $t in
      NS)
        JSON_DATA=$(jq --argjson a "$(jq -R -s 'split("\n") | map(sub("^\\\"";"") | sub("\\\"$";""))' <<<"$ans")" \
                       '.dns_records.NS = $a' <<<"$JSON_DATA")
        continue
        ;;
      TXT)
        JSON_DATA=$(jq --argjson a "$(jq -R -s 'split("\n") | map(sub("^\\\"";"") | sub("\\\"$";""))' <<<"$ans")" \
                       '.dns_records.TXT = $a' <<<"$JSON_DATA")
        continue
        ;;
    esac

    update_json '.dns_records' "$t" "$ans"
  done
}


zone_transfer_check() {
  local dom=$1 verbose=$2
  local nss=""
  nss=($(dig "$dom" NS +short 2>/dev/null))

  for ns in $nss; do
    $verbose && print "${YELLOW}AXFR via $ns${RESET}"
    local z=""
    z=$(dig axfr "$dom" @"$ns" +short +time=5 2>&1)
    z=$(escape_json_string "$z")
    z=$(echo "$z" | sed 's/; //' | sed 's/\.//g')
    update_json '.zone_transfer' "$ns" "$z"
  done
}


reverse_dns_lookup() {
  local dom=$1 verbose=$2
  local ips=""
  ips=($(dig "$dom" A +short 2>/dev/null))
  for ip in $ips; do
    $verbose && print "${YELLOW}PTR for $ip${RESET}"
    local p=""
    p=$(dig -x "$ip" +short 2>&1)
    p=$(escape_json_string "$p")
    update_json '.reverse_dns' "$ip" "$p"
  done
}




enumerate_subdomains() {
  integer MAX_BG=200

  emulate -L zsh

  local dom=$1 list=$2 verbose=$3
  [[ -z $list ]] && { print "Sub-domain brute skipped (no wordlist)"; return; }
  [[ -f $list ]]  || { print "${RED}Wordlist not found${RESET}"; return 1; }

  $verbose && print "${YELLOW}Sub-domain brute${RESET}"

  local tmpdir=$(mktemp -d) || return 1
  local job=0

  while read -r sub; do
    (( job++ ))
    {
      local full=$sub.$dom
      local ip=$(dig "$full" A +short 2>&1)
      ip=$(escape_json_string "$ip")
      # write one line per job:  job_number<tab>full<tab>ip
      print -r "$job"$'\t'"$full"$'\t'"$ip"
    } >$tmpdir/$job 2>&1 &

    # throttle: keep MAX_BG jobs running
    while (( $(jobs -r | wc -l) >= MAX_BG )); do
      sleep 0.1
    done
  done <"$list"

  wait

  local i=1
  for ((i=1; i<=job; i++)); do
    typeset -a line=()
    IFS=$'\t' read -rA line < $tmpdir/$i
    if [[ ! -z $line[3] ]]; then
      update_json '.subdomains' "${line[2]}" "${line[3]}"
    fi
  done

  rm -rf $tmpdir
}



email_security_analysis() {
  local dom=$1 sel=$2 verbose=$3
  $verbose && print "${YELLOW}Email security checks${RESET}"

  # SPF
  local spf=""
  spf=$(dig "$dom" TXT +short 2>/dev/null | grep -m1 "v=spf1")
  JSON_DATA=$(jq --arg v "${spf//\"/}" \
                 '.email_security.spf = ($v | if . == "" then null else . end)' <<<"$JSON_DATA")

  # DMARC
  local dmar=""
  dmar=$(dig "_dmarc.$dom" TXT +short 2>/dev/null | grep -m1 "v=DMARC1")
  JSON_DATA=$(jq --arg v "${dmar//\"/}" \
                 '.email_security.dmarc = ($v | if . == "" then null else . end)' <<<"$JSON_DATA")

  # DKIM
  if [[ -n $sel ]]; then
    local dkim=""
    dkim=$(dig "${sel}._domainkey.$dom" TXT +short 2>&1)
    JSON_DATA=$(jq --arg k "dkim_${sel}" --arg v "${dkim//\"/}" \
                   '.email_security[$k] = ($v | if . == "" then null else . end)' <<<"$JSON_DATA")
  fi
}


generate_text_output() {

  local json="$1" nocolor=${2:-0}
  local out="" domain=""
  domain=$(jq -r '.domain' <<<"$json")

  colorize() { ((nocolor)) && print -nr -- "$2" || print -nr -- "$1$2$RESET"; }

  out=$'\n\n'"=== DNS Records for $domain ==="$'\n\n'
  while IFS= read -r l; do
    out+=$(colorize "$YELLOW" "${l%%:*}")": ${l#*: }"$'\n\n'
  done < <(jq -r '.dns_records|to_entries[]|"\(.key): \(.value//"null")"' <<<"$json")

  out+=$'\n\n'"=== Zone Transfer ==="$'\n'
  while IFS= read -r l; do
    out+="${l%%:*}: ${l#*: }"$'\n'
  done < <(jq -r '.zone_transfer|to_entries[]|"\(.key): \(.value//"null")"' <<<"$json")

  out+=$'\n\n'"=== Reverse DNS ==="$'\n'
  while IFS= read -r l; do
    out+=$(colorize "$YELLOW" "${l%%:*}")": ${l#*: }"$'\n'
  done < <(jq -r '.reverse_dns|to_entries[]|"\(.key): \(.value//"null")"' <<<"$json")

  if jq -e '.subdomains|length>0' <<<"$json" &>/dev/null; then
    out+=$'\n\n'"=== Subdomains ==="$'\n'
    while IFS= read -r l; do
      out+=$(colorize "$YELLOW" "${l%%:*}")": ${l#*: }"$'\n'
    done < <(jq -r '.subdomains|to_entries[]|"\(.key): \(.value//"null")"' <<<"$json")
  fi

  out+=$'\n\n'"=== Email Security ==="$'\n'
  while IFS= read -r l; do
    out+=$(colorize "$YELLOW" "${l%%:*}")": ${l#*: }"$'\n'
  done < <(jq -r '.email_security|to_entries[]|"\(.key): \(.value//"null")"' <<<"$json")

  print -nr -- "$out"
}




function ooo(){
  if [[ -n "$output_file" ]]; then
    mkdir -p "$(dirname "$output_file")" || {
      print "${RED}Error: Failed to create directory for '$output_file'${RESET}"; return 1}

    touch "$output_file" || {
      print "${RED}Error: Failed to create output file '$output_file'${RESET}"; return 1}
  fi
}


main() {
  local -A opts
  local verbose=false json_out=false ofile= wlist= dom= sel=

  zmodload zsh/zutil
  zparseopts -D -E -A opts h v o: w: j d: k:

  (( ${+opts[-h]} )) && { usage; return 0; }

  (( ${+opts[-v]} )) && verbose=true

  ofile=${opts[-o]:-}
  wlist=${opts[-w]:-}
  (( ${+opts[-j]} )) && json_out=true
  dom=${opts[-d]:-}
  sel=${opts[-k]:-}

  [[ -z $dom ]] && { print -u2 -- "${RED}Domain required (-d)${RESET}"; usage; return 1; }

  if ! dig "$dom" A +short &>/dev/null; then
    print -u2 -- "${RED}Cannot resolve $dom${RESET}"; return 1
  fi

  if $json_out && [[ -z $ofile ]]; then
    print -u2 -- "${RED}JSON output needs -o FILE${RESET}"; usage; return 1
  fi

  print "${WHITE}Checking DNS for $dom${RESET}"

  $verbose && print "Verbose mode on"

  init_json "$dom"

  query_dns_records      "$dom" "$verbose"
  zone_transfer_check    "$dom" "$verbose"
  reverse_dns_lookup     "$dom" "$verbose"
  enumerate_subdomains   "$dom" "$wlist" "$verbose"
  email_security_analysis "$dom" "$sel"  "$verbose"

  if $json_out; then
    jq . <<<"$JSON_DATA" > "$ofile"
    print "${GREEN}JSON saved → $ofile${RESET}"
  else
    local use_color=1
    [[ -n $ofile ]] && use_color=0
    generate_text_output "$JSON_DATA" "$use_color" | sed $'s/\e\[[0-9;]*m//g' >|"${ofile:-/dev/stdout}"
    [[ -n $ofile ]] && print "${GREEN}Text saved → $ofile${RESET}"
  fi
  rm -f "$JSON_TEMP_FILE"
}



main "$@"
