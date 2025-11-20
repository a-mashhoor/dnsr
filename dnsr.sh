#!/usr/bin/env zsh

# DNS recon tool – parallel diging :)
# dig faster u fool :))
# Author: https://github.com/a-mashhoor
# under MIT LICENCE

setopt extendedglob dotglob nullglob nounset
trap 'kill $(jobs -rp) 2>/dev/null' EXIT INT TERM

set -euo pipefail
emulate -L zsh

command -v jq   &>/dev/null || { print -u2 "Err: jq required";   exit 1; }
command -v dig  &>/dev/null || { print -u2 "Err: dig required";  exit 1; }

WHITE="\e[1;37m"; RED="\e[1;31m"; GREEN="\e[1;32m"; YELLOW="\e[1;33m"; RESET="\e[0m"

function usage() {
  cat <<EOF
Usage: $0 [options]
  -h            Show help
  -v            Verbose mode (forces text output to screen)
  -o FILE       Output file
  -w FILE       Wordlist for sub-domain brute (max 200 background jobs)
  -j            JSON output format
  -d DOMAIN     Target domain (required)
  -J            Enable parallel execution (faster)
  -k SELECTOR   DKIM selector for email security checks

Output Behavior:
  • With -v (verbose): Always shows text output on screen
    - With -j and -o: Also saves JSON to file
    - Without -j: Only shows text on screen

  • Without -v (normal):
    - With -j and -o: Shows JSON on screen AND saves to file
    - With -j only: Shows JSON on screen
    - With -o only: Shows text on screen AND saves to file
    - No -j or -o: Shows text on screen

Examples:
  $0 -d example.com                    # Text output to screen
  $0 -d example.com -j                 # JSON output to screen
  $0 -d example.com -j -o results.json # JSON to screen AND file
  $0 -d example.com -v                 # Verbose text output
  $0 -d example.com -v -j -o results.json # Verbose text + JSON file
  $0 -d example.com -J -w wordlist.txt # Parallel with wordlist
  $0 -d example.com -k google          # Check specific DKIM selector

Features:
  • DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS, SOA, etc.)
  • Zone transfer attempts
  • Reverse DNS lookups
  • Subdomain enumeration (with wordlist)
  • Email security (SPF, DMARC, DKIM)
  • Parallel execution for faster results (-J)
  • JSON or formatted text output
EOF
}

function update_json_file() {
  local file="$1" p="$2" k="$3" v="$4"
  if [[ ! -f "$file" ]]; then
    echo "{}" > "$file"
  fi

  if [[ -z "$v" ]]; then
    jq --arg k "$k" "$p |= . + {(\$k):null}" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  else
    jq --arg k "$k" --arg v "$v" "$p |= . + {(\$k):\$v}" "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  fi
}

function escape_json_string() { print -nr -- "$1"; }

function run_parallel_recon(){
  local dom=$1 wlist=$2 sel=$3 jobs=50
  local tmpdir=$(mktemp -d) || return 1
  trap "rm -rf $tmpdir" EXIT INT TERM

  # Use arrays for clarity
  local -a funcs=(query_dns_records zone_transfer_check reverse_dns_lookup enumerate_subdomains email_security_analysis)
  local -a outputs=("$tmpdir/dns.json" "$tmpdir/axfr.json" "$tmpdir/ptr.json" "$tmpdir/subs.json" "$tmpdir/mail.json")
  local -a args=("" "" "" "$wlist" "$sel")

  for ((i=1; i<=${#funcs[@]}; i++)); do
    local func=${funcs[i]}
    local out=${outputs[i]}
    local arg=${args[i]}

    echo "{}" > "$out"

    { $func "$dom" "$arg" "$out"; } &

    while (( $(jobs -r | wc -l) >= jobs )); do sleep 0.2; done
  done
  wait

  local base_json=$(jq -n --arg domain "$dom" '{
    domain: $domain,
    dns_records: {},
    zone_transfer: {},
    reverse_dns: {},
    subdomains: {},
    email_security: {}
  }')

  if [[ -f "$tmpdir/dns.json" ]]; then
    base_json=$(jq --slurpfile dns "$tmpdir/dns.json" '.dns_records = $dns[0]' <<<"$base_json")
  fi
  if [[ -f "$tmpdir/axfr.json" ]]; then
    base_json=$(jq --slurpfile axfr "$tmpdir/axfr.json" '.zone_transfer = $axfr[0]' <<<"$base_json")
  fi
  if [[ -f "$tmpdir/ptr.json" ]]; then
    base_json=$(jq --slurpfile ptr "$tmpdir/ptr.json" '.reverse_dns = $ptr[0]' <<<"$base_json")
  fi
  if [[ -f "$tmpdir/subs.json" ]]; then
    base_json=$(jq --slurpfile subs "$tmpdir/subs.json" '.subdomains = $subs[0]' <<<"$base_json")
  fi
  if [[ -f "$tmpdir/mail.json" ]]; then
    base_json=$(jq --slurpfile mail "$tmpdir/mail.json" '.email_security = $mail[0]' <<<"$base_json")
  fi

  escape_json_string "$base_json"
}


function query_dns_records() {
  local dom=$1 arg=$2 output_file="$3"
  local -a rtps=(A AAAA CNAME MX TXT NS SOA SRV PTR CAA RP HINFO LOC NAPTR TLSA DNAME)

  local tmpdir=$(mktemp -d) || return 1
  integer BG=16 job=0

  # wildcard first (serial – only one query)
  local wild=""
  wild=$(dig "*.$dom" A +short +time=1 +tries=2 2>&1)
  [[ $? -eq 0 && -n $wild ]] || wild=""
  update_json_file "$output_file" '.' 'wildcard' "$wild"

  for t in $rtps; do
    ((job++))
    {
      $verbose && print "${YELLOW}Querying $t${RESET}" >&2
      local ans=""
      ans=$(dig "$dom" "$t" +short +time=5 +tries=2 2>&1)

      print -r "$t"$'\t'"$ans" > $tmpdir/$job
    } &

    while (( $(jobs -r | wc -l) > BG )); do sleep 0.01; done
  done

  wait

  for ((i=1;i<=job;i++)); do
    local t="" ans=""
    t=$(head -1 $tmpdir/$i | cut -f1)
    ans=$(tail -n +1 $tmpdir/$i | cut -f2-)

    # For NS and TXT records, handle multiple lines properly om array
    case $t in
      NS)
        # Convert multiple NS records to JSON array
        local ns_array=$(print -r -- "$ans" | jq -R -s 'split("\n") | map(select(. != "" and . != ".")) | map(sub("\\.$";""))')
        jq --argjson a "$ns_array" ".NS = \$a" "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
        ;;
      TXT)
        local txt_array=$(print -r -- "$ans" | jq -R -s 'split("\n") | map(select(. != "")) | map(sub("^\\\"";"") | sub("\\\"$";""))')
        jq --argjson a "$txt_array" ".TXT = \$a" "$output_file" > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
        ;;
      *)
        local first_line=$(print -r -- "$ans" | head -1)
        update_json_file "$output_file" '.' "$t" "$first_line"
        ;;
    esac
   done

  rm -rf $tmpdir
}


function zone_transfer_check() {
  local dom=$1 arg=$2 output_file="$3"
  local nss=""
  nss=($(dig "$dom" NS +short 2>/dev/null))

  for ns in $nss; do
    $verbose && print "${YELLOW}AXFR via $ns${RESET}" >&2
    local z=""
    z=$(dig axfr "$dom" @"$ns" +short +time=5 2>&1)
    z=$(echo "$z" | sed 's/; //' | sed 's/\.//g')
    update_json_file "$output_file" '.' "$ns" "$z"
  done
}

function reverse_dns_lookup() {
  local dom=$1 arg=$2 output_file="$3"
  local ips=""
  ips=($(dig "$dom" A +short 2>/dev/null))
  for ip in $ips; do
    $verbose && print "${YELLOW}PTR for $ip${RESET}" >&2
    local p=""
    p=$(dig -x "$ip" +short 2>&1)
    update_json_file "$output_file" '.' "$ip" "$p"
  done
}


function enumerate_subdomains() {
  integer MAX_BG=200
  emulate -L zsh

  local dom=$1 list=$2 output_file="$3"

  [[ -z $list ]] && { print "Sub-domain brute skipped (no wordlist)" >&2; return; }
  [[ -f $list ]]  || { print "${RED}Wordlist not found${RESET}" >&2; return 1; }
  $verbose && print "${YELLOW}Sub-domain brute${RESET}" >&2

  local tmpdir=$(mktemp -d) || return 1
  local job=0

  while read -r sub; do
    (( job++ ))
    {
      local full=$sub.$dom
      local ip=$(dig "$full" A +short 2>&1)
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
      update_json_file "$output_file" '.' "${line[2]}" "${line[3]}"
    fi
  done

  rm -rf $tmpdir
}

function email_security_analysis() {
  local dom=$1 sel=$2 output_file="$3"
  $verbose && print "${YELLOW}Email security checks${RESET}" >&2

  # SPF
  local spf=""
  spf=$(dig "$dom" TXT +short 2>/dev/null | grep -m1 "v=spf1")
  update_json_file "$output_file" '.' 'spf' "${spf//\"/}"

  # DMARC
  local dmar=""
  dmar=$(dig "_dmarc.$dom" TXT +short 2>/dev/null | grep -m1 "v=DMARC1")
  update_json_file "$output_file" '.' 'dmarc' "${dmar//\"/}"

  # DKIM
  if [[ -n $sel ]]; then
    local dkim=""
    dkim=$(dig "${sel}._domainkey.$dom" TXT +short 2>&1)
    update_json_file "$output_file" '.' "dkim_${sel}" "${dkim//\"/}"
  fi
}


function generate_text_output() {
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

  print "$out"
}

function main() {
  local -A opts
  local json_out=false parallel_jobs=false ofile= wlist= dom= sel=
  typeset -g verbose=false

  zmodload zsh/zutil
  zparseopts -D -E -A opts h v J o: w: j d: k:

  (( ${+opts[-h]} )) && { usage; return 0; }
  (( ${+opts[-v]} )) && verbose=true
  ofile=${opts[-o]:-}
  wlist=${opts[-w]:-}
  (( ${+opts[-j]} )) && json_out=true
  dom=${opts[-d]:-}
  sel=${opts[-k]:-}

  (( ${+opts[-J]} )) && parallel_jobs=true

  [[ -z $dom ]] && { print -u2 "${RED}Domain required (-d)${RESET}"; usage; return 1; }
  if ! dig "$dom" A +short &>/dev/null; then
    print -u2 "${RED}Cannot resolve $dom${RESET}"; return 1
  fi
  if $json_out && [[ -z $ofile ]]; then
    print -u2 "${RED}JSON output needs -o FILE${RESET}"; usage; return 1
  fi

  $verbose && print "${WHITE}Checking DNS for $dom${RESET}" >&2
  $verbose && print "Verbose mode on  (parallel jobs: $parallel_jobs)" >&2

  local JSON_DATA="{}"

  handle_output() {
    local json_data="$1"

    if $verbose; then
      generate_text_output "$json_data" 0

      if $json_out && [[ -n "$ofile" ]]; then
        jq . <<<"$json_data" > "$ofile"
        $verbose && print "${GREEN}JSON saved → $ofile${RESET}" >&2
      fi
    else
      if $json_out; then
        if [[ -n "$ofile" ]]; then
          jq . <<<"$json_data" > "$ofile"
          jq . <<<"$json_data"
          $verbose && print "${GREEN}JSON saved → $ofile${RESET}" >&2
        else
          jq . <<<"$json_data"
        fi
      else
        if [[ -n "$ofile" ]]; then
          generate_text_output "$json_data" 0 > "$ofile"
          generate_text_output "$json_data" 0
          $verbose && print "${GREEN}Text saved → $ofile${RESET}" >&2
        else
          # Show text on stdout only
          generate_text_output "$json_data" 0
        fi
      fi
    fi
  }

  if $parallel_jobs; then
    # Parallel mode
    JSON_DATA=$(run_parallel_recon "$dom" "$wlist" "$sel")
    handle_output "$JSON_DATA"
  else
    # Sequential mode
    local tmpdir=$(mktemp -d)
    trap "rm -rf $tmpdir" EXIT

    echo "{}" > "$tmpdir/dns.json"
    echo "{}" > "$tmpdir/axfr.json"
    echo "{}" > "$tmpdir/ptr.json"
    echo "{}" > "$tmpdir/subs.json"
    echo "{}" > "$tmpdir/mail.json"

    query_dns_records "$dom" "" "$tmpdir/dns.json"
    zone_transfer_check "$dom" "" "$tmpdir/axfr.json"
    reverse_dns_lookup "$dom" "" "$tmpdir/ptr.json"
    enumerate_subdomains "$dom" "$wlist" "$tmpdir/subs.json"
    email_security_analysis "$dom" "$sel" "$tmpdir/mail.json"

    JSON_DATA=$(jq -n --arg domain "$dom" '{
      domain: $domain,
      dns_records: {},
      zone_transfer: {},
      reverse_dns: {},
      subdomains: {},
      email_security: {}
    }')

    JSON_DATA=$(jq --slurpfile dns "$tmpdir/dns.json" '.dns_records = $dns[0]' <<<"$JSON_DATA")
    JSON_DATA=$(jq --slurpfile axfr "$tmpdir/axfr.json" '.zone_transfer = $axfr[0]' <<<"$JSON_DATA")
    JSON_DATA=$(jq --slurpfile ptr "$tmpdir/ptr.json" '.reverse_dns = $ptr[0]' <<<"$JSON_DATA")
    JSON_DATA=$(jq --slurpfile subs "$tmpdir/subs.json" '.subdomains = $subs[0]' <<<"$JSON_DATA")
    JSON_DATA=$(jq --slurpfile mail "$tmpdir/mail.json" '.email_security = $mail[0]' <<<"$JSON_DATA")

    handle_output "$JSON_DATA"
    rm -rf "$tmpdir"
  fi
}


# Only run main if this script is executed directly
# We are doing this to perform parallelism without any wierd errors :)
if [[ $ZSH_EVAL_CONTEXT == 'toplevel' ]]; then
  main "$@"
fi
