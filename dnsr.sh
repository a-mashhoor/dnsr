#!/bin/zsh

# I initiated this project as a simple DNS handler but it was so much work, enjoy!

# Enable better zsh options
setopt extended_glob
setopt null_glob
setopt no_unset

# Check if jq is installed
if ! command -v jq &> /dev/null; then
	echo "Error: jq is not installed. Please install it first."
	echo "On Debian/Ubuntu: sudo apt-get install jq"
	echo "On CentOS/RHEL: sudo yum install jq"
	echo "On macOS: brew install jq"
	exit 1
fi

# Define colors
WHITE="\e[1;37m"
RED="\e[1;31m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
RESET="\e[0m"

# Global JSON storage
JSON_TEMP_FILE=$(mktemp)
JSON_DATA="{}"

# Help documentation
usage() {
	echo "Usage: $0 [options]"
	echo "Options:"
	echo "  -h            Show this help message"
	echo "  -v            Enable verbose mode for detailed logs"
	echo "  -o FILE       Save results to a file (optional)"
	echo "  -w FILE       Use a wordlist for subdomain enumeration (optional)"
	echo "  -j            Save results in JSON format (requires -o)"
	echo "  -d DOMAIN     Specify the target domain (required)"
	echo "  -k SELECTOR   Specify the DKIM selector for DKIM testing (optional)"
	echo ""
	echo "Note: use json output for a cleaner result"
	echo ""
	echo "Examples: "
	echo "  $0 -v -o results.txt -d example.com"
	echo "  $0 -v -o results.txt -d example.com -w wordlist.txt -k default"
	echo "  $0 -d example.com -o output.json -j"
}

# Initialize JSON structure
init_json() {
	local domain="$1"
	JSON_DATA=$(/usr/bin/jq -n --arg domain "$domain" '{
	domain: $domain,
	dns_records: {},
	zone_transfer: {},
	reverse_dns: {},
	subdomains: {},
	email_security: {}
}')
}

# Update JSON data
update_json() {
	local path="$1"
	local key="$2"
	local value="$3"

	if [[ "$value" == "null" ]]; then
		JSON_DATA=$(/usr/bin/jq --arg key "$key" "$path |= . + {(\$key): null}" <<< "$JSON_DATA")
	else
		JSON_DATA=$(/usr/bin/jq --arg key "$key" --arg value "$value" "$path |= . + {(\$key): \$value}" <<< "$JSON_DATA")
	fi
}

# Function to escape special characters for JSON
escape_json_string() {
	local input="$1"
	input="${input//\\/\\\\}"
	input="${input//\"/\\\"}"
	input="${input//$'\n'/\\n}"
	input="${input//$'\r'/\\r}"
	input="${input//$'\t'/\\t}"
	echo "$input"
}

query_dns_records() {
	local domain="$1" verbose="$2"
	local record_types=(A AAAA CNAME MX TXT NS SOA SRV PTR CAA RP HINFO LOC NAPTR TLSA DNAME)
	local records record_type wildcard

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== Querying DNS Records ===${RESET}"
	fi

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== cheking for wildcard possibility ===${RESET}"
	fi

	wildcard=$(dig "*.$domain" A +short +time=5 +tries=2 2>&1)
	if [[ -z "$wildcard" ]]; then
		update_json ".dns_records" "wildcard" "null"
	else
		update_json ".dns_records" "wildcard" "$wildcard"
	fi

	for record_type in $record_types; do
		if [[ "$verbose" == "true" ]]; then
			print "Querying $record_type records for domain: $domain"
		fi

		records=$(dig "$domain" "$record_type" +short +time=5 +tries=2 2>&1)
		records=$(escape_json_string "$records")

		if [[ -z "$records" ]]; then
			update_json ".dns_records" "$record_type" "null"
		else
			update_json ".dns_records" "$record_type" "$records"
		fi
	done
}

zone_transfer_check() {
	local domain="$1" verbose="$2"
	local ns_servers ns axfr

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== Zone Transfer (AXFR) ===${RESET}"
	fi

	ns_servers=($(dig "$domain" NS +short 2>/dev/null))

	for ns in $ns_servers; do
		if [[ "$verbose" == "true" ]]; then
			print "Attempting zone transfer with name server: $ns"
		fi

		axfr=$(dig axfr "$domain" @"$ns" +short +time=5 2>&1)
		axfr=$(escape_json_string "$axfr")

		if [[ -z "$axfr" ]]; then
			update_json ".zone_transfer" "$ns" "null"
		else
			update_json ".zone_transfer" "$ns" "$axfr"
		fi
	done
}

reverse_dns_lookup() {
	local domain="$1" verbose="$2"
	local ips ip ptr

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== Reverse DNS Lookup (PTR) ===${RESET}"
	fi

	ips=($(dig "$domain" A +short 2>/dev/null))

	for ip in $ips; do
		if [[ "$verbose" == "true" ]]; then
			print "Performing reverse DNS lookup for IP: $ip"
		fi

		ptr=$(dig -x "$ip" +short 2>&1)
		ptr=$(escape_json_string "$ptr")

		if [[ -z "$ptr" ]]; then
			update_json ".reverse_dns" "$ip" "null"
		else
			update_json ".reverse_dns" "$ip" "$ptr"
		fi
	done
}

enumerate_subdomains() {
	local domain="$1" wordlist="$2" verbose="$3"
	local subdomain full_domain ip

	if [[ -z "$wordlist" ]]; then
		print "Subdomain enumeration skipped (no wordlist provided)."
		return 0
	fi

	if [[ ! -f "$wordlist" ]]; then
		print "${RED}Error: Wordlist file not found: $wordlist${RESET}"
		return 1
	fi

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== Subdomain Enumeration ===${RESET}"
	fi

	while read -r subdomain; do
		full_domain="$subdomain.$domain"
		if [[ "$verbose" == "true" ]]; then
			print "Testing subdomain: $full_domain"
		fi

		ip=$(dig "$full_domain" A +short 2>&1)
		ip=$(escape_json_string "$ip")

		if [[ -z "$ip" ]]; then
			update_json ".subdomains" "$full_domain" "null"
		else
			update_json ".subdomains" "$full_domain" "$ip"
		fi
	done < "$wordlist"
}

email_security_analysis() {
	local domain="$1" dkim_selector="$2" verbose="$3"
	local spf dmarc_domain dmarc dkim_domain dkim

	if [[ "$verbose" == "true" ]]; then
		print "${YELLOW}=== Email Security Analysis (SPF, DKIM, DMARC) ===${RESET}"
	fi

    # Check SPF
    if [[ "$verbose" == "true" ]]; then
	    print "Checking SPF record for domain: $domain"
    fi
    spf=$(dig "$domain" TXT +short 2>/dev/null | grep "v=spf1" || true)
    spf=$(escape_json_string "$spf")
    if [[ -z "$spf" ]]; then
	    update_json ".email_security" "spf" "null"
    else
	    update_json ".email_security" "spf" "$spf"
    fi

    # Check DMARC
    dmarc_domain="_dmarc.$domain"
    if [[ "$verbose" == "true" ]]; then
	    print "Checking DMARC record for domain: $dmarc_domain"
    fi
    dmarc=$(dig "$dmarc_domain" TXT +short 2>/dev/null | grep "v=DMARC1" || true)
    dmarc=$(escape_json_string "$dmarc")
    if [[ -z "$dmarc" ]]; then
	    update_json ".email_security" "dmarc" "null"
    else
	    update_json ".email_security" "dmarc" "$dmarc"
    fi

    # Check DKIM
    if [[ -n "$dkim_selector" ]]; then
	    dkim_domain="${dkim_selector}._domainkey.$domain"
	    if [[ "$verbose" == "true" ]]; then
		    print "Checking DKIM record for selector: $dkim_selector (domain: $dkim_domain)"
	    fi
	    dkim=$(dig "$dkim_domain" TXT +short 2>&1)
	    dkim=$(escape_json_string "$dkim")
	    if [[ -z "$dkim" ]]; then
		    update_json ".email_security" "dkim_$dkim_selector" "null"
	    else
		    update_json ".email_security" "dkim_$dkim_selector" "$dkim"
	    fi
    fi
}

generate_text_output() {
	local json_data="$1"
	local output=""
	local domain=$(jq -r '.domain' <<< "$json_data")
	local use_colors=${2:-1}  # Default to using colors (1), set to 0 to disable

    # Helper function to conditionally add colors
    colorize() {
	    local color_code="$1"
	    local text="$2"
	    [[ $use_colors -eq 1 ]] && echo -n "${color_code}${text}${RESET}" || echo -n "$text"
    }

    # Build output with actual newlines instead of \n
    output="${output}=== DNS Records for $domain ==="$'\n'
    jq -r '.dns_records | to_entries[] | "\(.key): \(.value)"' <<< "$json_data" | while read -r line; do
    output="${output}$(colorize "$YELLOW" "${line%%:*}"): ${line#*: }"$'\n'
done

output="${output}"$'\n'"=== Zone Transfer Results ==="$'\n'
jq -r '.zone_transfer | to_entries[] | "\(.key): \(.value)"' <<< "$json_data" | while read -r line; do
output="${output}${line%%:*}: ${line#*: }"$'\n'
done

output="${output}"$'\n'"=== Reverse DNS Results ==="$'\n'
jq -r '.reverse_dns | to_entries[] | "\(.key): \(.value)"' <<< "$json_data" | while read -r line; do
output="${output}$(colorize "$YELLOW" "${line%%:*}"): ${line#*: }"$'\n'
done

if jq -e '.subdomains | length > 0' <<< "$json_data" >/dev/null; then
	output="${output}"$'\n'"=== Subdomain Results ==="$'\n'
	jq -r '.subdomains | to_entries[] | "\(.key): \(.value)"' <<< "$json_data" | while read -r line; do
	output="${output}$(colorize "$YELLOW" "${line%%:*}"): ${line#*: }"$'\n'
done
fi

output="${output}"$'\n'"=== Email Security Results ==="$'\n'
jq -r '.email_security | to_entries[] | "\(.key): \(.value)"' <<< "$json_data" | while read -r line; do
output="${output}$(colorize "$YELLOW" "${line%%:*}"): ${line#*: }"$'\n'
done

    # Print the output (without interpretation, since we used actual newlines)
    print -r -- "$output"
}

main() {
	local verbose=false output_file="" wordlist="" json_output=false domain="" dkim_selector=""
	local -A opts

	zmodload zsh/zutil
	zparseopts -D -E -A opts h v o: w: j d: k:

	if (( ${+opts[-h]} )); then
		usage
		return 0
	fi

	if (( ${+opts[-v]} )); then
		verbose=true
	fi

	output_file=${opts[-o]:-}
	wordlist=${opts[-w]:-}

	if (( ${+opts[-j]} )); then
		json_output=true
	fi

	domain=${opts[-d]:-}
	dkim_selector=${opts[-k]:-}

	if [[ -z "$domain" ]]; then
		print "${RED}Error: Domain is required (-d).${RESET}"
		usage
		return 1
	fi

	if ! dig "$domain" A +short > /dev/null 2>&1; then
		print "${RED}Error: Unable to resolve domain '$domain'.${RESET}"
		return 1
	fi

	if $json_output && [[ -z "$output_file" ]]; then
		print "${RED}Error: JSON output requires an output file (-o).${RESET}"
		usage
		return 1
	fi

	print "${WHITE}Checking DNS records for domain: $domain${RESET}"
	if [[ "$verbose" == "true" ]]; then
		print "Verbose mode enabled. Detailed logs will be displayed."
	fi

    # Initialize JSON structure
    init_json "$domain"

    query_dns_records "$domain" "$verbose"
    zone_transfer_check "$domain" "$verbose"
    reverse_dns_lookup "$domain" "$verbose"
    enumerate_subdomains "$domain" "$wordlist" "$verbose"
    email_security_analysis "$domain" "$dkim_selector" "$verbose"

    if $json_output; then
	    if [[ -n "$output_file" ]]; then
		    jq . <<< "$JSON_DATA" > "$output_file"
		    print "${GREEN}DNS records saved to $output_file in JSON format${RESET}"
	    else
		    jq . <<< "$JSON_DATA"
	    fi
    else
	    local use_colors=1
	    [[ -n "$output_file" ]] && use_colors=0
	    output=$(generate_text_output "$JSON_DATA" "$use_colors" | sed 's/\x1B\[[0-9;]*[JKmsu]//g')
	    if [[ -n "$output_file" ]]; then
		    print -r -- "$output" > "$output_file"
		    print "${GREEN}DNS records saved to $output_file${RESET}"
	    else
		    print -r -- "$output"
	    fi
    fi
    # Clean up
    rm -f "$JSON_TEMP_FILE"
}

main "$@"
