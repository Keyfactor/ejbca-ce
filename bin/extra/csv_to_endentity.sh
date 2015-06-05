#!/bin/bash
#
# csv_to_endentity.sh
#
# Copyright (C) 2013, PrimeKey Solutions AB
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

program="csv_to_endentity.sh"
version="0.1"

function usage() {
    cat <<EOF
$program $version, a non-interactive utility for importing end entity
information from a CSV file into EJBCA

Usage: $program [OPTIONS] csv_file

$program is a non-interactive utility for importing end entity information from
a CSV file into EJBCA. The utility will create end entities in EJBCA using a
combination of static values and data read from CSV file. The expected format of
the CSV file is:

name,cn,ip

Blank lines in the file will be ignored.

The "name" field will be used as username for the end entity created in
EJBCA. The "cn" field refers to common name that will be used as part of forming
the subject DN for end entity. The "ip" field is used for specifying the IP
address subject alternative name of the end entity.

The following values are hard-coded when adding a new end entity:

- Subject DN suffix (appended to the CN to consturct the subject DN).
- Password.
- E-mail.
- Token type.
- Certificate profile.
- End entity profile.
- CA name.

Utility must be run from within EJBCA's base directory (for example
/opt/ejbca/).


$program accepts the following options:

    -v        show script version and licensing information
    -h        show usage help


Please report bugs and send feature requests to <branko.majic@primekey.se>.
EOF
}

function version() {
        cat <<EOF
$program, version $version

+-----------------------------------------------------------------------+
| Copyright (C) 2013, PrimeKey Solutions AB                             |
|                                                                       |
| This library is free software; you can redistribute it and/or         |
| modify it under the terms of the GNU Lesser General Public            |
| License as published by the Free Software Foundation; either          |
| version 2.1 of the License, or (at your option) any later version.    |
|                                                                       |
| This library is distributed in the hope that it will be useful,       |
| but WITHOUT ANY WARRANTY; without even the implied warranty of        |
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     |
| Lesser General Public License for more details.                       |
|                                                                       |
| You should have received a copy of the GNU General Public License     |
| along with this program.  If not, see <http://www.gnu.org/licenses/>. |
+-----------------------------------------------------------------------+

EOF
}

# If no arguments were given, just show usage help.
if [[ -z $1 ]]; then
    usage
    exit 0
fi

# Parse the arguments
while getopts "vh" opt; do
    case "$opt" in
        v) version
           exit 0;;
        h) usage
           exit 0;;
        *) usage
           exit 1;;
    esac
done
i=$OPTIND
shift $(($i-1))

# Set-up default values for adding the end entity.
dnSuffix="O=Sample,C=SE"
password="password"
mail="null"
tokenType="PEM"
certificateProfile="ENDUSER"
endentityProfile="EMPTY"
caName="ManagementCA"

# Read the positional arguments.
csvFile="$1"

# Verify arguments.
if [[ ! -f "$csvFile" ]]; then
    echo "No such file '$csvFile'." >&2
    exit 2
fi

# Verify that the working directory is EJBCA home.
if [[ ! -f "bin/ejbca.sh" ]]; then
    echo "Could not locate EJBCA CLI from within current directory." >&2
    echo "Are you sure that the current working directory is EJBCA home directory?" >&2
    exit 2
fi

# Read the CSV line-by-line
while read line; do
    # Verify that line has proper format (in terms of field count).
    if [[ ! $line =~ ^[^,]*,[^,]*,[^,]*$ ]]; then
        echo "Improperly formatted CSV line was detected in file '$csvFile':" >&2
        echo "$line" >&2
        echo "Aborting execution." >&2
        exit 10
    fi

    # Parse the line. If the echo had been piping into the read command, it
    # would've caused it to fork-off another shell subprocess, and read
    # variables wouldn't be available in current shell process. That's why the
    # unusual syntax is used instead. See:
    # http://mywiki.wooledge.org/BashFAQ/024
    IFS="," read name cn ip < <(echo "$line")
    
    # Construct some of the derived parameters.
    dn="CN=${cn},${dnSuffix}"
    # Set-up EJBCA command that should be executed.
    command=("bin/ejbca.sh" "ra" "addendentity")
    # Set-up username/password parameters.
    command+=("$name" "$password")
    # Set-up subject/alt names parameters.
    command+=("$dn" "ipaddress=$ip")
    # Set-up CA name, e-mail, user type, token type parameters.
    command+=("$caName" "$mail" "1" "$tokenType")
    # Set-up certificate and end entity profile that should be used.
    command+=("$certificateProfile" "$endentityProfile")

    # Run the command and capture the output.
    output=$("${command[@]}" 2>&1)

    # Print-out the information messages, otherwise assume it was an error.
    if ! echo "$output" | grep -E "(User '$name' already exists in the database.|User '$name' has been added.)"; then
        echo "Failed to add user '$name' to EJBCA." >&2
        echo "Attempted command was:" >&2
        for param in "${command[@]}"; do
            echo -n "'$param' " >&2
        done
        echo >&2
        echo "Output from command was:" >&2
        echo "$output" >&2
        echo "Aborting execution." >&2
        exit 15
    fi
done < <(grep -v "^[[:blank:]]*$" "$csvFile")

echo
echo "Import of EJBCA end entities from file '$csvFile' completed without errors."

