#!/bin/bash

if [ "$DEBUG" == "true" ] ; then
    set -x
fi

# Setup the UID the container runs as to be named 'jenkins' (purely for niceness)
if ! whoami &> /dev/null; then
  if [ -w /etc/passwd ]; then
    echo "jenkins:x:$(id -u):0:jenkins user:/opt:/sbin/nologin" >> /etc/passwd
  fi
fi
echo "Current user '$(whoami)' belongs to group(s): $(groups)"

reportFile="report-pmd.xml"

antCommonParameters="-q -Dappserver.home=/tmp -Dappserver.type=jboss -Dappserver.subtype=jbosseap6 -Dejbca.productionmode=false"
antCommonParameters="$antCommonParameters"

# Calculate the number of available cores
cpuPeriod=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
cpuQouta=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
cpuTotal=$(cat /proc/cpuinfo | grep ^processor | wc -l)
if [ ${cpuQouta:-0} -ne -1 ]; then
  coreLimit=$((cpuQouta/cpuPeriod))
else
  coreLimit=$cpuTotal
fi
echo "Detected $coreLimit available cores."

if [ "$DEBUG" == "true" ] ; then
    echo "
### Show PMD help (to help with future improvements of this scan) ###
"
/opt/pmd/bin/run.sh pmd -h
fi

echo "
### Running PMD ###
"
if [ "$DEBUG" == "true" ] ; then
    debugOption="-verbose"
fi

cd ejbca/

# Generate a temporary list of sources matching modules/**/*.java relative to EJBCA directory
find modules/ -name *.java | tr '\n' ',' > all-java-files.txt

# Run analysis
time /opt/pmd/bin/run.sh pmd $debugOption -t $coreLimit -no-cache -f xml -encoding UTF-8 -reportfile "${reportFile}" -filelist all-java-files.txt \
    -language java -rulesets $(pwd)/../code-analyzer-tools/pmd/rulesets/ruleset.xml --failOnViolation false -minimumpriority 4

# Remove temporary list of sources
rm ./all-java-files.txt
cd ..

echo "
### Done! ###
"
violations=$(grep "<violation" "$(realpath ejbca/${reportFile})" | wc -l)
reportSize="$(du -h ejbca/${reportFile} | sed 's/\t.*//')"
echo "Report with ${violations} violations is available in $(realpath ejbca/${reportFile}) [${reportSize}]"
