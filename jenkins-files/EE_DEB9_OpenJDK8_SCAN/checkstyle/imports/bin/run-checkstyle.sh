#!/bin/bash

if [ "$DEBUG" = "true" ]; then
    set -x
fi

# Setup the UID the container runs as to be named 'jenkins' (purely for niceness)
if ! whoami &> /dev/null; then
  if [ -w /etc/passwd ]; then
    echo "jenkins:x:$(id -u):0:jenkins user:/opt:/sbin/nologin" >> /etc/passwd
  fi
fi
echo "Current user '$(whoami)' belongs to group(s): $(groups)"

reportFile="report-checkstyle.xml"

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

if [ "$DEBUG" = "true" ]; then
    echo "
### Show PMD help (to help with future improvements of this scan) ###
"
    java -jar /opt/checkstyle.jar --help
fi
echo "
### Running checkstyle ###
"
if [ "$DEBUG" = "true" ]; then
    debugOption="--debug"
fi

styleCheckRules="code-analyzer-tools/checkstyle/checks/sun_checks.xml"

# Redact rules that we definitely don't care about and makes the report to large to handle
# - LineLength: "Line is longer than 80 characters (found ...)."
# - RegexpSinglelineCheck: "Line has trailing spaces." -> There are too many such "errors" to cope with. Allow 99..
# - WhitespaceAround: Defacto not followed in EJBCA
# - FinalParameters: Nice to have, but too many errors.
# - JavadocPackage: Defacto not followed in EJBCA
# - JavadocVariable: Defacto not followed in EJBCA unless motivated.
# - DesignForExtension: Usually implicit when such extension is intended. Not everything needs to be designed for extension.
# - AvoidInlineConditionalsCheck: Not anything bad with this
# - AvoidNestedBlocksCheck: Not anything bad with this
# - ConstantNameCheck: Matches non-compile time constant fields also, such as "log", so too much spam
# - EmptyBlockCheck: Also matches empty blocks with a comment explaining why it is empty.
# - InnerAssignmentCheck: Useful code pattern sometimes.
# - InterfaceIsTypeCheck: Matches interfaces that lack methods, but that gives false positives with interfaces that describe a behavior only.
# - LeftCurlyCheck: Lots of false positives for getters and setters.
# - MethodNameCheck: Conflicts with EcaQa test case naming.
# - MissingSwitchDefaultCheck: This is actually a good coding practice, because then the compiler can check for missing enum cases.
# - NoWhitespaceAfterCheck: Contrary to our usual style for array initializers.
# - OperatorWrapCheck: Controversial topic, some find this less error prone other find it more error prone. Also contrary to most of the EJBCA code.
# - RegexpSinglelineCheck: False positives on indented blank lines, which in turn is controversial.
# - TodoCommentCheck: False positives with TODO comments that have an issue number.
# - TypeNameCheck: False positives with WS method names.
cat "${styleCheckRules}" \
    | sed 's/maximum" value="0/maximum" value="99/' \
    | grep -vE 'LineLength|WhitespaceAround|FinalParameters|JavadocPackage|JavadocVariable|DesignForExtension|AvoidInlineConditionalsCheck' \
    | grep -vE 'AvoidNestedBlocksCheck|ConstantNameCheck|EmptyBlockCheck|InnerAssignmentCheck|InterfaceIsTypeCheck|LeftCurlyCheck' \
    | grep -vE 'MethodNameCheck|MissingSwitchDefaultCheck|NoWhitespaceAfterCheck|OperatorWrapCheck|RegexpSinglelineCheck|TodoCommentCheck|TypeNameCheck' \
    > /tmp/checks.xml

if [ "$DEBUG" = "true" ]; then
    echo
    echo "Here is the checks.xml file:"
    cat /tmp/checks.xml
fi

# --checker-threads-number=$coreLimit -> "IllegalArgumentException: Multi thread mode for Checker module is not implemented"
# --exclude=ejbca/modules/cesecore-common/src-test/org/cesecore/util/SecureXMLDecoderTest.java \
time java ${JAVA_OPTS} -jar /opt/checkstyle.jar $debugOption \
    -c=/tmp/checks.xml -f=xml -o=ejbca/${reportFile} \
    --exclude-regexp=.+Test\.java$ \
    ejbca/modules/

echo "
### Done! ###
"
reportSize="$(du -h ejbca/${reportFile} | sed 's/\t.*//')"
echo "Report is available in $(realpath ejbca/${reportFile}) [${reportSize}]"
