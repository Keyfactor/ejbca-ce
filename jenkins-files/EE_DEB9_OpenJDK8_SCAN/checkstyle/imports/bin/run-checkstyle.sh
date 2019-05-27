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
# Added some extra rules (these are inserted into the TreeWalker checker)
# - JavadocParagraphCheck: Checks that there is a <p> between Javadoc paragraphs (otherwise it won't appear correctly).
# - NoFinalizer: Finalizers are unreliable and should be avoided.
# - StringLiteralEquality: Comparing strings should not be done with == or != (TODO this should be reported at a higher severity).
# - UniqueProperties: Checks for duplicate properties. This can happen in language files for example.
# Changed some checks to low severity:
# - WhitespaceAfter|ParenPad|JavadocStyle|FileTabCharacter|MethodParamPad|NoWhitespaceBefore|NewlineAtEndOfFile|RightCurly|GenericWhitespace|TypecastParenPad - All are about whitespace or pure cosmetics
cat "${styleCheckRules}" \
    | sed 's/maximum" value="0/maximum" value="99/' \
    | sed -r 's/(<module name="RegexpSingleline">)/\1\n<property name="severity" value="ignore"\/>/' \
    | grep -vE 'LineLength|WhitespaceAround|FinalParameters|JavadocPackage|JavadocVariable|DesignForExtension|AvoidInlineConditionals' \
    | grep -vE 'AvoidNestedBlocks|ConstantName|EmptyBlock|InnerAssignment|InterfaceIsType|LeftCurly' \
    | grep -vE 'MethodName|MissingSwitchDefault|NoWhitespaceAfter|OperatorWrap|TodoComment|TypeName' \
    | sed -r 's/(<module name="VisibilityModifier")\/>/\1><property name="packageAllowed" value="true"\/><property name="protectedAllowed" value="true"\/><\/module>/' \
    | sed -r 's/(<module +name *= *"TreeWalker" *>)/\1\n<module name="JavadocParagraph"\/><module name="NoFinalizer"\/><module name="StringLiteralEquality"\/><module name="NestedIfDepth"><property name="max" value="3"\/><\/module>/' \
    | sed -r 's/(<module +name *= *"Checker" *>)/\1\n<module name="UniqueProperties"\/>/' \
    | sed -r 's/<module name="(WhitespaceAfter|ParenPad|JavadocStyle|FileTabCharacter|MethodParamPad|NoWhitespaceBefore|NewlineAtEndOfFile|RightCurly|GenericWhitespace|TypecastParenPad)"\/>/<module name="\1"><property name="severity" value="info"\/><\/module>/' \
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
    ejbca/modules/ src/samples/

echo "
### Done! ###
"
reportSize="$(du -h ejbca/${reportFile} | sed 's/\t.*//')"
echo "Report is available in $(realpath ejbca/${reportFile}) [${reportSize}]"
