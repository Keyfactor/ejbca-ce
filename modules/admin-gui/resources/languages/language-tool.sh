#!/bin/bash

### Language tool for EJBCA (Admin GUI)
#
# Filename:    language-tool.sh
# Version:     1.1, 2012-06-01
# Script:      Bash script
# Require:     EJBCA 4.0.x
# Contributor: David CARELLA, david.carella [AT] gmail.com


### INITIALIZATION

## Constants

PROGRAM=$(basename "$0")
VERSION="1.1"

#- EJBCA folders
SVN_ROOT="../../../.."		# Script path = modules/admin-gui/resources/languages/
PATH_ADMINGUI_RES="modules/admin-gui/resources"		# Files: JSP, JSPF, JSF
PATH_ADMINGUI_SRC="modules/admin-gui/src"			# Files: Java
PATH_CONFIG="conf"									# Files: Properties
PATH_JAVA_CESECORE="src/java/org/cesecore"			# Files: Java
PATH_JAVA_EJBCA="src/java/org/ejbca"				# Files: Java
PATH_JAVA="src/java"								# Files: Properties
#- EJBCA folders [INFO]
#  $SVN_ROOT/$PATH_ADMINGUI_RES/languages/
#  $SVN_ROOT/$PATH_ADMINGUI_RES/
#  $SVN_ROOT/$PATH_ADMINGUI_SRC/
#  $SVN_ROOT/$PATH_CONFIG/
#  $SVN_ROOT/$PATH_JAVA_CESECORE/
#  $SVN_ROOT/$PATH_JAVA_EJBCA/
#  $SVN_ROOT/$PATH_JAVA/

#- EJBCA version (only numbers and dots)
EJBCA_VERSION=$(cat $SVN_ROOT/src/internal.properties | grep "app.version.number=" | sed -e "s/^.*=\([0-9.]*\).*/\1/")

#- Language
LANG_PREFIX="languagefile"
LANG_EXT="properties"
LANG_REF="en"
FILENAME_REF=$LANG_PREFIX"."$LANG_REF"."$LANG_EXT


## Variables

status=0
action=""
lang=""
format=""
filename=$FILENAME_REF


## Header : Script name and version

echo "Language tool for EJBCA ($EJBCA_VERSION), ${PROGRAM}, v${VERSION}"
echo



### FUNCTIONS

## Function print_help()

print_help ( ) (
	echo "Usage: ${PROGRAM} [-h] [-a|-u|-s] [-l <LANG>] [-e csv|xdoc|doku]"
	echo "Usage: ${PROGRAM} [-h] [-f|-c] -k <KEY>"
	echo "Usage: ${PROGRAM} [-h] [-p]"
	echo "    -a: all message keys in <LANG> file."
	echo "    -u: unused message keys in <LANG> file."
#	echo "    -r: repeated message keys in <LANG> file."				## Future: TO IMPLEMENT
#	echo "    -d: difference between <LANG> file and English file."		## Future: TO IMPLEMENT (like check-trad.pl)
	echo "    -s: statistics of message keys (in <LANG> file only, if present)."
	echo "    -f: find message key <KEY> (in source and language files)."
	echo "    -c: count message key <KEY> (in source files)."
	echo "    -p: parsed source files [internal technical info]."
	echo "    -l <LANG>: language code [default: $LANG_REF]."
	echo "    -e <FORMAT>: export format (CSV, XDoc, DokuWiki) [default: Text]."
	echo "    -k <KEY>: message key."
	echo "    -h: this help."
	echo
	echo "Examples:"
	echo "    ${PROGRAM}"
	echo "    ${PROGRAM} -a"
	echo "    ${PROGRAM} -u"
	echo "    ${PROGRAM} -u -l fr"
	echo "    ${PROGRAM} -s"
	echo "    ${PROGRAM} -s -e csv"
	echo "    ${PROGRAM} -f -k CERT_SUBJECTDN"
	echo "    ${PROGRAM} -c -k CERT_SUBJECTDN"
	echo "    ${PROGRAM} -p"
	echo
)



### ARGUMENTS PARSING

if [ "$1" == "" ]; then
	print_help
	exit 1
fi


## Options parsing

while getopts "hausl:e:fck:p" flag
do 
	case "$flag" in 

	h)
		print_help
		exit 1
		;;

#-- Language file

	a)
		action="all"
		;;
	u)
		action="unused"
		;;
	s)
		action="stats"
		;;
	l)
		lang=$OPTARG
		filename=$LANG_PREFIX"."$lang"."$LANG_EXT
		;;
	e)
		format=$OPTARG
		;;

#-- Message key

	f)
		action="find"
		;;
	c)
		action="count"
		;;
	k)
		keysearch=$OPTARG
		;;

#-- Source files

	p)
		action="parsed"
		;;

#-- Error

	*)
		echo "Usage: ${PROGRAM} [-h] [-a|-u|-s] [-l <LANG>] [-e <FORMAT>] [-f|-c] [-k <KEY>] [-p]"
		echo "Help: ${PROGRAM} -h"
		echo
		exit 4
		;;

	esac
done


## Parameters verifying

case "$action" in

#-- Language file

	"all" | "unused" | "stats")
		## Test if filename exists
		if [ ! -f $filename ]; then
			echo "Error: File not found ($filename)."
			echo
			exit 4
		fi
		;;

#-- Message key

	"find" | "count")
		## Test if keysearch is set
		if [ -z "$keysearch" ]; then
			echo "Error: Key is null or empty (use -k <KEY>)."
			echo
			exit 4
		fi
		## Test if keysearch length >= 2
		if [ "${#keysearch}" -lt "2" ]; then
			echo "Error: Key string length must be 2 characters or more."
			echo
			exit 4
		fi
		;;

#-- Source files
	"parsed")
		## Nothing to test
		;;

#-- Error

	*) echo "Error: Unknown action ('$action')."; echo; exit 1 ;;

esac



### EXECUTION

## INIT Variables

	## Horizontal rule (wide as terminal width)
	hr=$(eval printf '%.s-' {1..$(tput cols)})

#- Note: Comments about 'PATTERNS' describe the regexp strings
#        (between two '|' in comments) that will be search.


## Processing

case "$action" in


#-- Language file

	"all")
		echo "Filename: $filename"

		echo
		echo "All message keys:"
		echo "$hr"

		## Extract and display all message keys
		cat $filename | sed -e "/^[^=]*$/d" -e "/^#.*/d" -e "s/[ \t=].*$//"
		## Count all message keys, i.e. all lines with '=' and without '#' (comment)
		keycount=$(cat $filename | sed -e "/^[^=]*$/d" -e "/^#.*/d" | wc -l)

		echo "$hr"
		echo "Count = $keycount message keys  (in $filename)"

		;;



	"unused")
		echo "Filename: $filename"

	## INIT Variables
		keycount=0

		echo
		echo "Unused message keys:"
		echo "$hr"

		## Read each message keys in filename, then search them in source files
		for key in $(cat $filename | sed -e "/^[^=]*$/d" -e "/^#.*/d" -e "s/[ \t=].*$//")
		do

		## ADMIN-GUI > RESOURCES (JSP, JSPF, JSF)

		#-- PATTERNS = |"KEY"|, |\"KEY\"|, |'KEY'|, |\'KEY\'|
			count=$(grep -l -e "[\"']"$key"[\"'\]" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		#-- PATTERNS = |{web.text.KEY}|
			count=$(grep -l -e "{web.text.$key}" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		## ADMIN-GUI > SRC (Java)

		#-- PATTERNS = |"KEY"|, |'KEY'|
			count=$(grep -l -e "[\"']"$key"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		## CONF

		#-- PATTERNS = | KEY|, | KEY |, |=KEY|, |=KEY |
			count=$(grep -l -e "[ \t=]"$key"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		## SRC > JAVA (CESecore, EJBCA, properties)

		#-- PATTERNS = |"KEY"|, |'KEY'|
			count=$(grep -l -e "[\"']"$key"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi
			count=$(grep -l -e "[\"']"$key"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		#-- PATTERNS = |;KEY;|, |,KEY,|, |;KEY|, |,KEY|, |= KEY|, etc.
			count=$(grep -l -e "[;,][ \t]*"$key"[ \t]*[;,]" -e "[;,=][ \t]*"$key"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | wc -l)
			if [ $count -gt 0 ]; then
				continue
			fi

		##  KEY NOT FOUND
			echo "$key"
			let "keycount++"

		done

		echo "$hr"
		echo "Count = $keycount unused message keys  (in $filename)"

		;;



	"stats")
		echo "Reference: $FILENAME_REF"

	## INIT Variables

		## List all language files, then remove the virtual language 'zz'
		filelist=$(echo *.$LANG_EXT | sed -e "s/"$LANG_PREFIX".zz."$LANG_EXT"//")
		if [ "$lang" != "" ]; then
			filelist=$filename
		fi
		## Count all language files
		filecount=$(echo $filelist | wc -w)
		## Count all message keys of the reference language file
		refcount=$(cat $FILENAME_REF | sed -e "/^[^=]*$/d" -e "/^#.*/d" | wc -l)

		echo
		echo "Message key statistics:"
		echo

	## TABLE > HEADER
		case "$format" in 
		"csv")		# CSV format (Comma-separated values)
			echo "Syntax: CSV format"
			echo "$hr"
			echo "Language;Filename;Key count;Completed (%)"
			;;
		"xdoc")		# XDoc code (XML document)
			echo "Syntax: XDoc code"
			echo "$hr"
			echo '<section name="Language file statistics">'
			echo '<table>'
			echo '<tr><th>Language</th><th>Filename</th><th>Key count</th><th>Completed (%)</th></tr>'
			;;
		"doku")		# DokuWiki code
			echo "Syntax: DokuWiki code"
			echo "$hr"
			echo "===== Language file statistics ====="
			echo "^  Language  ^ Filename  ^  Key count  ^  Completed (%)  ^"
			;;
		*)			# Text (terminal)
			## Table constants (column width, spaces, horizontal rule)
			col1=8
			col2=31
			col3=11
			col4=9
			spaces100=$(printf '%.s ' {1..100})
			hr_table=$(eval printf '%.s-' {1..$(($col1+$col2+$col3+$col4))})
			## Header appending
			col1_title="Lang."$spaces100
			col2_title="Filename"$spaces100
			col3_title="Key count"$spaces100
			col4_title="Completed"$spaces100
			## Header cutting
			col1_title=${col1_title:0:$col1}	# Left align
			col2_title=${col2_title:0:$col2}	# Left align
			col3_title=${col3_title:0:$col3}	# Left align
			col4_title=${col4_title:0:$col4}	# Left align
			## Header displaying
			echo "$col1_title$col2_title$col3_title$col4_title"
			echo "$hr_table"
			;;
		esac

		## Read each language files, then count message keys
		for filename in $filelist
		do

			## Extract the language code from current language file name
			lang=$(echo "$filename" | sed -e "s/"$LANG_PREFIX"\.\(.*\)\."$LANG_EXT"/\1/")
			## Count all message keys of the current language file 'filename'
			keycount=$(cat $filename | sed -e "/^[^=]*$/d" -e "/^#.*/d" | wc -l)
			## Compute the completion rate of the current language file
			progress=$(echo "scale=1; 100*$keycount/$refcount" | bc)

		## TABLE > BODY
			case "$format" in 
			"csv")		# CSV format (Comma-separated values)
				echo "$lang;$filename;$keycount;$progress %"
				;;
			"xdoc")		# XDoc code (XML document)
				echo '<tr><td align="center"><strong>'$lang'</strong></td><td><big><code>'$filename'</code></big></td><td align="center">'$keycount'</td><td align="center">'$progress' %</td></tr>'
				;;
			"doku")		# DokuWiki code
				echo "|  **$lang**  | ''$filename''  |  $keycount  |  $progress %  |"
				;;
			*)			# Text (terminal)
				## Cell appending
				col1_data=" ""$lang"$spaces100
				col2_data="$filename"$spaces100
				col3_data=$spaces100"$keycount keys""  "
				col4_data=$spaces100"$progress %"" "
				## Cell cutting
				col1_data=${col1_data:0:$col1}							# Left align
				col2_data=${col2_data:0:$col2}							# Left align
				col3_data=${col3_data:$((${#col3_data}-$col3)):$col3}	# Right align
				col4_data=${col4_data:$((${#col4_data}-$col4)):$col4}	# Right align
				## Cell displaying
				echo "$col1_data$col2_data$col3_data$col4_data"
				;;
			esac

		done

	## TABLE > FOOTER
		case "$format" in 
		"csv")		# CSV format (Comma-separated values)
			echo "$hr"
			echo "Count = $filecount language files (Admin GUI)"
			;;
		"xdoc")		# XDoc code (XML document)
			echo '</table>'
			echo '<p>Reference: <big><code>'$FILENAME_REF'</code></big><br/>'
			echo 'Count: <strong>'$filecount' language files</strong> (Admin GUI)<br/>'
			echo 'Date: '$(date +%F)' (EJBCA '$EJBCA_VERSION')</p>'
			echo '</section>'
			echo "$hr"
			;;
		"doku")		# DokuWiki code
			echo "Reference: ''$FILENAME_REF''\\\\"
			echo "Count: **$filecount language files** (Admin GUI)\\\\"
			echo "Date: $(date +%F) (EJBCA $EJBCA_VERSION)"
			echo "$hr"
			;;
		*)			# Text (terminal)
			## Footer displaying
			echo "$hr_table"
			echo "Count = $filecount language files (Admin GUI)"
			echo "Date: $(date +%F) (EJBCA $EJBCA_VERSION)"
			;;
		esac

		;;



#-- Message key

	"find")
		echo "Message key: $keysearch"

	## INIT Variables
		filecount=0

		echo
		echo "Source files that contains '$keysearch':"

	## ADMIN-GUI > RESOURCES (JSP, JSPF, JSF)

	#-- PATTERNS = |"KEY"|, |\"KEY\"|, |'KEY'|, |\'KEY\'|
		grep -l -e "[\"']"$keysearch"[\"'\]" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[\"']"$keysearch"[\"'\]" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "filecount+=count"

	#-- PATTERNS = |{web.text.KEY}|
		grep -l -e "{web.text.$keysearch}" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "{web.text.$keysearch}" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "filecount+=count"

	## ADMIN-GUI > SRC (Java)

	#-- PATTERNS = |"KEY"|, |'KEY'|
		grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | wc -l)
		let "filecount+=count"

	## CONF

	#-- PATTERNS = | KEY|, | KEY |, |=KEY|, |=KEY |
		grep -l -e "[ \t=]"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[ \t=]"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | wc -l)
		let "filecount+=count"

	## SRC > JAVA (CESecore, EJBCA, properties)

	#-- PATTERNS = |"KEY"|, |'KEY'|
		grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | wc -l)
		let "filecount+=count"
		grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | wc -l)
		let "filecount+=count"

	#-- PATTERNS = |;KEY;|, |,KEY,|, |;KEY|, |,KEY|, |= KEY|, etc.
		grep -l -e "[;,][ \t]*"$keysearch"[ \t]*[;,]" -e "[;,=][ \t]*"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "[;,][ \t]*"$keysearch"[ \t]*[;,]" -e "[;,=][ \t]*"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | wc -l)
		let "filecount+=count"

		echo "Count = $filecount source files"

	## INIT Variables
		filecount=0
		echo
		echo "Language files that contains '$keysearch':"

	## ADMIN-GUI > RESOURCES > LANGUAGES

	#-- PATTERNS = |"KEY"|, |\"KEY\"|, |'KEY'|, |\'KEY\'|
		grep -l -e "^"$keysearch"[ \t=].*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/languages/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "^"$keysearch"[ \t=].*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/languages/ | wc -l)
		let "filecount+=count"

		echo "Count = $filecount language files"

		;;



	"count")
		echo "Message key: $keysearch"

	## INIT Variables
		filecount=0
		keycount=0

		echo
		echo "Message key occurrences of '$keysearch':"

	## ADMIN-GUI > RESOURCES (JSP, JSPF, JSF)

	#-- PATTERNS = |"KEY"|, |\"KEY\"|, |'KEY'|, |\'KEY\'|
		count=$(grep -l -e "[\"']"$keysearch"[\"'\]" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[\"']"$keysearch"[\"'\]" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "keycount+=count"

	#-- PATTERNS = |{web.text.KEY}|
		count=$(grep -l -e "{web.text.$keysearch}" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "{web.text.$keysearch}" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "keycount+=count"

	## ADMIN-GUI > SRC (Java)

	#-- PATTERNS = |"KEY"|, |'KEY'|
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | wc -l)
		let "keycount+=count"

	## CONF

	#-- PATTERNS = | KEY|, | KEY |, |=KEY|, |=KEY |
		count=$(grep -l -e "[ \t=]"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[ \t=]"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | wc -l)
		let "keycount+=count"

	## SRC > JAVA (CESecore, EJBCA, properties)

	#-- PATTERNS = |"KEY"|, |'KEY'|
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | wc -l)
		let "keycount+=count"
		count=$(grep -l -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[\"']"$keysearch"[\"']" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | wc -l)
		let "keycount+=count"

	#-- PATTERNS = |;KEY;|, |,KEY,|, |;KEY|, |,KEY|, |= KEY|, etc.
		count=$(grep -l -e "[;,][ \t]*"$keysearch"[ \t]*[;,]" -e "[;,=][ \t]*"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | wc -l)
		let "filecount+=count"
		count=$(grep -e "[;,][ \t]*"$keysearch"[ \t]*[;,]" -e "[;,=][ \t]*"$keysearch"[ \t]*$" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | wc -l)
		let "keycount+=count"

		echo "Count = $keycount key occurences in $filecount source files"

		;;



#-- Source files

	"parsed")
		echo "EJBCA source: EJBCA $EJBCA_VERSION ($(date +%F))"

	## INIT Variables
		filecount=0

		echo
		echo "Parsed source files:"
		echo "$hr"

	## ADMIN-GUI > RESOURCES (JSP, JSPF, JSF)

	#-- PATTERNS = ||
		grep -l -e "" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.js* --exclude=*.js -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_RES/ | wc -l)
		let "filecount+=count"

	## ADMIN-GUI > SRC (Java)

	#-- PATTERNS = ||
		grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_ADMINGUI_SRC/ | wc -l)
		let "filecount+=count"

	## CONF

	#-- PATTERNS = ||
		grep -l -e "" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_CONFIG/ | wc -l)
		let "filecount+=count"

	## SRC > JAVA (CESecore, EJBCA, properties)

	#-- PATTERNS = ||
		grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_CESECORE/ | wc -l)
		let "filecount+=count"
		grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.java -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA_EJBCA/ | wc -l)
		let "filecount+=count"

	#-- PATTERNS = ||
		grep -l -e "" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | sed -e "s/\.\.\///g"
		count=$(grep -l -e "" --include=*.properties -r --exclude-dir=.svn $SVN_ROOT/$PATH_JAVA/ | wc -l)
		let "filecount+=count"

		echo "$hr"
		echo "Count = $filecount parsed source files"

		;;


esac


## Warning displaying

case "$action" in

#-- Language file

	"all")
		## No warning to display
		;;

	"unused")
		echo
		echo "Warning: DON'T REMOVE ALL UNUSED KEYS; it is probably normal that this count is not equal to zero, because some message keys exist for future use." | fmt -80
		echo
		echo "Important: before remove message keys, please:" | fmt -80
		if [ "$lang" != "" ]; then
			echo "- look at the unused keys in the English language file: ${PROGRAM} -u" | fmt -80
		fi
		echo "- search \"Clean up message keys\" in EJBCA issue tracker (e.g. ECA-2624)" | fmt -80
		echo "- for example, visite: https://jira.primekey.se/browse/ECA-2624" | fmt -80
		;;

	"stats")
		echo
		echo "Warning: all message keys are counted; thus, unused and duplicated message keys are not excluded." | fmt -80
		;;

#-- Message key

	"find" | "count")
		if [ "${#keysearch}" -le "2" ]; then
			echo
			echo "Warning: the key '$keysearch' with short length (${#keysearch} characters) may not be a message key. Check it in source files." | fmt -80
		fi
		;;

#-- Source files

	"parsed")
		## No warning to display
		;;

esac



### Exit

echo
exit $status


### EOF
