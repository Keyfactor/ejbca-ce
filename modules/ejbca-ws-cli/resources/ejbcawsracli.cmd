@echo off

set a=%1
set b=%2
set c=%3
set d=%4
set e=%5
set f=%6
set g=%7
set h=%8
set i=%9
shift
set j=%9
shift
set k=%9
shift
set l=%9
shift
set m=%9
shift
set n=%9
shift
set o=%9
shift
set p=%9
shift
set q=%9
shift
set r=%9

java -Djava.endorsed.dirs=lib/endorsed -jar ejbca-ws-cli.jar %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% %k% %l% %m% %n% %o% %p% %q% %r%