rem Starting ctb using a Windows .BAT file
rem change line below to suit your setup
set TOOLBOX_HOME=".\clientToolBox-dist"
set CLASSES=%TOOLBOX_HOME%\clientToolBox.jar

rem Fixup arguments, we have to do this since windows normally only 
rem supports %1-%9 as command line arguments
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
rem echo %a% %b% %c% %d% %e% %f% %g% %h% %i% %j%

java -Djava.endorsed.dirs=%TOOLBOX_HOME%/endorse;%TOOLBOX_HOME%/lib -cp %CLASSES% org.ejbca.ui.cli.ClientToolBox %a% %b% %c% %d% %e% %f% %g% %h% %i% %j%
