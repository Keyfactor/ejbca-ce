rem Starting ctb using a Windows .BAT file
rem change line below to suit your setup
set TOOLBOX_HOME="C:\Documents and Settings\Anders\workspace\ejbca\clientToolBox-dist"
set CLASSES=%TOOLBOX_HOME%\clientToolBox.jar
java -Djava.endorsed.dirs=%TOOLBOX_HOME%/endorse;%TOOLBOX_HOME%/lib -cp %CLASSES% org.ejbca.ui.cli.ClientToolBox %1 %2 %3 %4 %5 %6 %7 %8 %9
