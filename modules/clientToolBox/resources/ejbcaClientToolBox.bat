@echo off
SetLocal EnableDelayedExpansion 

rem Starting ctb using a Windows .BAT file
set TOOLBOX_HOME=%~dp0

rem Fixup arguments, we have to do this since windows normally only 
rem supports %1-%9 as command line arguments
FOR %%A IN (%*) DO (
    set args=!args! %%A
) 
rem echo %args%

if exist "%TOOLBOX_HOME%clientToolBox.jar" goto exists
	echo You have to build the ClientToolBox before running this command.
	goto end
:exists

rem @echo on
${javaCmd} ${JAVA_OPT} -cp "%TOOLBOX_HOME%clientToolBox.jar;%TOOLBOX_HOME%endorsed/*" org.ejbca.ui.cli.ClientToolBox "${@}"
