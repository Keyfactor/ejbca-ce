@echo off

set CP=.;.\admin.jar;.\lib\log4j-1.2.7.jar;.\lib\batik-css.jar;.\lib\batik-dom.jar;.\lib\batik-ext.jar;.\lib\batik-parser.jar;.\lib\batik-svg-dom.jar;.\lib\batik-svggen.jar;.\lib\batik-transcoder.jar;.\lib\batik-util.jar;.\lib\batik-xml.jar;.\lib\xerces_2_3_0.jar;.\lib\ldap.jar;.\lib\batik-bridge.jar;.\lib\batik-script.jar;.\lib\batik-gvt.jar;.\lib\batik-awt-util.jar

java -cp %CP% se.anatom.ejbca.admin.SVGTemplatePrinter %*

