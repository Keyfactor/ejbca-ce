/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.admin.configuration;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletContext;

import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;


/**
 * An class interpreting the language properties files. I contains one method getText that returns
 * the presented text in the users preferred language.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class WebLanguages implements java.io.Serializable {
    private static final long serialVersionUID = -2381623760140383128L;

    private static final Logger log = Logger.getLogger(WebLanguages.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** Constructor used to load static content. An instance must be declared with this constructor before
     *  any WebLanguage object can be used. */
    /** Special constructor used by Ejbca web bean */
    private void init(ServletContext servletContext, GlobalConfiguration globalconfiguration) throws IOException {
        if(languages == null){
            // Get available languages.
            availablelanguages=null;
            String availablelanguagesstring = globalconfiguration.getAvailableLanguagesAsString();
            availablelanguages =  availablelanguagesstring.split(",");
            for(int i=0; i < availablelanguages.length;i++){
                availablelanguages[i] = availablelanguages[i].trim().toLowerCase();
                if (availablelanguages[i].equalsIgnoreCase("se")) {  /* For compatibility with EJBCA 6.2.x and before */
                    availablelanguages[i] = "sv";
                }
                if (availablelanguages[i].equalsIgnoreCase("ua")) {  /* For compatibility with EJBCA 6.2.x and before */
                    availablelanguages[i] = "uk";
                }
            }
            // Load available languages
            languages = new LanguageProperties[availablelanguages.length];
            for(int i = 0; i < availablelanguages.length; i++){
                languages[i] = new LanguageProperties();
                String propsfile = "/" + globalconfiguration.getLanguagePath() + "/"
                + globalconfiguration.getLanguageFilename() + "."
                + availablelanguages[i] +".properties";
                
                InputStream is = null;
                if (servletContext != null) {
                	is = servletContext.getResourceAsStream(propsfile);
                } else {
                    is = this.getClass().getResourceAsStream(propsfile);                	
                }
                if(is==null) {
                    //if not available as stream, try it as a file
                    is = new FileInputStream("/tmp"+propsfile);
                }
                if (log.isDebugEnabled()) {
                	log.debug("Loading language from file: "+propsfile);
                }
                languages[i].load(is);
            }
            // Get languages English and native names
            languagesenglishnames = new String[availablelanguages.length];
            languagesnativenames = new String[availablelanguages.length];
            for(int i = 0; i < availablelanguages.length; i++){
                languagesenglishnames[i] = languages[i].getProperty("LANGUAGE_ENGLISHNAME");
                languagesnativenames[i] = languages[i].getProperty("LANGUAGE_NATIVENAME");
            }
        }
    }

    public WebLanguages(ServletContext servletContext, GlobalConfiguration globalconfiguration, int preferedlang, int secondarylang) throws IOException {
        init(servletContext, globalconfiguration);
        this.userspreferedlanguage=preferedlang;
        this.userssecondarylanguage=secondarylang;
    }


    /** The main method that looks up the template text in the users preferred language. */
    public  String getText(String template){
      String returnvalue = null;
      try{
        returnvalue= languages[userspreferedlanguage].getProperty(template);
        if(returnvalue == null){
          returnvalue= languages[userssecondarylanguage].getProperty(template);
        }
        if(returnvalue == null){
            returnvalue= intres.getLocalizedMessage(template);
        }        
      }catch(java.lang.NullPointerException e){}
      if(returnvalue == null) {
        returnvalue = template;
      }
      return returnvalue;
    }

    /* Returns a text string array containing the available languages */
    public String[] getAvailableLanguages(){
      return availablelanguages;
    }

    /* Returns a text string array containing the languages English names */
    public String[] getLanguagesEnglishNames(){
      return languagesenglishnames;
    }

    /* Returns a text string array containing the languages native names */
    public String[] getLanguagesNativeNames(){
      return languagesnativenames;
    }


    // Protected fields
    private int userspreferedlanguage;
    private int userssecondarylanguage;

    private String[] availablelanguages;
    private String[] languagesenglishnames;
    private String[] languagesnativenames;
    private LanguageProperties[] languages = null;

}
