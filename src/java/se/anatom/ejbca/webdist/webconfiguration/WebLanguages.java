/*
 * WebLanguage.java
 *
 * Created on den 27 mars 2002, 21:09
 */

package se.anatom.ejbca.webdist.webconfiguration;

import java.util.Properties;
import java.io.FileInputStream;
import java.io.File;
import java.io.IOException;

/**
 * An class interprenting the langage properties files. I contains one method getText that returns
 * the presented text in the users prefered language.
 *
 * @author  Philip Vendil
 */
public class WebLanguages {
    
    /** Construtor used to load static content. An instance must be declared with this constructor before
     *  any WebLanguage object can be used. */
    /** Special constructor used by Ejbca web bean */
    public WebLanguages() throws IOException{  
      if(languages == null){ 
        // Get available languages.  
         this.availablelanguages=null;
         String[] availablelanguagefilenames;
         FileInputStream fis;
         java.io.File languagedirectory = new java.io.File(GlobalConfiguration.getDocumentRoot() 
                                                           +GlobalConfiguration.getLanguagePath());
         availablelanguagefilenames = languagedirectory.list(new LanguageFilenameFilter());
 
         if(availablelanguagefilenames != null){
           availablelanguages = new String[availablelanguagefilenames.length];  

           for(int i = 0; i <  availablelanguages.length; i++){
              availablelanguages[i] = availablelanguagefilenames[i].substring(GlobalConfiguration.getLanguageFilename().length()+1
                                                                             ,availablelanguagefilenames[i].length()-11)
                                                                             .toUpperCase();    
           }  

           // Load availabe languages
           languages = new Properties[availablelanguages.length];
           for(int i = 0; i < availablelanguagefilenames.length; i++){
             fis = new FileInputStream(GlobalConfiguration.getDocumentRoot() 
                                       +GlobalConfiguration.getLanguagePath() + "/" +availablelanguagefilenames[i]);
             languages[i] = new Properties();
             languages[i].load(fis);
             fis.close();
           } 
         }
       }
    }
      
      
      

    
    
    public WebLanguages(int preferedlang, int secondarylang) {   
      this.userspreferedlanguage=preferedlang;
      this.userssecondarylanguage=secondarylang;  
    }
      
       
    /** The main method that looks up the template text in the users prefered language. */
    public  String getText(String template){
      String returnvalue = null;  
      try{  
        returnvalue= languages[userspreferedlanguage].getProperty(template);
        if(returnvalue == null)
          returnvalue= languages[userssecondarylanguage].getProperty(template);

      }catch(java.lang.NullPointerException e){}   
      if(returnvalue == null)
        returnvalue= "No text available";    
      return returnvalue; 
    }
    
    /* Returns a textstring containing the available languages */
    public static String[] getAvailableLanguages(){
      return availablelanguages;   
    }
    
    
    // Protected fields
    private int userspreferedlanguage;
    private int userssecondarylanguage;

    private static String[] availablelanguages;
    private static Properties[] languages = null;

}
