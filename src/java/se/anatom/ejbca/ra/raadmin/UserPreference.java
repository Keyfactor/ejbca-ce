/*
 * UserPreference.java
 *
 * Created on den 28 mars 2002, 12:36
 */

package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.webdist.webconfiguration.WebLanguages;

/**
 * A class representing a users personal preferenses.
 *
 * @author  Philip Vendil
 * @version $Id: UserPreference.java,v 1.4 2002-09-12 18:14:15 herrvendil Exp $
 */
public class UserPreference implements java.io.Serializable, Cloneable {
    
    // Public constants
    public static final int FILTERMODE_BASIC     = 0;
    public static final int FILTERMODE_ADVANCED  = 1;

    /** Creates a new instance of UserPreference */
    public UserPreference() {}

    public int getPreferedLanguage() {return preferedlanguage;}

   /* Returns the prefered language code. Ex: 'EN' */
    public String getPreferedLanguageCode(){
      return WebLanguages.getAvailableLanguages()[preferedlanguage];
    }

    public int getSecondaryLanguage() {return secondarylanguage;}

    /* Returns the prefered secondary language code. Ex: 'EN' */
    public String getSecondaryLanguageCode(){
      return  WebLanguages.getAvailableLanguages()[secondarylanguage];
    }

    public int getEntriesPerPage(){
      return entriesperpage;
    }

    public void setEntriesPerPage(int entriesperpage){
      this.entriesperpage= entriesperpage;
    }
    
    public int getLogEntriesPerPage(){
      return logentriesperpage;
    }

    public void setLogEntriesPerPage(int logentriesperpage){
      this.logentriesperpage= logentriesperpage;
    }
    
    public String getTheme() {return theme;}

    public void setPreferedLanguage(String languagecode) {
      String[] languages = WebLanguages.getAvailableLanguages();
      if(languages != null){
        for(int i=0; i < languages.length; i++){
          if(languages[i].toUpperCase().equals(languagecode.toUpperCase()))
            preferedlanguage=i;
        }
      }
    }

    public void setPreferedLanguage(int language){
      this.preferedlanguage=language;
    }

    public void setSecondaryLanguage(String languagecode){
      String[] languages = WebLanguages.getAvailableLanguages();
      if(languages != null){
        for(int i=0; i < languages.length; i++){
          if(languages[i].toUpperCase().equals(languagecode.toUpperCase()))
            secondarylanguage=i;
        }
      }
    }


    public void setSecondaryLanguage(int language) {
      this.secondarylanguage=language;
    }

    public void setTheme(String theme) {
      this.theme=theme;
    }


    public String getLastProfile(){ return lastprofile;}
    public void setLastProfile(String lastprofile){this.lastprofile=lastprofile;}
    
    public int getLastFilterMode(){ return lastfiltermode;}
    public void setLastFilterMode(int lastfiltermode){this.lastfiltermode=lastfiltermode;}
    
    public int getLastLogFilterMode(){ return lastlogfiltermode;}
    public void setLastLogFilterMode(int lastlogfiltermode){this.lastlogfiltermode=lastlogfiltermode;}    
    
    public Object clone() throws CloneNotSupportedException {
      return super.clone();
    }

    // Private fields
    private int preferedlanguage;
    private int secondarylanguage;
    private int entriesperpage= 25;
    private int logentriesperpage = 25;
    private String theme;
    private String lastprofile;
    private int lastlogfiltermode = FILTERMODE_BASIC;
    private int lastfiltermode = FILTERMODE_BASIC;

}
