/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ra.raadmin;

import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.webdist.webconfiguration.WebLanguages;
import se.anatom.ejbca.util.UpgradeableDataHashMap;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;

/**
 * A class representing a admins personal preferenses.
 *
 * @author  Philip Vendil
 * @version $Id: AdminPreference.java,v 1.6 2004-04-16 07:38:41 anatom Exp $
 */
public class AdminPreference extends UpgradeableDataHashMap implements java.io.Serializable, Cloneable {
    
    public static final float LATEST_VERSION = 0;    
    
    
    // Public constants
    public static final int FILTERMODE_BASIC     = 0;
    public static final int FILTERMODE_ADVANCED  = 1;

    /** Creates a new instance of AdminPreference */
    public AdminPreference() {
      super();
      
      // Set default values.
      data.put(PREFEREDLANGUAGE, new Integer(GlobalConfiguration.EN));
      data.put(SECONDARYLANGUAGE, new Integer(GlobalConfiguration.EN));
      data.put(ENTRIESPERPAGE, new Integer(25));
      data.put(LOGENTRIESPERPAGE, new Integer(25));
      data.put(THEME, "default_theme");   
      data.put(LASTPROFILE, new Integer(0));
      data.put(LASTFILTERMODE, new Integer(FILTERMODE_BASIC));
      data.put(LASTLOGFILTERMODE, new Integer(FILTERMODE_BASIC));
    }

    public int getPreferedLanguage() {return ((Integer) data.get(PREFEREDLANGUAGE)).intValue();}
    public void setPreferedLanguage(int language){ data.put(PREFEREDLANGUAGE, new Integer(language));}
    
   /* Returns the prefered language code. Ex: 'EN' */
    public String getPreferedLanguageCode(){
      return WebLanguages.getAvailableLanguages()[((Integer) data.get(PREFEREDLANGUAGE)).intValue()];
    }
    
    public void setPreferedLanguage(String languagecode) {
      String[] languages = WebLanguages.getAvailableLanguages();
      if(languages != null){
        for(int i=0; i < languages.length; i++){
          if(languages[i].toUpperCase().equals(languagecode.toUpperCase()))
            data.put(PREFEREDLANGUAGE, new Integer(i));
        }
      }
    }    

    public int getSecondaryLanguage() {return ((Integer) data.get(SECONDARYLANGUAGE)).intValue();}
    public void setSecondaryLanguage(int language){ data.put(SECONDARYLANGUAGE, new Integer(language));}
    
    /* Returns the prefered secondary language code. Ex: 'EN' */
    public String getSecondaryLanguageCode(){
      return  WebLanguages.getAvailableLanguages()[((Integer) data.get(SECONDARYLANGUAGE)).intValue()];
    }
    
    public void setSecondaryLanguage(String languagecode){
      String[] languages = WebLanguages.getAvailableLanguages();
      if(languages != null){
        for(int i=0; i < languages.length; i++){
          if(languages[i].toUpperCase().equals(languagecode.toUpperCase()))
            data.put(SECONDARYLANGUAGE, new Integer(i));
        }
      }
    }    

    public int getEntriesPerPage(){return ((Integer) data.get(ENTRIESPERPAGE)).intValue();}
    public void setEntriesPerPage(int entriesperpage){ data.put(ENTRIESPERPAGE, new Integer(entriesperpage));}
    
    public int getLogEntriesPerPage(){return ((Integer) data.get(LOGENTRIESPERPAGE)).intValue();}
    public void setLogEntriesPerPage(int logentriesperpage){ data.put(LOGENTRIESPERPAGE, new Integer(logentriesperpage));}
    
    public String getTheme() {return  (String) data.get(THEME); }
    public void setTheme(String theme){ data.put(THEME, theme);}    

    public int getLastProfile(){return  ((Integer) data.get(LASTPROFILE)).intValue();}
    public void setLastProfile(int lastprofile){data.put(LASTPROFILE, new Integer(lastprofile));}
    
    /** Last filter mode is the admins last mode in the list end entities jsp page. */
    public int getLastFilterMode(){ return  ((Integer) data.get(LASTFILTERMODE)).intValue();}
    public void setLastFilterMode(int lastfiltermode){data.put(LASTFILTERMODE, new Integer(lastfiltermode));}
    
    public int getLastLogFilterMode() {return  ((Integer) data.get(LASTLOGFILTERMODE)).intValue();}
    public void setLastLogFilterMode(int lastlogfiltermode) {data.put(LASTLOGFILTERMODE, new Integer(lastlogfiltermode));}    
    
    public Object clone() throws CloneNotSupportedException {
      AdminPreference clone = new AdminPreference();
      HashMap clonedata = (HashMap) clone.saveData();
      
      Iterator i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();  
        clonedata.put(key, data.get(key));  
      }
      
      clone.loadData(clonedata);
      return clone;
    }
    
    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;  
    }
    
    /** Implemtation of UpgradableDataHashMap function upgrade. */    
    
    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade  
        
        data.put(VERSION, new Float(LATEST_VERSION));  
      }  
    }    
    

    // Private fields
    private static final String PREFEREDLANGUAGE  = "preferedlanguage"; 
    private static final String SECONDARYLANGUAGE = "secondarylanguage"; 
    private static final String ENTRIESPERPAGE    = "entriesperpage"; 
    private static final String LOGENTRIESPERPAGE = "logentriesperpage"; 
    private static final String THEME             = "theme";
    private static final String LASTPROFILE       = "lastprofile";
    private static final String LASTFILTERMODE    = "lastfiltermode";
    private static final String LASTLOGFILTERMODE = "lastlogfiltermode";    
    
}
