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
 
package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.config.GlobalConfiguration;


/**
 * A class representing a admins personal preferenses.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AdminPreference extends UpgradeableDataHashMap implements Serializable, Cloneable {
    
    private static final long serialVersionUID = -3408759285870979620L;


    public static final float LATEST_VERSION = 1;
    
    
    // Public constants
    public static final int FILTERMODE_BASIC     = 0;
    public static final int FILTERMODE_ADVANCED  = 1;

    /** Creates a new instance of AdminPreference */
    public AdminPreference() {
      super();
      
      // Set default values.
      data.put(PREFEREDLANGUAGE, Integer.valueOf(GlobalConfiguration.EN));
      data.put(SECONDARYLANGUAGE, Integer.valueOf(GlobalConfiguration.EN));
      data.put(ENTRIESPERPAGE, Integer.valueOf(25));
      data.put(LOGENTRIESPERPAGE, Integer.valueOf(25));
      data.put(THEME, "default_theme");   
      data.put(LASTPROFILE, Integer.valueOf(0));
      data.put(LASTFILTERMODE, Integer.valueOf(FILTERMODE_BASIC));
      data.put(LASTLOGFILTERMODE, Integer.valueOf(FILTERMODE_BASIC));
      data.put(FRONTPAGECASTATUS, DEFAULT_FRONTPAGECASTATUS);
      data.put(FRONTPAGEPUBQSTATUS, DEFAULT_FRONTPAGEPUBQSTATUS);
    }

    public int getPreferedLanguage() {return ((Integer) data.get(PREFEREDLANGUAGE)).intValue();}
    public void setPreferedLanguage(int language){ data.put(PREFEREDLANGUAGE, Integer.valueOf(language));}
    /** Method taking a string, needs as input the available languages.
     * 
     * @param languages available languages as retrieved from EjbcaWebBean.getAvailableLanguages
     * @param languagecode two letter language code (ISO 639-1), e.g. en, sv
     * @see org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getAvailableLanguages()
     */
    public void setPreferedLanguage(String[] languages, String languagecode) {
        if(languages != null){
            for(int i=0; i < languages.length; i++){
                if(languages[i].equalsIgnoreCase(languagecode)) {
                    data.put(PREFEREDLANGUAGE, Integer.valueOf(i));
                }
            }
        }
    }    
    
    public int getSecondaryLanguage() {return ((Integer) data.get(SECONDARYLANGUAGE)).intValue();}
    public void setSecondaryLanguage(int language){ data.put(SECONDARYLANGUAGE, Integer.valueOf(language));}
    /** Method taking a string, needs as input the available languages.
     * 
     * @param languages available languages as retrieved from EjbcaWebBean.getAvailableLanguages
     * @param languagecode two letter language code (ISO 639-1), e.g. en, sv
     * @see org.ejbca.ui.web.admin.configuration.EjbcaWebBean#getAvailableLanguages()
     */
    public void setSecondaryLanguage(String[] languages, String languagecode){
        if(languages != null){
            for(int i=0; i < languages.length; i++){
                if(languages[i].equalsIgnoreCase(languagecode)) {
                    data.put(SECONDARYLANGUAGE, Integer.valueOf(i));
                }
            }
        }
    }    

    public int getEntriesPerPage(){return ((Integer) data.get(ENTRIESPERPAGE)).intValue();}
    public void setEntriesPerPage(int entriesperpage){ data.put(ENTRIESPERPAGE, Integer.valueOf(entriesperpage));}
    
    public int getLogEntriesPerPage(){return ((Integer) data.get(LOGENTRIESPERPAGE)).intValue();}
    public void setLogEntriesPerPage(int logentriesperpage){ data.put(LOGENTRIESPERPAGE, Integer.valueOf(logentriesperpage));}
    
    public String getTheme() {return  (String) data.get(THEME); }
    public void setTheme(String theme){ data.put(THEME, theme);}    

    public int getLastProfile(){return  ((Integer) data.get(LASTPROFILE)).intValue();}
    public void setLastProfile(int lastprofile){data.put(LASTPROFILE, Integer.valueOf(lastprofile));}
    
    /** Last filter mode is the admins last mode in the list end entities jsp page. */
    public int getLastFilterMode(){ return  ((Integer) data.get(LASTFILTERMODE)).intValue();}
    public void setLastFilterMode(int lastfiltermode){data.put(LASTFILTERMODE, Integer.valueOf(lastfiltermode));}
    
    public int getLastLogFilterMode() {return  ((Integer) data.get(LASTLOGFILTERMODE)).intValue();}
    public void setLastLogFilterMode(int lastlogfiltermode) {data.put(LASTLOGFILTERMODE, Integer.valueOf(lastlogfiltermode));}    
    
    public boolean getFrontpageCaStatus(){return Boolean.TRUE.equals(data.get(FRONTPAGECASTATUS));}
    public void setFrontpageCaStatus(boolean frontpagecastatus){ data.put(FRONTPAGECASTATUS, Boolean.valueOf(frontpagecastatus));}
    
    public boolean getFrontpagePublisherQueueStatus(){return Boolean.TRUE.equals(data.get(FRONTPAGEPUBQSTATUS));}
    public void setFrontpagePublisherQueueStatus(boolean frontpagepubqstatus){ data.put(FRONTPAGEPUBQSTATUS, Boolean.valueOf(frontpagepubqstatus));}
    
    public Object clone() throws CloneNotSupportedException {
      AdminPreference clone = new AdminPreference();
      @SuppressWarnings("unchecked")
    HashMap<Object, Object> clonedata = (HashMap<Object, Object>) clone.saveData();
      
      Iterator<Object> i = (data.keySet()).iterator();
      while(i.hasNext()){
        Object key = i.next();  
        clonedata.put(key, data.get(key));  
      }
      
      clone.loadData(clonedata);
      return clone;
    }
    
    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;  
    }
    
    /** Implementation of UpgradableDataHashMap function upgrade. */     
    public void upgrade(){
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
    		// New version of the class, upgrade  
    		
    		if(data.get(FRONTPAGECASTATUS) == null) {
    			data.put(FRONTPAGECASTATUS, DEFAULT_FRONTPAGECASTATUS);
    		}
    		if(data.get(FRONTPAGEPUBQSTATUS) == null) {
    			data.put(FRONTPAGEPUBQSTATUS, DEFAULT_FRONTPAGEPUBQSTATUS);
    		}
    		
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
    private static final String FRONTPAGECASTATUS   			= "frontpagecastatus";
    private static final String FRONTPAGEPUBQSTATUS   			= "frontpagepubqstatus";
    
    public static final boolean DEFAULT_FRONTPAGECASTATUS	= true;
    public static final boolean DEFAULT_FRONTPAGEPUBQSTATUS	= true;
    
}
