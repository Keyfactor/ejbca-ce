/*
 * PropertiesFilenameFilter.java
 *
 * Created on den 1 april 2002, 15:00
 */

package se.anatom.ejbca.webdist.webconfiguration;

/**
 * A class to determine if a file is a property file. It looks for the fileending '.properties'
 *
 * @author  Philip Vendil
 */
public class LanguageFilenameFilter implements java.io.FilenameFilter{
    
    /** Creates a new instance of PropertiesFilenameFilter */
    public LanguageFilenameFilter() {
    }
    
    /** Checks if the given filename ends have a '.properties' ending. */
    public boolean accept(java.io.File file, String filename) {
        System.out.println("LanguageFilenameFilter: accept : " + filename + "," +GlobalConfiguration.getLanguageFilename());
       return filename.toLowerCase().trim().endsWith(".properties") && 
              filename.toLowerCase().trim().startsWith(GlobalConfiguration.getLanguageFilename());
    }
    
}
