/*
 * CssFilenameFilter.java
 *
 * Created on den 28 mars 2002, 13:51
 */

package se.anatom.ejbca.webdist.webconfiguration;

/**
 * A class to determine if a file is a cascading style sheet. It looks for the fileending '.css'
 *
 * @author  Philip Vendil
 */
public class CssFilenameFilter implements java.io.FilenameFilter {
    
    /** Creates a new instance of CssFilenameFilter */
    public CssFilenameFilter() {
    }
    
    /** Checks if the given filename ends have a 'css' ending. */
    public boolean accept(java.io.File file, String filename) {
       return filename.toLowerCase().trim().endsWith(".css");
    }
    
}
