/*
 * DirectoryFilenameFilter.java
 *
 * Created on den 16 mars 2002, 17:06
 */

package se.anatom.ejbca.webdist.ejbcaathorization;
import java.io.FilenameFilter;
import java.io.File;
/**
 * A class to recognise if a file is a directory. Is used to filter out subdirectories.
 *
 * @author  Philip Vendil
 */
public class DirectoryFilenameFilter implements FilenameFilter{
    
    /** Creates a new instance of DirectoryFileFilter, does nothing */
    public DirectoryFilenameFilter() {
    }
    
    /** Used to list only subdirectories. */
    public boolean accept(File path, String filename){ 
      return (new File(path, filename)).isDirectory();
    }
   
}
