/*
 * AvailableDirectories.java
 *
 * Created on den 16 mars 2002, 16:35
 */

package se.anatom.ejbca.webdist.ejbcaathorization;

import java.util.Vector;
import java.io.File;
import java.io.IOException;

/**
 * 
 *
 * @author  Philip Vendil
 */
public class AvailableDirectories {
        
    /** Creates a new instance of AvailableDirectories */
    public AvailableDirectories(String rootdirectory, String[] hiddendirectories, String raadminpath) {      
      // Add trailing '/' if it doesn't exists.
      this.rootdirectory=rootdirectory.replace('\\','/');  
      if(!this.rootdirectory.endsWith("/")){
        this.rootdirectory=this.rootdirectory + "/";   
      }
     
      if(hiddendirectories != null){
      // Remove '/' in beginning and end of hidden direcories if it exists.
        this.hiddendirectories=hiddendirectories;
        for(int i=0; i < hiddendirectories.length; i++){
          this.hiddendirectories[i]=this.hiddendirectories[i].replace('\\','/');
          if(this.hiddendirectories[i].startsWith("/")){
            this.hiddendirectories[i]=this.hiddendirectories[i].substring(1);  
          }
          if(this.hiddendirectories[i].endsWith("/")){
            this.hiddendirectories[i]=this.hiddendirectories[i].substring(0,this.hiddendirectories[i].length()-1);
          }
        }
      }
      this.directoryfilenamefilter= new DirectoryFilenameFilter(); 
      
 /*     if(!raadminpath.equals(""))
        raadminpath = raadminpath.substring(0,raadminpath.length() -1);  */
      this.raadminpath = raadminpath;
    }
    // Public methods 
    /** Returns all the directories and subdirectories from the given subdirectory */
    public String[] getDirectories() throws IOException {
      String[] returnvalues={""};  
      Vector directories = new Vector(); 
      scanDirectoriesRecursive(new File(rootdirectory), directories);  
      return (String[]) directories.toArray(returnvalues);    
    }
    
    // Private methods
    private void scanDirectoriesRecursive(File currentdirectory, Vector directories) throws IOException{
        String[] subdirectories = null;       
        File curfile;
        String directoryname;
        
        subdirectories = currentdirectory.list(directoryfilenamefilter);
        if(subdirectories != null){
          for(int i=0; i < subdirectories.length; i++){
            boolean hidden=false; 
            curfile = new File(currentdirectory, subdirectories[i]);
            if(hiddendirectories != null){
              for(int j=0; j < hiddendirectories.length; j++){
                // if directory isn't in the hidden list. add it to directories. 
                // It wont recurce thru hidden directories.
                String currfile =   curfile.getCanonicalPath().replace('\\','/');
                String next     =   (rootdirectory+hiddendirectories[j]).replace('\\','/');
                if(curfile.getCanonicalPath().replace('\\','/').equals((rootdirectory+hiddendirectories[j]).replace('\\','/'))){
                  hidden=true;
                }
              }
            }
            if(!hidden){
              // Add directory name without rootpath.  
              directoryname = curfile.getCanonicalPath().replace('\\','/').substring(rootdirectory.length());
              directories.addElement("/" + this.raadminpath + directoryname);
              // Go recursevely thru the filetree.
              scanDirectoriesRecursive(curfile,directories);
            }
          }
        }
    }
    
    // Private fields
    private String rootdirectory=null;
    private String raadminpath="";
    private String[] hiddendirectories;
    private DirectoryFilenameFilter directoryfilenamefilter;
}
