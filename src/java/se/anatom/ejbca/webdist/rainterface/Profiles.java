/*
 * UserGroups.java
 *
 * Created on 12 april 2002, 11:27
 */

package se.anatom.ejbca.webdist.rainterface;
import java.util.TreeMap;
import java.io.Serializable;



/**
 * A class that represents a set of profiles. The set is actually a Treemap.
 *
 * @author  Philip Vendil
 */
public class Profiles implements Serializable {
    // Public constants
    public static final String EMPTY_PROFILE = "00EMPTY";
    
    
    /** Creates a new instance of Profiles */
    public Profiles() {
      profiles = new TreeMap(); 
      try{
        addProfile(EMPTY_PROFILE, new Profile());
      }catch(Exception e){
          // do nothing.
      }
      defaultprofile = EMPTY_PROFILE;
    }
    
    // Public methods
    /** Method to add a profile. Throws ProfileExitsException if profile already exists  */
    public void addProfile(String name, Profile profile) throws ProfileExistsException {
      Profile pro = (Profile) profiles.get(name);
      if(pro != null)
        throw new ProfileExistsException(name);
      profiles.put(name,profile);
    }
    
    /** Method to remove a profile.*/ 
    public void removeProfile(String name) {
        if(name.equals(this.defaultprofile)){
          this.defaultprofile = this.EMPTY_PROFILE;   
        }
        profiles.remove(name);
    }
    
    /** Metod to rename a profile */
    public void renameProfile(String oldname, String newname) throws ProfileExistsException{
      Profile pro = (Profile) profiles.get(newname);
      if(pro != null){
        throw new ProfileExistsException(newname);        
      }
      else{
        pro = (Profile) profiles.get(oldname);
        if(pro != null){
          profiles.put(newname,pro);    
          profiles.remove(oldname); 
        }
      } 
    }
    
      /** Method to get a reference to a profile.*/ 
    public Profile getProfile(String name) {
        return (Profile) profiles.get(name);
    }  
        
    /** Returns the number of profiles i database. */
    public int getNumberOfProfiles() {
      return profiles.size();
    }
    
    /** Returns an array containing all the profiles names.*/
     public String[] getProfileNames() {
      String[] dummy={};  
      return (String[]) profiles.keySet().toArray(dummy);  
    }
    
    /** Returns an array containing all the profiles.*/
    public Profile[] getProfiles() {
      Profile[] dummy={};  
      return (Profile[]) profiles.values().toArray(dummy);  
    }
    
    public String[][][] getProfilesAsStrings(){
      String[][][] returnvalue = new String[profiles.size()][1][1];
      String[] profilesnames = getProfileNames();
      for(int i=0 ; i < profiles.size() ; i++){
         returnvalue[i] = ((Profile) profiles.get(profilesnames[i])).getAllValues();   
      }
      return returnvalue;  
    }
    
    public void cloneProfile(String originalname, String newname) throws ProfileExistsException{         
      // Check if original profile already exists. 
      Profile profile = (Profile) profiles.get(newname);
      if(profile != null){
        throw new ProfileExistsException(newname);        
      }       
      else{
        profile = (Profile) profiles.get(originalname);   
        if(profile != null){
          try{  
            profiles.put(newname, profile.clone());
          }catch( Exception e){
             // Do nothing   
          }
        }
      }
    }
    
    public void setDefaultProfile(String name){
      this.defaultprofile=name;        
    }
    
    public String getDefaultProfileName(){
      return this.defaultprofile;
    }
    
    public String[][] getDefaultProfileAsString(){
      return ((Profile) profiles.get(defaultprofile)).getAllValues();  
    }
    
    public Profile getDefaultProfile(){
      return (Profile) profiles.get(defaultprofile);   
    }
    
    // Private methods
    
    // Private fields
    private TreeMap profiles;
    private String defaultprofile;
 }



