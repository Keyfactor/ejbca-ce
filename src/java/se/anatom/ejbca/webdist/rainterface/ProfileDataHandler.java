/*
 * ProfileDataHandler.java
 *
 * Created on den 12 april 2002, 13:03
 */

package se.anatom.ejbca.webdist.rainterface;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 */
public class ProfileDataHandler {
    
    /** Creates a new instance of ProfileDataHandler */
    public ProfileDataHandler() {
    }
    
    /** Saves det data as a BLOB tto the database. */
    public void saveProfilesData(Profiles profiles) {
        // This is only temporate.
      try{
        ObjectOutputStream out = new ObjectOutputStream( new FileOutputStream("profiles"));
        out.writeObject(profiles);
        out.close();
      }catch(IOException e) {
        System.out.println("Error when saving profile data to file!");
      }
    }
    
    /** Loads the data from the database. */
    public Profiles loadProfilesData() {
        // This is only temporate.
      Profiles profiles;
      try{
        ObjectInputStream in = new ObjectInputStream( new FileInputStream("profiles"));
        profiles = (Profiles) in.readObject();
        in.close();
      }catch(Exception e) {
         // Probably the file didn't exist
         profiles = new Profiles(); 
      }
      return profiles; 
    }
    
}
