/*
 * UserGroupsDataHandler.java
 *
 * Created on den 12 april 2002, 13:03
 */

package se.anatom.ejbca.webdist.ejbcaathorization;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

/**
 * A class handling all the usergroup data. It saves and retrieves them currently from a database.
 *
 * @author  Philip Vendil
 */
public class UserGroupsDataHandler {
    
    /** Creates a new instance of UserGroupsDataHandler */
    public UserGroupsDataHandler() {
    }
    
    /** Saves det data as a BLOB tto the database. */
    public void saveAccessData(UserGroups usergroups) {
        // This is only temporate.
      try{
        ObjectOutputStream out = new ObjectOutputStream( new FileOutputStream("accessrules"));
        out.writeObject(usergroups);
        out.close();
      }catch(IOException e) {
        System.out.println("Error when saving access data to file!");
      }
    }
    
    /** Loads the data from the database. */
    public UserGroups loadAccessData() {
        // This is only temporate.
      UserGroups usergroups;  
      try{
        ObjectInputStream in = new ObjectInputStream( new FileInputStream("accessrules"));
        usergroups = (UserGroups) in.readObject();
        in.close();
      }catch(Exception e) {
         // Probably the file didn't exist
         usergroups = new UserGroups();
         // Temporate.  For all new databases, give total access to user with CN=Walter
         UserGroup defaultusergroup = new UserGroup();
         defaultusergroup.addUserEntity(UserEntity.WITH_COMMONNAME,UserEntity.TYPE_EQUALCASEINS,"Walter");
         defaultusergroup.addAccessRule("/",AccessRule.RULE_ACCEPT,true);
         try{ 
           usergroups.addUserGroup("Default",defaultusergroup);
         }catch(UsergroupExistsException f){}
      }
      return usergroups;
    }
    
}
