/*
 * UsersView.java
 *
 * Created on den 18 april 2002, 23:00
 */

package se.anatom.ejbca.webdist.rainterface;
import java.util.Vector;
import java.util.Collections;
import java.util.Collection;
import java.util.Iterator;
import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import se.anatom.ejbca.ra.UserAdminData;
/**
 * A class representing a set of users w
 * @author  philip
 */
public class UsersView {
        
    /** Creates a new instance of UsersView */
    public UsersView() {
      users = new Vector();
      sortby = new SortBy();
    }
    
    public UsersView(UserAdminData importuser) throws RemoteException, NamingException, FinderException, CreateException{
      users = new Vector();
      sortby = new SortBy();        
      users.addElement(new UserView(importuser)); 
      
      Collections.sort(users); 
    }
    
    public UsersView(Collection importusers) throws RemoteException, NamingException, FinderException, CreateException{ 
      users = new Vector();
      sortby = new SortBy();
      
      setUsers(importusers);
    }
    // Public methods.
    
    public void sortBy(int sortby, int sortorder) {
      this.sortby.setSortBy(sortby);
      this.sortby.setSortOrder(sortorder);
      
      Collections.sort(users);
    }
    
    public String[][] getUsers(int index, int size) {
      int endindex;  
      String[][] returnval;
   
      if(index > users.size()) index = users.size()-1;
      if(index < 0) index =0;
      
      endindex = index + size;
      if(endindex > users.size()) endindex = users.size();
      
      returnval = new String[endindex-index][UserView.NUMBEROF_USERFIELDS];  
      
      int end = endindex - index;
      for(int i = 0; i < end; i++){
        returnval[i] = ((UserView) users.elementAt(index+i)).getValues();   
      }
      
      return returnval;
    }
    
    public void setUsers(UserView[] users) {
       this.users.clear();
      if(users !=null && users.length > 0){       
        for(int i=0; i < users.length; i++){
          users[i].setSortBy(this.sortby);
          this.users.addElement(users[i]);
        }
      }
      Collections.sort(this.users);
    }
    
    public void setUsers(UserAdminData[] users) throws RemoteException, NamingException, FinderException, CreateException {
      UserView user;  
      this.users.clear();
      if(users !=null && users.length > 0){ 
        for(int i=0; i< users.length; i++){
          user = new UserView(users[i]); 
          user.setSortBy(this.sortby);
          this.users.addElement(user);
        }
        Collections.sort(this.users);
      }
    }

    public void setUsers(Collection importusers) throws RemoteException, NamingException, FinderException, CreateException{ 
      UserView user;  
      Iterator i;  
      this.users.clear();
      if(importusers!=null && importusers.size() > 0){
        i=importusers.iterator();
        while(i.hasNext()){
          UserAdminData nextuser = (UserAdminData) i.next();  
          user = new UserView(nextuser); 
          user.setSortBy(this.sortby);
          users.addElement(user);
        }
        Collections.sort(users);
      }
    }

    public void addUser(UserView user) {
       user.setSortBy(this.sortby);        
       users.addElement(user);
    }
    
    public int size(){
      return users.size();   
    }
    // Private fields
    private Vector users;
    private SortBy sortby;
    
}
