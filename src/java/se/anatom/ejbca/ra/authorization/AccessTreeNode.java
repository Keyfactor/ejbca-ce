
package se.anatom.ejbca.ra.authorization;

import java.util.Vector;
import java.util.HashMap;
import java.util.Set;
import java.util.Iterator;
import java.security.cert.X509Certificate;

import org.apache.log4j.*;


/**
 * The building component of the AccessTree. All nodes consist of these objects.
 *
 * @author  Philip Vendil
 * @version $Id: AccessTreeNode.java,v 1.2 2002-07-09 15:04:22 anatom Exp $
 */
public class AccessTreeNode {

    private static Category cat = Category.getInstance(AccessTreeNode.class.getName());

    // Private Constants
    // OBSERVE that the order is important!!
    public static final int STATE_UNKNOWN = 1;
    public static final int STATE_OPEN = 2;
    public static final int STATE_ACCEPT = 3;
    public static final int STATE_ACCEPT_RECURSIVE = 4;
    public static final int STATE_DECLINE = 5;
    public static final int STATE_DECLINE_RECURSIVE = 6;

    /** Creates a new instance of AccessTreeNode */
    public AccessTreeNode(String directory) {
        //cat.debug(">AccessTreeNode:" +directory);
        name=directory;
        useraccesspairs = new Vector();
        leafs = new HashMap();
    }

    /** Checks the tree if the users X509Certificate is athorized to view the requested url */
    public boolean isAuthorized(X509Certificate certificate, String url) {
        cat.debug(">isAuthorized: " +url);
        boolean retval =isAuthorizedRecursive(certificate,url,STATE_DECLINE); // Default is to decline access.
        cat.debug("<isAuthorized: returns " + retval);
        return retval;
    }

    /** Adds an open access rule to the tree. Open means that no athorization at all is requred. */
     public void addOpenAccessRule(String opendirectory) {
       cat.debug(">addOpenAccessRule: " + opendirectory);
       int index;
       AccessTreeNode next;
       String nextname;
       String nextsubdirectory;

       if(opendirectory.equals(this.name)){
           cat.debug("addOpenAccessRule : Opening " + this.name);
           this.open=true;
       }
       else{
           nextsubdirectory = opendirectory.substring(this.name.length());
           if((nextsubdirectory.toCharArray()[0])=='/')
             nextsubdirectory = nextsubdirectory.substring(1);
           index = nextsubdirectory.indexOf('/');
           if(index != -1){
             nextname =  nextsubdirectory.substring(0,index);
           }
           else{
             nextname = nextsubdirectory;
           }
           next= (AccessTreeNode) leafs.get(nextname);
           if(next == null){  // Doesn't exist, create.
              next=new AccessTreeNode(nextname);
              leafs.put(nextname, next);
           }
           //cat.debug(this.name + " --> ");
           next.addOpenAccessRule(nextsubdirectory);

       }
       cat.debug("<addOpenAccessRule: " + opendirectory);
     }

     /** Adds an access rule with associated usergroup to the tree. */
     public void addAccessRule(String subdirectory, AccessRule accessrule, UserGroup usergroup) {
       cat.debug(">addAccessRule: " + subdirectory );
       int index;
       AccessTreeNode next;
       String nextname;
       String nextsubdirectory;

       if(subdirectory.equals(this.name)){ // Root is a special case.
           Object[] accessusergroupair = {accessrule,usergroup};
           useraccesspairs.addElement(accessusergroupair);
       }
       else{
           nextsubdirectory = subdirectory.substring(this.name.length());
           if((nextsubdirectory.toCharArray()[0])=='/')
             nextsubdirectory = nextsubdirectory.substring(1);

           index = nextsubdirectory.indexOf('/');
           if(index != -1){
             nextname =  nextsubdirectory.substring(0,index);
           }
           else{
             nextname = nextsubdirectory;
           }
           next= (AccessTreeNode) leafs.get(nextname);
           if(next == null){  // Doesn't exist, create.
              next=new AccessTreeNode(nextname);
              leafs.put(nextname, next);
           }
           //cat.debug(this.name + " --> ");
           next.addAccessRule(nextsubdirectory, accessrule, usergroup);
       }
       cat.debug("<addAccessRule: " + subdirectory);
     }

    // Private methods
    private boolean isLeaf(){
      return leafs.size()==0;
    }

    private boolean isAuthorizedRecursive(X509Certificate certificate, String url, int state){
       cat.debug("isAuthorizedRecursive: " + " url: " + url + " name: "+ this.name + "," +state);
       int index;
       int internalstate = STATE_DECLINE;
       boolean returnval = false;
       AccessTreeNode next;
       String nextname;
       boolean lastdirectory=false;
       String nextsubdirectory;
       Set keys;
       String matchname;

       internalstate = matchCertificate(certificate);
       if(url.matches(this.name)) {
         // If this directory have state open or accept recursive state is given
         if(this.open || state == STATE_ACCEPT_RECURSIVE || internalstate == STATE_ACCEPT || internalstate == STATE_ACCEPT_RECURSIVE ){
             // If this directory's rule set don't says decline.
           if(!(internalstate == STATE_DECLINE || internalstate == STATE_DECLINE_RECURSIVE))
             returnval=true;
         }
       }
       else{
         //cat.debug(" url : " + url);
         nextsubdirectory = url.substring(this.name.length());
         if((nextsubdirectory.toCharArray()[0])=='/')
         nextsubdirectory = nextsubdirectory.substring(1);
         //cat.debug(" nexturl : " + nextsubdirectory);

         index = nextsubdirectory.indexOf('/');
         if(index != -1){
             nextname =  nextsubdirectory.substring(0,index);
       }
       else {
           lastdirectory = true;
           nextname = nextsubdirectory;
       }
         //cat.debug(" nextname : " + nextname);
         next = (AccessTreeNode) leafs.get(nextname);
         if(next == null){  // Url path doesn't exist
            // Se if any key matches a regular expression.
            keys = leafs.keySet();
            for( Iterator i = keys.iterator(); i.hasNext();){
              matchname = (String) i.next();
              if(nextname.matches(matchname)){
                 next = (AccessTreeNode) leafs.get(matchname);
              }
            }
            // If  internal state isn't decline recusive is accept recursive.
            if(internalstate == STATE_ACCEPT_RECURSIVE){
               returnval=true;
            }
            // If state accept recursive is given and internal state isn't decline recusive.
            if(state == STATE_ACCEPT_RECURSIVE  && internalstate != STATE_DECLINE_RECURSIVE && internalstate != STATE_DECLINE){
              returnval=true;
            }
            if((this.open == true || internalstate == STATE_ACCEPT) && lastdirectory){
              returnval=true;
            }
         }
         if(next != null){ // Url path exists.
           // If internalstate is accept recursive or decline recusive.
           if(internalstate == STATE_ACCEPT_RECURSIVE || internalstate == STATE_DECLINE_RECURSIVE){
             state=internalstate;
           }
           //cat.debug(this.name + " --> ");
           returnval=next.isAuthorizedRecursive(certificate, nextsubdirectory, state);
         }
       }
       cat.debug("<isAthorizedRecursive: returns " + returnval + " : " + url + "," +state);
       return returnval;
    }

       private int matchCertificate(X509Certificate certificate){
          cat.debug(">matchCertificate");
          final int ACCESSRULE = 0;
          final int USERGROUP  = 1;

          int state     = STATE_UNKNOWN;
          int stateprio = 0;
          Object[] accessuserpair;
          UserEntity[] userentities;

          for (int i = 0; i < useraccesspairs.size();i++){
            accessuserpair = (Object[]) useraccesspairs.elementAt(i);
            userentities = ((UserGroup) accessuserpair[USERGROUP]).getUserEntities();
            for(int j = 0; j < userentities.length;j++){
              // If user entity match.
              if(userentities[j].match(certificate)){
                int thisuserstate = ((AccessRule) accessuserpair[ACCESSRULE]).getRuleState();
                int thisuserstateprio = userentities[j].getPriority();
                // If rule has higher priority, it's state is to be used.
                if( stateprio < thisuserstateprio){
                   state=thisuserstate;
                   stateprio=thisuserstateprio;
                }
                else{
                  if( stateprio == thisuserstateprio){
                    // If the priority is the same then decline has priority over accept.
                    if(state < thisuserstate){
                        state=thisuserstate;
                    }
                  }
                }
              }
            }
          }
          cat.debug("<matchCertificate: returns " + state );
          return state;
       }

    // Private fields.
    private String  name;
    private Vector  useraccesspairs;
    private HashMap leafs;
    private boolean open=false;

}
