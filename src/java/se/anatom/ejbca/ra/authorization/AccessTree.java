/*
 * AccessTree.java
 *
 * Created on den 16 mars 2002, 20:39
 */

package se.anatom.ejbca.ra.authorization;

/**
 * A class that builds and maintains an accesstree. It should be used to check if a
 * client certificate has access rights to a resource or not. isAthorized metod is the one to use.
 *
 * @author  Philip Vendil
 */
import java.security.cert.X509Certificate;
import java.io.Serializable;

public class AccessTree implements Serializable {
    /** Creates a new instance of AccessTree */
    public AccessTree(String[] opendirectories) {
      // Remove '/' in the end of open direcories if they exists. And add one in the beginging if they doesn't.
      if(opendirectories != null){
        this.opendirectories=opendirectories;
        for(int i=0; i < opendirectories.length; i++){
          this.opendirectories[i]=this.opendirectories[i].replace('\\','/');
          if(!this.opendirectories[i].startsWith("/")){
            this.opendirectories[i]="/" + this.opendirectories[i];
          }
          if(this.opendirectories[i].endsWith("/") && this.opendirectories[i].length() > 1){
            this.opendirectories[i]=this.opendirectories[i].substring(0,this.opendirectories[i].length()-1);
          }
        }
      }
    }

    // Public methods
    /** Builds an accesstree out of the given usergroup data. */
    public void buildTree(UserGroup[] ug, String[] opendirectories) {
        rootnode = new AccessTreeNode("/");

        // Add open directories.
        if(opendirectories != null ){
          for(int i=0; i < opendirectories.length;i++){
             rootnode.addOpenAccessRule(opendirectories[i]);
          }
        }

        // Add all usergroups accessrules.
        for(int i=0; i < ug.length;i++){
          AccessRule[] accessrules=ug[i].getAccessRules();
          for(int j=0; j < accessrules.length; j++){
            rootnode.addAccessRule(accessrules[j].getDirectory(),accessrules[j],ug[i]); // Without heading '/'
          }
        }
    }

    /** A method to check if someone is athorized to view the given resource */
    public boolean isAuthorized(UserInformation userinformation, String resource){
          String checkresource = resource;
        // Must begin with '/'.
        if((checkresource.toCharArray())[0] != '/')
          checkresource = "/" + checkresource;

        // Check if user is athorized in the tree.
        boolean retval = rootnode.isAuthorized(userinformation, checkresource);
        return retval;
    }



    // Private fields
    private AccessTreeNode rootnode = null;
    private String[] opendirectories;

}
