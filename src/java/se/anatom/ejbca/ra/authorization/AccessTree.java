package se.anatom.ejbca.ra.authorization;

import java.io.Serializable;

/**
 * A class that builds and maintains an accesstree. It should be used to check if a
 * client certificate has access rights to a resource or not. isAthorized metod is the one to use.
 *
 * @author  Philip Vendil
 */
public class AccessTree implements Serializable {
    /** Creates a new instance of AccessTree */
    public AccessTree() {}

    // Public methods
    /** Builds an accesstree out of the given admingroup data. */
    public void buildTree(AdminGroup[] ug) {
        rootnode = new AccessTreeNode("/");
        
        // Add all admingroups accessrules.
        for(int i=0; i < ug.length;i++){
          AccessRule[] accessrules=ug[i].getAccessRules();
          for(int j=0; j < accessrules.length; j++){ 
              rootnode.addAccessRule(accessrules[j].getResource(),accessrules[j],ug[i]); // Without heading '/' 
          }
        }
    }

    /** A method to check if someone is athorized to view the given resource */
    public boolean isAuthorized(AdminInformation admininformation, String resource){
          String checkresource = resource;
        // Must begin with '/'.
        if((checkresource.toCharArray())[0] != '/')
          checkresource = "/" + checkresource;

        // Check if user is athorized in the tree.
        boolean retval = rootnode.isAuthorized(admininformation, checkresource);
        return retval;
    }



    // Private fields
    private AccessTreeNode rootnode = null;

}
