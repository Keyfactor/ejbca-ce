package se.anatom.ejbca.authorization;

import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;
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
    public void buildTree(Collection admingroups) {
        rootnode = new AccessTreeNode("/");
        System.out.println(" AccessTree : buildtree");
                  
        Iterator iter = admingroups.iterator();
        // Add all admingroups accessrules.
        while(iter.hasNext()){
          AdminGroup admingroup = (AdminGroup) iter.next(); 
          System.out.println(" adding admingroup to tree '" + admingroup.getAdminGroupName() + "' rules : " + admingroup.getAccessRules().size());
          Iterator iter2 = admingroup.getAccessRules().iterator();
          while(iter2.hasNext()){
            AccessRule accessrule = (AccessRule) iter2.next();  
            rootnode.addAccessRule(accessrule.getAccessRule(),accessrule,admingroup); // Without heading '/' 
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
