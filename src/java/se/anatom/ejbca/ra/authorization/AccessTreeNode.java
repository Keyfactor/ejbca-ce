package se.anatom.ejbca.ra.authorization;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Set;
import java.util.Vector;

import org.apache.log4j.Logger;


/**
 * The building component of the AccessTree. All nodes consist of these objects.
 *
 * @author Philip Vendil
 * @version $Id: AccessTreeNode.java,v 1.9 2003-07-24 08:43:31 anatom Exp $
 */
public class AccessTreeNode implements Serializable {
    private static Logger log = Logger.getLogger(AccessTreeNode.class);

    // Private Constants
    // OBSERVE that the order is important!!
    public static final int STATE_UNKNOWN = 1;
    public static final int STATE_ACCEPT = 2;
    public static final int STATE_ACCEPT_RECURSIVE = 3;
    public static final int STATE_DECLINE = 4;
    public static final int STATE_DECLINE_RECURSIVE = 5;

    /**
     * Creates a new instance of AccessTreeNode
     *
     * @param resource DOCUMENT ME!
     */
    public AccessTreeNode(String resource) {
        //log.debug(">AccessTreeNode:" +resource);
        name = resource;
        useraccesspairs = new Vector();
        leafs = new HashMap();
    }

    /**
     * Checks the tree if the users X509Certificate is athorized to view the requested resource
     *
     * @param admininformation DOCUMENT ME!
     * @param resource DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isAuthorized(AdminInformation admininformation, String resource) {
        log.debug(">isAuthorized: " + resource);

        boolean retval = isAuthorizedRecursive(admininformation, resource, STATE_DECLINE); // Default is to decline access.
        log.debug("<isAuthorized: returns " + retval);

        return retval;
    }

    /**
     * Adds an access rule with associated admingroup to the tree.
     *
     * @param subresource DOCUMENT ME!
     * @param accessrule DOCUMENT ME!
     * @param admingroup DOCUMENT ME!
     */
    public void addAccessRule(String subresource, AccessRule accessrule, AdminGroup admingroup) {
        log.debug(">addAccessRule: " + subresource);

        int index;
        AccessTreeNode next;
        String nextname;
        String nextsubresource;

        if (subresource.equals(this.name)) { // Root is a special case.

            Object[] accessadmingroupair = { accessrule, admingroup };
            useraccesspairs.addElement(accessadmingroupair);
        } else {
            nextsubresource = subresource.substring(this.name.length());

            if ((nextsubresource.toCharArray()[0]) == '/') {
                nextsubresource = nextsubresource.substring(1);
            }

            index = nextsubresource.indexOf('/');

            if (index != -1) {
                nextname = nextsubresource.substring(0, index);
            } else {
                nextname = nextsubresource;
            }

            next = (AccessTreeNode) leafs.get(nextname);

            if (next == null) { // Doesn't exist, create.
                next = new AccessTreeNode(nextname);
                leafs.put(nextname, next);
            }

            //log.debug(this.name + " --> ");
            next.addAccessRule(nextsubresource, accessrule, admingroup);
        }

        log.debug("<addAccessRule: " + subresource);
    }

    // Private methods
    private boolean isLeaf() {
        return leafs.size() == 0;
    }

    private boolean isAuthorizedRecursive(AdminInformation admininformation, String resource,
        int state) {
        log.debug("isAuthorizedRecursive: " + " resource: " + resource + " name: " + this.name +
            "," + state);

        int index;
        int internalstate = STATE_DECLINE;
        boolean returnval = false;
        AccessTreeNode next;
        String nextname = null;
        boolean lastresource = false;
        String nextsubresource;
        Set keys;
        String matchname;

        internalstate = matchInformation(admininformation);

        if (resource.equals(this.name)) {
            // If this resource have state accept recursive state is given
            if ((state == STATE_ACCEPT_RECURSIVE) || (internalstate == STATE_ACCEPT) ||
                    (internalstate == STATE_ACCEPT_RECURSIVE)) {
                // If this resource's rule set don't says decline.
                if (!((internalstate == STATE_DECLINE) ||
                        (internalstate == STATE_DECLINE_RECURSIVE))) {
                    returnval = true;
                }
            }
        } else {
            //log.debug(" resource : " + resource);
            nextsubresource = resource.substring(this.name.length());

            if ((nextsubresource.toCharArray()[0]) == '/') {
                nextsubresource = nextsubresource.substring(1);
            }

            //log.debug(" nextresource : " + nextsubresource);
            index = nextsubresource.indexOf('/');

            if (index != -1) {
                nextname = nextsubresource.substring(0, index);
            } else {
                nextname = nextsubresource;
            }

            //log.debug(" nextname : " + nextname);
            next = (AccessTreeNode) leafs.get(nextname);

            if (next == null) { // resource path doesn't exist

                // If  internal state isn't decline recusive is accept recursive.
                if (internalstate == STATE_ACCEPT_RECURSIVE) {
                    returnval = true;
                }

                // If state accept recursive is given and internal state isn't decline recusive.
                if ((state == STATE_ACCEPT_RECURSIVE) &&
                        (internalstate != STATE_DECLINE_RECURSIVE) &&
                        (internalstate != STATE_DECLINE)) {
                    returnval = true;
                }

                /*     if(internalstate == STATE_ACCEPT && lastresource){
                       returnval=true;
                     } */
            }

            if (next != null) { // resource path exists.

                // If internalstate is accept recursive or decline recusive.
                if ((internalstate == STATE_ACCEPT_RECURSIVE) ||
                        (internalstate == STATE_DECLINE_RECURSIVE)) {
                    state = internalstate;
                }

                //log.debug(this.name + " --> ");
                returnval = next.isAuthorizedRecursive(admininformation, nextsubresource, state);
            }
        }

        log.debug("<isAthorizedRecursive: returns " + returnval + " : " + resource + "," + state);

        return returnval;
    }

    private int matchInformation(AdminInformation admininformation) {
        log.debug(">matchInformation");

        final int ACCESSRULE = 0;
        final int USERGROUP = 1;

        int state = STATE_UNKNOWN;
        int stateprio = 0;
        Object[] accessuserpair;
        AdminEntity[] adminentities;

        for (int i = 0; i < useraccesspairs.size(); i++) {
            accessuserpair = (Object[]) useraccesspairs.elementAt(i);
            adminentities = ((AdminGroup) accessuserpair[USERGROUP]).getAdminEntities();

            for (int j = 0; j < adminentities.length; j++) {
                // If user entity match.
                if (adminentities[j].match(admininformation)) {
                    int thisuserstate = ((AccessRule) accessuserpair[ACCESSRULE]).getRuleState();
                    int thisuserstateprio = adminentities[j].getPriority();

                    // If rule has higher priority, it's state is to be used.
                    if (stateprio < thisuserstateprio) {
                        state = thisuserstate;
                        stateprio = thisuserstateprio;
                    } else {
                        if (stateprio == thisuserstateprio) {
                            // If the priority is the same then decline has priority over accept.
                            if (state < thisuserstate) {
                                state = thisuserstate;
                            }
                        }
                    }
                }
            }
        }

        log.debug("<matchInformation: returns " + state);

        return state;
    }

    // Private fields.
    private String name;
    private Vector useraccesspairs;
    private HashMap leafs;
}
