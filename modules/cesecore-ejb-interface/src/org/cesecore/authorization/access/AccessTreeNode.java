/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.access;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.roles.RoleData;

/**
 * This access tree effectively maps the resources that we control. Each node corresponds to a resource level, and the leafs individual resources,
 * much like directories and files in a file tree. Rights are likewise hierarchical, which means that denial at a shallow level closes off access to
 * any deeper structures.
 * 
 * Each node of an access tree contains the following:
 * <ul>
 * <li>A reference to the resource that this node represents (i.e.<i>rootnode/subnode_a/subnode_a_b/subnode_a_b_a</i>)</li>
 * <li>A list of tuplets linking {@link RoleData} objects with {@link AccessRuleData} objects.</li>
 * <li>A list of leafs to this branch.</li>
 * </ul>
 * 
 * The flow when entering this node is as follows:
 * 
 * <ol>
 * <li>Entering this node, parameters will be a {@link AuthenticationToken}, a reference to the sought resource and the greediest access rule derived
 * in the previous step. The importance of this last parameter will become clear.</li>
 * <li>The groups the supplied AuthenticationToken is a member of are extracted, and access rules are checked.</li>
 * <li>At this point, the following may happen:
 * <ol type="i">
 * <li>If this is the final node of our sought resource and there is a valid Role to which the sought user is a member with an AccessRule of type
 * STATE_ACCEPT or STATE_ACCEPT_RECURSIVE, return true.</li>
 * <li>If the best result we find is STATE_DENIED, or no result at all, return false.</li>
 * <li>If we encounter a STATE_ACCEPT and the AccessRule is recursive but have not reached the final node, recurse down the next node of the tree,
 * passing the STATE_ACCEPT_RECURSIVE result along.
 * <li>If the best result we find is STATE_UNKNOWN <b>and</b> we have previously encountered a STATE_ACCEPT_RECURSIVE, then keep recursing.
 * </ol>
 * </li>
 * </ol>
 * 
 * Probably based on EJBCA's AccessTreeNode r11153 (updated 2011-01-12).
 * 
 * @version $Id$
 * 
 */
public class AccessTreeNode {

    private static final Logger log = Logger.getLogger(AccessTreeNode.class);

    private String resource;
    private Collection<AbstractMap.SimpleEntry<RoleData, AccessRuleData>> roleRulePairs;
    private HashMap<String, AccessTreeNode> leafs;

    /**
     * Creates a new instance of AccessTreeNode
     */
    public AccessTreeNode(String resource) {
        this.resource = resource;
        this.roleRulePairs = new ArrayList<AbstractMap.SimpleEntry<RoleData, AccessRuleData>>();
        this.leafs = new HashMap<String, AccessTreeNode>();
    }

    /**
     * Entrance method.
     * 
     * Will by default accept recursive and non-recursive accept values. 
     * 
     * @param role
     *            Role to check access for.
     * @param resourcePath
     *            Resource to investigate
     * @return True if role is authorized to resource.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String resourcePath)
            throws AuthenticationFailedException {
        return isAuthorizedRecursive(authenticationToken, resourcePath, AccessTreeState.STATE_UNKNOWN, false);

    }
    
    /**
     * Entrance method.
     * 
     * TODO: Unit test this method.
     * 
     * @param role
     *            Role to check access for.
     * @param resourcePath
     *            Resource to investigate
     * @param requireRecursive true if only accept recursive values should be accepted. 
     * @return True if role is authorized to resource.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    public boolean isAuthorized(final AuthenticationToken authenticationToken, final String resourcePath, final boolean requireRecursive)
            throws AuthenticationFailedException {
        return isAuthorizedRecursive(authenticationToken, resourcePath, AccessTreeState.STATE_UNKNOWN, requireRecursive);

    }

    /**
     * Performs a recursive check of authorization through this resource, and all below it.
     * 
     * @param role
     *            Role to check for.
     * @param resourcePath
     *            Resource to check.
     * @param legacyState
     *            The best state yet encountered.
     * @param requireRecursive true if only accept recursive values should be accepted
     * @return True of role is authorized to resource.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    private boolean isAuthorizedRecursive(final AuthenticationToken authenticationToken, final String resourcePath, AccessTreeState legacyState,
            final boolean requireRecursive) throws AuthenticationFailedException {
        if (log.isTraceEnabled()) {
        log.trace(">isAuthorizedRecursive("+authenticationToken.toString()+", "+resourcePath+", "+legacyState+"). Resource="+resource);
        }
        boolean returnval = false;

        AccessTreeState internalstate = findPreferredRule(authenticationToken);
        if (log.isTraceEnabled()) {
            log.trace("preferredRule: "+internalstate);
        }
        if (resourcePath.equals(resource)) {
            if (legacyState == AccessTreeState.STATE_DECLINE) {
                if (log.isTraceEnabled()) {
                    log.trace("Rejecting because legacyState is AccessTreeState.STATE_DECLINE");
                }
                returnval = false;
            } else if (legacyState == AccessTreeState.STATE_ACCEPT_RECURSIVE) {
                // If this resource have state accept recursive state is given
                if (internalstate != AccessTreeState.STATE_DECLINE) {
                    returnval = true;
                }
            } else {
                if((internalstate == AccessTreeState.STATE_ACCEPT && !requireRecursive) || internalstate == AccessTreeState.STATE_ACCEPT_RECURSIVE) {
                    returnval = true;
                }
            }
        } else {
            String nextsubresource = resourcePath.substring(resource.length());
            if ((nextsubresource.toCharArray()[0]) == '/') {
                nextsubresource = nextsubresource.substring(1);
            }

            int index = nextsubresource.indexOf('/');
            String nextname;
            if (index != -1) {
                nextname = nextsubresource.substring(0, index);
            } else {
                nextname = nextsubresource;
            }

            final AccessTreeNode next = (AccessTreeNode) leafs.get(nextname);
            if (next == null) { // resource path doesn't exist            
                // If internal state is accept recursive.
                if (internalstate == AccessTreeState.STATE_ACCEPT_RECURSIVE) {
                    returnval = true;
                } else if (legacyState == AccessTreeState.STATE_ACCEPT_RECURSIVE && internalstate != AccessTreeState.STATE_DECLINE) {
                    // If state accept recursive is given and internal state isn't decline .
                    returnval = true;
                } else {
                    if (log.isTraceEnabled()) {
                        log.trace("Not accepting because state is not STATE_ACCEPT_RECURSIVE. Internalstate=" + internalstate + ", legacyState="
                                + legacyState);
                    }
                }           
            } else { // resource path exists.
                     // If internalstate is accept recursive or decline.
                if (internalstate == AccessTreeState.STATE_ACCEPT_RECURSIVE || internalstate == AccessTreeState.STATE_DECLINE) {
                    legacyState = internalstate;
                }
                returnval = next.isAuthorizedRecursive(authenticationToken, nextsubresource, legacyState, requireRecursive);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<isAuthorizedRecursive("+authenticationToken.toString()+", "+resourcePath+", "+legacyState+"): "+returnval);
        }
        return returnval;
    }

    /**
     * Adds an access rule with associated role to the tree.
     * 
     * TODO: Look over the string manipulation in this method, see if it can be improved. TODO: Unit test extensively.
     * 
     * @param subresource
     *            The name of the resource to add a role/rule to.
     * @param accessRule
     *            The desired AccessRule
     * @param role
     *            The desired Role
     */
    public void addAccessRule(String resource, AccessRuleData accessRule, RoleData role) {

        if (resource.equals(this.resource)) {
            roleRulePairs.add(new AbstractMap.SimpleEntry<RoleData, AccessRuleData>(role, accessRule));
        } else {
            String nextsubresource = resource.substring(this.resource.length());
            if ((nextsubresource.toCharArray()[0]) == '/') {
                nextsubresource = nextsubresource.substring(1);
            }

            int index = nextsubresource.indexOf('/');
            String nextname;
            if (index != -1) {
                nextname = nextsubresource.substring(0, index);
            } else {
                nextname = nextsubresource;
            }

            AccessTreeNode next = leafs.get(nextname);
            if (next == null) { // Doesn't exist, create.
                next = new AccessTreeNode(nextname);
                leafs.put(nextname, next);
            }
            next.addAccessRule(nextsubresource, accessRule, role);
        }
    }

    /** Finds the user aspect matching with the highest priority for the authentication token
     * and return the AccessTreeState for the rule with the highest priority.
     * Important if the UserAspect matches more than one rule.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    private AccessTreeState findPreferredRule(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        AccessTreeState state = null; 
        AccessMatchValue statePriority = authenticationToken.getDefaultMatchValue();
        if (log.isTraceEnabled()) {
            log.trace("AccessTreeNode " + resource + " has " + roleRulePairs.size() + " roleRulePairs");
        }
        SEARCH_ALL_ROLE_RULE_PAIRS: for (AbstractMap.SimpleEntry<RoleData, AccessRuleData> roleRulePair : roleRulePairs) {
            final Collection<AccessUserAspectData> accessUsers = roleRulePair.getKey().getAccessUsers().values();
            if (log.isTraceEnabled()) {
                log.trace("roleRulePair for accessRuleName " + roleRulePair.getValue().getAccessRuleName() + " has " + accessUsers.size()
                        + " accessUsers");
            }
            for (AccessUserAspect accessUser : accessUsers) {
                // If aspect is of the correct token type
                if (authenticationToken.matchTokenType(accessUser.getTokenType())) {
                    // And the two principals match (done inside to save on cycles)
                    if (authenticationToken.matches(accessUser)) {
                        /*
                         * The below line is a hack in order to allow supertokens. By setting state = null at the top of this
                         * method, any authentication token that doesn't match will get STATE_UNKNOWN in this method's last line. 
                         * 
                         * Should we match token type and access user, we have a special state where we can let an authentication token
                         * be a super token by setting the return of getDefaultMatchValue() to Integer.MaxInt, hence trumping any other 
                         * matches done by this method. This eliminates the need for any reflective code for supertokens. 
                         */
                        if (state == null) {
                            //Only set state to A+R if this is the first run
                            state = AccessTreeState.STATE_ACCEPT_RECURSIVE;
                        }
                        final AccessTreeState thisUserState = roleRulePair.getValue().getTreeState();
                        final AccessMatchValue thisUserStatePriority = authenticationToken.getMatchValueFromDatabaseValue(accessUser.getMatchWith());
                        if (log.isTraceEnabled()) {
                            /*
                             * Note that this entire block is only for trace logging and does not affect 
                             * the surrounding code in any way.
                             */
                            AccessTreeState logState = thisUserState;
                            if (logState == null) {
                                log.trace("logState is null for authenticationToken " + authenticationToken.toString());
                                logState = AccessTreeState.STATE_UNKNOWN;
                            }
                            AccessMatchValue logMatchValue = thisUserStatePriority;
                            if (logMatchValue == null) {
                                log.trace("logMatchValue is null for authenticationToken " + authenticationToken.toString());
                                logMatchValue = authenticationToken.getDefaultMatchValue();
                            }
                            final AccessMatchType matchType = accessUser.getMatchTypeAsType();
                            log.trace("accessUser " + logMatchValue.name() + " " + (matchType == null ? "null" : matchType.name()) + " "
                                    + accessUser.getMatchValue() + " matched authenticationToken. thisUserState=" + logState.name()
                                    + " thisUserStatePriority=" + thisUserStatePriority);
                        }
                        // If rule has higher priority, its state is to be used.
                        if (statePriority.getNumericValue() < thisUserStatePriority.getNumericValue()) {
                            state = thisUserState;
                            statePriority = thisUserStatePriority;
                        } else {
                            if (statePriority == thisUserStatePriority) {
                                // If the priority is the same then decline has priority over accept.
                                if (state.getLegacyNumber() < thisUserState.getLegacyNumber()) {
                                    state = thisUserState;
                                }
                            }
                        }
                        if(statePriority.getNumericValue() == Integer.MAX_VALUE) {            
                            break SEARCH_ALL_ROLE_RULE_PAIRS;
                        }
                        
                    } else if (log.isTraceEnabled()) {
                        log.trace("accessUser " + authenticationToken.getMatchValueFromDatabaseValue(accessUser.getMatchWith()).name() + " " + accessUser.getMatchTypeAsType().name() + " "
                                + accessUser.getMatchValue() + " did not match authenticationToken.");
                    }
                }
            }
        }
        //If no matches were made, return AccessTreeState.STATE_UNKNOWN
        if (state == null) {
            state = AccessTreeState.STATE_UNKNOWN;
        }
        return state;
    }

    public String getResource() {
        return resource;
    }

}
