package se.anatom.ejbca.ra.authorization;

import java.util.Collection;

/**
 * For docs, see UserGroupDataBean
 *
 * @version $Id: UserGroupDataLocal.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 **/

public interface UserGroupDataLocal extends javax.ejb.EJBLocalObject {

    // public methods

    public String getUserGroupName();
    public void setUserGroupName(String usergroupname);

    /**
     * Adds an accessrule to the database. Changes it's values if it already exists
     *
     */

    public void addAccessRule(String directory, int rule, boolean recursive);

    /**
     * Adds an array of accessrule to the database. Changes it's values if it already exists
     *
     */

    public void addAccessRules(AccessRule[] accessrules);

     /**
     * Removes an accessrule from the database.
     *
     */
    public void removeAccessRule(String directory);

     /**
     * Returns the number of access rules in usergroup
     *
     * @return the number of accessrules in the database
     */
    public int getNumberOfAccessRules();

     /**
      * Returns all the accessrules as an array of AccessRule
      *
      */
    public AccessRule[] getAccessRulesAsArray();

     /**
     * Adds a user entity to the database. Changes it's values if it already exists
     *
     */

    public void addUserEntity(int matchwith, int matchtype, String matchvalue);

     /**
     * Adds an array of user entity to the database. Changes it's values if it already exists
     *
     */

    public void addUserEntities(UserEntity[] userentities);

     /**
     * Removes a user entity from the database.
     *
     */
    public void removeUserEntity(int matchwith, int matchtype, String matchvalue);

     /**
     * Returns the number of user entities in usergroup
     *
     * @return the number of user entities in the database
     */
    public int getNumberOfUserEntities();

     /**
      * Returns all the UserEntities as an array of UserEntities
      *
      */
    public UserEntity[] getUserEntitiesAsArray();

     /**
      * Returns the data in usergroup representation.
      */
    public UserGroup getUserGroup();

}

