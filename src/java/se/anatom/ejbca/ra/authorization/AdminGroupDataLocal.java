package se.anatom.ejbca.ra.authorization;

/**
 * For docs, see AdminGroupDataBean
 *
 * @version $Id: AdminGroupDataLocal.java,v 1.2 2003-01-12 17:16:30 anatom Exp $
 **/
public interface AdminGroupDataLocal extends javax.ejb.EJBLocalObject {

    // public methods

    public String getAdminGroupName();
    public void setAdminGroupName(String admingroupname);

    /**
     * Adds an accessrule to the database. Changes it's values if it already exists
     *
     */

    public void addAccessRule(String resource, int rule, boolean recursive);

    /**
     * Adds an array of accessrule to the database. Changes it's values if it already exists
     *
     */

    public void addAccessRules(AccessRule[] accessrules);

     /**
     * Removes an accessrule from the database.
     *
     */
    public void removeAccessRule(String resource);

     /**
     * Returns the number of access rules in admingroup
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

    public void addAdminEntity(int matchwith, int matchtype, String matchvalue);

     /**
     * Adds an array of user entity to the database. Changes it's values if it already exists
     *
     */

    public void addAdminEntities(AdminEntity[] adminentities);

     /**
     * Removes a user entity from the database.
     *
     */
    public void removeAdminEntity(int matchwith, int matchtype, String matchvalue);

     /**
     * Returns the number of user entities in admingroup
     *
     * @return the number of user entities in the database
     */
    public int getNumberOfAdminEntities();

     /**
      * Returns all the AdminEntities as an array of AdminEntities
      *
      */
    public AdminEntity[] getAdminEntitiesAsArray();

     /**
      * Returns the data in admingroup representation.
      */
    public AdminGroup getAdminGroup();

}

