package se.anatom.ejbca.util;

/**
 * IUpgradableData is an interface intended to be used by classed saved to database as BLOB. Every
 * such class should put all it's data in one of the Collection data structures and it will only
 * be the collection saved to the database. This is to avoid serialization problems when upgrading
 * the class.
 *
 * @version $Id: IUpgradeableData.java,v 1.3 2003-06-26 11:43:25 anatom Exp $
 */
public interface IUpgradeableData {
    /**
     * Should return a constant containing the latest available version of the class.
     *
     * @return DOCUMENT ME!
     */
    public abstract float getLatestVersion();

    /**
     * Function returning the current version of the class data.
     *
     * @return DOCUMENT ME!
     */
    public abstract float getVersion();

    /**
     * Function sending the data to be saved to the database.
     *
     * @return DOCUMENT ME!
     */
    public abstract Object saveData();

    /**
     * Function loading saved data into to data structure.
     */
    public abstract void loadData(Object data);

    /**
     * Function that should handle the update of the data in the class so it's up to date with the
     * latest version.
     */
    public abstract void upgrade();
}
