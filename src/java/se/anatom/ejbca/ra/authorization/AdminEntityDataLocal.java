package se.anatom.ejbca.ra.authorization;

/**
 * For docs, see AdminEntityDataBean
 *
 * @version $Id: AdminEntityDataLocal.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface AdminEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public Integer getMatchWith();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Integer getMatchType();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getMatchValue();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminEntity getAdminEntity();
}
