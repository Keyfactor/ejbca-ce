package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * admin entity in EJBCA authorization module Information stored:
 * <pre>
 *   matchwith
 *   matchtype
 *   matchvalue
 * </pre>
 *
 * @version $Id: AdminEntityDataBean.java,v 1.6 2003-07-24 08:43:31 anatom Exp $
 */
public abstract class AdminEntityDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(AdminEntityDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getPK();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getMatchWith();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getMatchType();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getMatchValue();

    /**
     * DOCUMENT ME!
     *
     * @param pK DOCUMENT ME!
     */
    public abstract void setPK(int pK);

    /**
     * DOCUMENT ME!
     *
     * @param matchwith DOCUMENT ME!
     */
    public abstract void setMatchWith(Integer matchwith);

    /**
     * DOCUMENT ME!
     *
     * @param matchtype DOCUMENT ME!
     */
    public abstract void setMatchType(Integer matchtype);

    /**
     * DOCUMENT ME!
     *
     * @param matchvalue DOCUMENT ME!
     */
    public abstract void setMatchValue(String matchvalue);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminEntity getAdminEntity() {
        return new AdminEntity(getMatchWith().intValue(), getMatchType().intValue(), getMatchValue());
    }

    //
    // Fields required by Container
    //
    public AdminEntityPK ejbCreate(String admingroupname, int matchwith, int matchtype,
        String matchvalue) throws CreateException {
        AdminEntityPK pk = new AdminEntityPK(admingroupname, matchwith, matchtype, matchvalue);
        setPK(pk.hashCode());
        setMatchWith(new Integer(matchwith));
        setMatchType(new Integer(matchtype));
        setMatchValue(matchvalue);

        log.debug("Created admin entity " + matchvalue);

        return pk;
    }

    /**
     * DOCUMENT ME!
     *
     * @param admingroupname DOCUMENT ME!
     * @param matchwith DOCUMENT ME!
     * @param matchtype DOCUMENT ME!
     * @param matchvalue DOCUMENT ME!
     */
    public void ejbPostCreate(String admingroupname, int matchwith, int matchtype, String matchvalue) {
        // Do nothing. Required.
    }
}
