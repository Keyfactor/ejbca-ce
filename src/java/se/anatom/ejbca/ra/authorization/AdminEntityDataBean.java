package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a admin entity in EJBCA authorization module
 * Information stored:
 * <pre>
 *   matchwith
 *   matchtype
 *   matchvalue
 * </pre>
 *
 * @version $Id: AdminEntityDataBean.java,v 1.3 2003-02-28 09:26:45 koen_serry Exp $
 */
public abstract class AdminEntityDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(AdminEntityDataBean.class);

    public abstract int          getPK();
    public abstract Integer      getMatchWith();
    public abstract Integer      getMatchType();
    public abstract String       getMatchValue();

    public abstract void setPK(int pK);
    public abstract void setMatchWith(Integer matchwith);
    public abstract void setMatchType(Integer matchtype);
    public abstract void setMatchValue(String matchvalue);


    public AdminEntity getAdminEntity(){
      return new AdminEntity(getMatchWith().intValue(), getMatchType().intValue(), getMatchValue());
    }


    //
    // Fields required by Container
    //


    public AdminEntityPK ejbCreate(String admingroupname, int matchwith, int matchtype, String matchvalue) throws CreateException {

        AdminEntityPK pk = new AdminEntityPK(admingroupname, matchwith,matchtype,matchvalue);
        setPK(pk.hashCode());
        setMatchWith(new Integer(matchwith));
        setMatchType(new Integer(matchtype));
        setMatchValue(matchvalue);


        log.debug("Created admin entity "+ matchvalue);
        return pk;
    }

    public void ejbPostCreate(String admingroupname, int matchwith, int matchtype, String matchvalue) {
        // Do nothing. Required.
    }
}
