package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;
import se.anatom.ejbca.ca.store.certificatetypes.*;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a certificate type in the ra web interface.
 * Information stored:
 * <pre>
 *  id (Primary key)
 * CertificateType name
 * CertificateType data
 * </pre>
 *
 * @version $Id: ProfileDataBean.java,v 1.4 2002/07/22 10:38:48 anatom Exp $
 **/

public abstract class CertificateTypeDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(CertificateTypeDataBean.class.getName() );


    protected EntityContext  ctx;
    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getCertificateTypeName();
    public abstract void setCertificateTypeName(String certificatetypename);

    public abstract CertificateType getCertificateType();
    public abstract void setCertificateType(CertificateType certificatetype);

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a raadmin profile.
     * @param certificatetypename.
     * @param certificatetype is the CertificateType.
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String certificatetypename, CertificateType certificatetype) throws CreateException {
        setId(id);
        setCertificateTypeName(certificatetypename);
        setCertificateType(certificatetype);
        log.debug("Created certificatetype "+ certificatetypename );
        return id;
    }

    public void ejbPostCreate(Integer id, String certificatetypename, CertificateType certificatetype) {
        // Do nothing. Required.
    }

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

