package se.anatom.ejbca.keyrecovery;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.math.BigInteger;
import java.util.Date;
import java.security.KeyPair;
import org.apache.log4j.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a certificates key recovery data in the ra.
 * Information stored:
 * <pre>
 *  pk (Primary key, hashcodes of certificatesn and issuerdn)
 *  certificatesn
 *  issuerdn
 *  username
 *  markedasrecoverable
 *  keypair
 * </pre>
 *
 * @version $Id: KeyRecoveryDataBean.java,v 1.2 2003-02-19 10:20:39 anatom Exp $
 **/

public abstract class KeyRecoveryDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(KeyRecoveryDataBean.class.getName() );

    protected EntityContext  ctx;
    public abstract int getPK();
    public abstract void setPK(int pK);

    public abstract String getCertSN();
    public abstract void setCertSN(String certificatesn);

    public abstract String getIssuerDN();
    public abstract void setIssuerDN(String issuerdn);

    public abstract String getUsername();
    public abstract void setUsername(String username);

    public abstract boolean getMarkedAsRecoverable();
    public abstract void setMarkedAsRecoverable(boolean markedasrecoverable);

    public abstract KeyPair getKeyPair();
    public abstract void setKeyPair(KeyPair keypair);

    public BigInteger getCertificateSN(){ return new BigInteger(getCertSN(),16);  }
    public void setCertificateSN(BigInteger certificatesn){ setCertSN(certificatesn.toString(16)); }

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding keyrecovery data of users certificate.
     *
     * @return Primary Key
     *
     **/

    public KeyRecoveryDataPK ejbCreate(BigInteger certificatesn, String issuerdn, String username, KeyPair keypair) throws CreateException {
        KeyRecoveryDataPK pk = new KeyRecoveryDataPK(certificatesn,issuerdn);
        setPK(pk.pK);
        setCertificateSN(certificatesn);
        setIssuerDN(issuerdn);
        setUsername(username);
        setMarkedAsRecoverable(false);
        setKeyPair(keypair);

        log.debug("Created Key Recoverydata for user "+ username );
        return pk;
    }

    public void ejbPostCreate(BigInteger certificatesn, String issuerdn, String username, KeyPair keypair) {
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

