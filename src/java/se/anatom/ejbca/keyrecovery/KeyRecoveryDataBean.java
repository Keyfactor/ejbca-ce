package se.anatom.ejbca.keyrecovery;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.math.BigInteger;
import java.util.Date;
import java.security.KeyPair;
import org.apache.log4j.*;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;

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
 * @version $Id: KeyRecoveryDataBean.java,v 1.4 2003-02-28 09:25:57 koen_serry Exp $
 **/

public abstract class KeyRecoveryDataBean extends BaseEntityBean {



    private static Category log = Category.getInstance(KeyRecoveryDataBean.class.getName() );

    public abstract int getPK();
    public abstract void setPK(int pK);

    public abstract String getCertSN();
    public abstract void setCertSN(String certificatesn);

    public abstract String getIssuerDN();
    public abstract void setIssuerDN(String issuerdn);

    public abstract String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
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
        setUsername(StringTools.strip(username));
        setMarkedAsRecoverable(false);
        setKeyPair(keypair);

        log.debug("Created Key Recoverydata for user "+ username );
        return pk;
    }

    public void ejbPostCreate(BigInteger certificatesn, String issuerdn, String username, KeyPair keypair) {
        // Do nothing. Required.
    }
}

