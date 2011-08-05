/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp.standalonesession;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.protocol.ocsp.OCSPUtil;

/**
 * An object of this class is used to sign OCSP responses for certificates belonging to one CA.
 * @version $Id$
 */
class SigningEntity {
    /**
     * Log object.
     */
    static final private Logger m_log = Logger.getLogger(SigningEntity.class);
    /**
     * The certificate chain with the CA of the signer on top.
     */
    final private List<X509Certificate> chain;
    /**
     * The signing key.
     */
    final PrivateKeyContainer keyContainer;
    /**
     * The provider to be used when signing.
     */
    final ProviderHandler providerHandler;
    /**
     * The object is ready to sign after this constructor has been called.
     * @param c Certificate chain with CA for which OCSP requests should be signed on top.
     * @param f The signing key.
     * @param ph The provider.
     */
    SigningEntity(List<X509Certificate> c, PrivateKeyContainer f, ProviderHandler ph) {
        this.chain = c;
        this.keyContainer = f;
        this.providerHandler = ph;
    }
    /**
     * Get certificate chain. With signing certificate on top.
     * @return The chain.
     */
    X509Certificate[] getCertificateChain() {
        return getCertificateChain(this.keyContainer.getCertificate());
    }
    /**
     * Add certificate on top of certificate chain.
     * @param entityCert The certificate to be on top.
     * @return The certificate chain.
     */
    private X509Certificate[] getCertificateChain(final X509Certificate entityCert) {
        final List<X509Certificate> entityChain = new ArrayList<X509Certificate>(this.chain);
        if ( entityCert==null ) {
            m_log.error("CA "+this.chain.get(0).getSubjectDN()+" has no signer.");
            return null;
        }
        entityChain.add(0, entityCert);
        return entityChain.toArray(new X509Certificate[0]);
    }
    /**
     * Initiates key key renewal.
     * @param caid The EJBCA CA id for the CA.
     */
    void init(int caid) {
        this.providerHandler.addKeyContainer(this.keyContainer);
        this.keyContainer.init(this.chain, caid);
    }
    /**
     * Stops key renewal.
     */
    void shutDown() {
        this.keyContainer.destroy();
    }
    /* (non-Javadoc)
     * @see java.lang.Object#finalize()
     */
    @Override
    protected void finalize() throws Throwable {
        // break up circular dependence that prevents the keyContainer to be destroyed.
        shutDown();
        super.finalize();
    }
    /**
     * Signs a OCSP response.
     * @param request The response to be signed.
     * @return The signed response.
     * @throws ExtendedCAServiceRequestException
     * @throws IllegalExtendedCAServiceRequestException
     */
    OCSPCAServiceResponse sign( OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException {
        final String hsmErrorString = "HSM not functional";
        final String providerName = this.providerHandler.getProviderName();
        final long HSM_DOWN_ANSWER_TIME = 15000; 
        if ( providerName==null ) {
            synchronized(this) {
                try {
                    this.wait(HSM_DOWN_ANSWER_TIME); // Wait here to prevent the client repeat the request right away. Some CPU power might be needed to recover the HSM.
                } catch (InterruptedException e) {
                    throw new Error(e); //should never ever happen. The main thread should never be interrupted.
                }
            }
            throw new ExtendedCAServiceRequestException(hsmErrorString+". Waited "+HSM_DOWN_ANSWER_TIME/1000+" seconds to throw the exception");
        }
        final PrivateKey privKey;
        final X509Certificate entityCert;
        try {
            privKey = this.keyContainer.getKey();
            entityCert = this.keyContainer.getCertificate(); // must be after getKey
        } catch (ExtendedCAServiceRequestException e) {
            this.providerHandler.reload();
            throw e;
        } catch (Exception e) {
            this.providerHandler.reload();
            throw new ExtendedCAServiceRequestException(e);
        }
        if ( privKey==null ) {
            throw new ExtendedCAServiceRequestException(hsmErrorString);
        }
        try {
            return OCSPUtil.createOCSPCAServiceResponse(request, privKey, providerName, getCertificateChain(entityCert));
        } catch( ExtendedCAServiceRequestException e) {
            this.providerHandler.reload();
            throw e;
        } catch( IllegalExtendedCAServiceRequestException e ) {
            throw e;
        } catch( Throwable e ) {
            this.providerHandler.reload();
            final ExtendedCAServiceRequestException e1 = new ExtendedCAServiceRequestException(hsmErrorString);
            e1.initCause(e);
            throw e1;
        } finally {
            this.keyContainer.releaseKey();
        }
    }
    /**
     * Checks if the signer could be used.
     * @return True if OK.
     */
    boolean isOK() {
        try {
            return this.keyContainer.isOK();
        } catch (Exception e) {
            m_log.info("Exception thrown when accessing the private key: ", e);
            return false;
        }
    }
}