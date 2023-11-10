package org.ejbca.core.protocol.msae;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

public interface KecCache {
    
    public Certificate getCachedKEC(final AuthenticationToken admin, final int cAId, final int cPId)
            throws CertificateEncodingException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException, OperatorCreationException, IllegalNameException,
            AuthorizationDeniedException, CertificateExtensionException, KeyArchivalException;

    
    public void flushKecCache();
}
