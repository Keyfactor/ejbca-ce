/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ca.sign;
import java.io.Serializable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.cesecore.certificates.certificate.request.FailInfo;

public class IntuneScepResponseData implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean failed = false;
    private X500Principal issuer = null;
    private BigInteger serialNumber = null;
    private Instant notAfter = null;
    private byte[] thumbprint = null;
    private FailInfo failInfo = null;
    private String failText = null;

    public IntuneScepResponseData(X500Principal issuer, BigInteger serialNumber, Instant notAfter, byte[] thumbprint) {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notAfter = notAfter;
        this.thumbprint = thumbprint;
        failed = false;
    }

    public IntuneScepResponseData(FailInfo failInfo, String failText) {
        this.failInfo = failInfo;
        this.failText = failText;
        failed = true;
    }

    public static final long getSerialversionuid() {
        return serialVersionUID;
    }

    public final X500Principal getIssuer() {
        return issuer;
    }

    public final BigInteger getSerialNumber() {
        return serialNumber;
    }

    public final Instant getNotAfter() {
        return notAfter;
    }

    public final byte[] getThumbprint() {
        return thumbprint;
    }

    public final boolean isFailed() {
        return failed;
    }

    public final FailInfo getFailInfo() {
        return failInfo;
    }

    public final String getFailText() {
        return failText;
    }

    @Override
    public String toString() {
        return "IntuneScepResponseData [failed=" + failed + ", " + (issuer != null ? "issuer=" + issuer + ", " : "")
                + (serialNumber != null ? "serialNumber=" + serialNumber + ", " : "") + (notAfter != null ? "notAfter=" + notAfter + ", " : "")
                + (thumbprint != null ? "thumbprint=" + Arrays.toString(thumbprint) + ", " : "")
                + (failInfo != null ? "failInfo=" + failInfo + ", " : "") + (failText != null ? "failText=" + failText : "") + "]";
    }

}
