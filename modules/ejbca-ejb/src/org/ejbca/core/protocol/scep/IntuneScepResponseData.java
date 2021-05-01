/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.scep;

import java.io.Serializable;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

public class IntuneScepResponseData implements Serializable {
    private static final long serialVersionUID = 1L;

    private X500Principal issuer;
    private BigInteger serialNumber;
    private Instant notAfter;
    private byte[] thumbprint;

    public IntuneScepResponseData(X500Principal issuer, BigInteger serialNumber, Instant notAfter, byte[] thumbprint) {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notAfter = notAfter;
        this.thumbprint = thumbprint;
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

    @Override
    public String toString() {
        return "IntuneScepResponseData [" + (issuer != null ? "issuer=" + issuer + ", " : "")
                + (serialNumber != null ? "serialNumber=" + serialNumber + ", " : "") + (notAfter != null ? "notAfter=" + notAfter + ", " : "")
                + (thumbprint != null ? "thumbprint=" + Arrays.toString(thumbprint) : "") + "]";
    }

}
