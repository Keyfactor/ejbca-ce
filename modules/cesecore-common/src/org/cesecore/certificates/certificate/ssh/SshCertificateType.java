/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate.ssh;

import java.io.Serializable;
import java.util.HashMap;

/**
 * SSH Certificate Type.
 *
 * @version $Id$
 */
public enum SshCertificateType implements Serializable{
    USER(1, "User"),
    HOST(2, "Host");

    private static final HashMap<Integer, SshCertificateType> typeMap = new HashMap<>();

    static {
        for(SshCertificateType sshCertificateType : SshCertificateType.values()) {
            typeMap.put(sshCertificateType.getType(), sshCertificateType);
        }
    }

    private final int type;
    private final String label;

    SshCertificateType(int type, final String label) {
      this.type = type;
      this.label = label;
    }

    public int getType() {
      return this.type;
    }

    public String getLabel() {
        return this.label;
    }

    public static SshCertificateType fromInt(final int type) {
        return typeMap.get(type);
    }
}
