package org.cesecore.certificate.ca.its;

import java.io.Serializable;
import java.util.HashMap;

/**
 * ITS Certificate Type.
 */
public enum ITSCertificateType implements Serializable{
    EXPLICIT(0, "Explicit"),
    IMPLICIT(1, "Implicit");

    private static final HashMap<Integer, ITSCertificateType> typeMap = new HashMap<>();

    static {
        for(ITSCertificateType itsCertificateType : ITSCertificateType.values()) {
            typeMap.put(itsCertificateType.getType(), itsCertificateType);
        }
    }

    private final int type;
    private final String label;

    ITSCertificateType(int type, final String label) {
      this.type = type;
      this.label = label;
    }

    public int getType() {
      return this.type;
    }

    public String getLabel() {
        return this.label;
    }

    public static ITSCertificateType fromInt(final int type) {
        return typeMap.get(type);
    }
}
