
package org.ejbca.core.protocol.ws.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "caRenewCertRequestResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "caRenewCertRequestResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class CaRenewCertRequestResponse {

    @XmlElement(name = "return", namespace = "", nillable = true)
    private byte[] _return;

    /**
     * 
     * @return
     *     returns byte[]
     */
    public byte[] getReturn() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void setReturn(byte[] _return) {
        this._return = _return;
    }

}
