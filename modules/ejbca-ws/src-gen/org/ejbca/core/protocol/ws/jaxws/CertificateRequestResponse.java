
package org.ejbca.core.protocol.ws.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "certificateRequestResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "certificateRequestResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class CertificateRequestResponse {

    @XmlElement(name = "return", namespace = "")
    private org.ejbca.core.protocol.ws.objects.CertificateResponse _return;

    /**
     * 
     * @return
     *     returns CertificateResponse
     */
    public org.ejbca.core.protocol.ws.objects.CertificateResponse getReturn() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void setReturn(org.ejbca.core.protocol.ws.objects.CertificateResponse _return) {
        this._return = _return;
    }

}
