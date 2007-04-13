
package org.ejbca.core.protocol.ws.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.ejbca.core.protocol.ws.objects.Certificate;

@XmlRootElement(name = "getCertificateResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getCertificateResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class GetCertificateResponse {

    @XmlElement(name = "return", namespace = "")
    private Certificate _return;

    /**
     * 
     * @return
     *     returns Certificate
     */
    public Certificate get_return() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void set_return(Certificate _return) {
        this._return = _return;
    }

}
