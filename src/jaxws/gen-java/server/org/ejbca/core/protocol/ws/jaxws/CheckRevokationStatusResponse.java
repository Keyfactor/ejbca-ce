
package org.ejbca.core.protocol.ws.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;

@XmlRootElement(name = "checkRevokationStatusResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "checkRevokationStatusResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class CheckRevokationStatusResponse {

    @XmlElement(name = "return", namespace = "")
    private RevokeStatus _return;

    /**
     * 
     * @return
     *     returns RevokeStatus
     */
    public RevokeStatus get_return() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void set_return(RevokeStatus _return) {
        this._return = _return;
    }

}
