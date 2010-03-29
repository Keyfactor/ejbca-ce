
package org.ejbca.core.protocol.ws.jaxws;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "caCertResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "caCertResponse", namespace = "http://ws.protocol.core.ejbca.org/", propOrder = {
    "arg0",
    "arg1",
    "arg2",
    "arg3"
})
public class CaCertResponse {

    @XmlElement(name = "arg0", namespace = "")
    private String arg0;
    @XmlElement(name = "arg1", namespace = "", nillable = true)
    private byte[] arg1;
    @XmlElement(name = "arg2", namespace = "")
    private List<byte[]> arg2;
    @XmlElement(name = "arg3", namespace = "")
    private String arg3;

    /**
     * 
     * @return
     *     returns String
     */
    public String getArg0() {
        return this.arg0;
    }

    /**
     * 
     * @param arg0
     *     the value for the arg0 property
     */
    public void setArg0(String arg0) {
        this.arg0 = arg0;
    }

    /**
     * 
     * @return
     *     returns byte[]
     */
    public byte[] getArg1() {
        return this.arg1;
    }

    /**
     * 
     * @param arg1
     *     the value for the arg1 property
     */
    public void setArg1(byte[] arg1) {
        this.arg1 = arg1;
    }

    /**
     * 
     * @return
     *     returns List<byte[]>
     */
    public List<byte[]> getArg2() {
        return this.arg2;
    }

    /**
     * 
     * @param arg2
     *     the value for the arg2 property
     */
    public void setArg2(List<byte[]> arg2) {
        this.arg2 = arg2;
    }

    /**
     * 
     * @return
     *     returns String
     */
    public String getArg3() {
        return this.arg3;
    }

    /**
     * 
     * @param arg3
     *     the value for the arg3 property
     */
    public void setArg3(String arg3) {
        this.arg3 = arg3;
    }

}
