package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>Java class for getProfile complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="getProfile">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="arg0" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="arg1" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getProfile", propOrder = {
   "arg0",
   "arg1"
})

public class GetProfile {

   protected int arg0;
   protected String arg1;

   /**
    * Gets the value of the arg0 property.
    * 
    */
   public int getArg0() {
       return arg0;
   }
 
   /**
    * Sets the value of the arg0 property.
    * 
    */
   public void setArg0(int value) {
       this.arg0 = value;
   }

   /**
    * Gets the value of the arg1 property.
    * 
    */
   public String getArg1() {
       return arg1;
   }

   /**
    * Sets the value of the arg1 property.
    * 
    */
   public void setArg1(String value) {
       this.arg1 = value;
   }
}