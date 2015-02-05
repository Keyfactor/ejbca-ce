package org.ejbca.core.protocol.ws.client.gen;

import java.util.HashMap;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>Java class for createCryptoToken complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="createCryptoToken">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="arg0" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg1" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg2" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg3" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="arg4" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="arg5" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg6" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg7" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg8" type="{http://www.w3.org/2001/XMLSchema}HashMap<String, String>"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "createCryptoToken", propOrder = {
   "arg0",
   "arg1",
   "arg2",
   "arg3",
   "arg4",
   "arg5",
   "arg6",
   "arg7",
   "arg8",
})

public class CreateCryptoToken {

   protected String arg0;
   protected String arg1;
   protected String arg2;
   protected boolean arg3;
   protected boolean arg4;
   protected String arg5;
   protected String arg6;
   protected String arg7;
   protected HashMap<String, String> arg8;
   
   /**
    * Gets the value of the arg0 property.
    * 
    */
   public String getArg0() {
       return arg0;
   }
 
   /**
    * Sets the value of the arg0 property.
    * 
    */
   public void setArg0(String value) {
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
   
   /**
    * Gets the value of the arg2 property.
    * 
    */
   public String getArg2() {
       return arg2;
   }

   /**
    * Sets the value of the arg2 property.
    * 
    */
   public void setArg2(String value) {
       this.arg2 = value;
   }

   /**
    * Gets the value of the arg3 property.
    * 
    */
   public boolean getArg3() {
       return arg3;
   }

   /**
    * Sets the value of the arg3 property.
    * 
    */
   public void setArg3(boolean value) {
       this.arg3 = value;
   }

   /**
    * Gets the value of the arg4 property.
    * 
    */
   public boolean getArg4() {
       return arg4;
   }

   /**
    * Sets the value of the arg4 property.
    * 
    */
   public void setArg4(boolean value) {
       this.arg4 = value;
   }

   /**
    * Gets the value of the arg5 property.
    * 
    */
   public String getArg5() {
       return arg5;
   }

   /**
    * Sets the value of the arg5 property.
    * 
    */
   public void setArg5(String value) {
       this.arg5 = value;
   }

   /**
    * Gets the value of the arg6 property.
    * 
    */
   public String getArg6() {
       return arg6;
   }

   /**
    * Sets the value of the arg6 property.
    * 
    */
   public void setArg6(String value) {
       this.arg6 = value;
   }

   /**
    * Gets the value of the arg7 property.
    * 
    */
   public String getArg7() {
       return arg7;
   }

   /**
    * Sets the value of the arg7 property.
    * 
    */
   public void setArg7(String value) {
       this.arg7 = value;
   }

   /**
    * Gets the value of the arg8 property.
    * 
    */
   public HashMap<String, String> getArg8() {
       return arg8;
   }

   /**
    * Sets the value of the arg8 property.
    * 
    */
   public void setArg8(HashMap<String, String> value) {
       this.arg8 = value;
   }

}