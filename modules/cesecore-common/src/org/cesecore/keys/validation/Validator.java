/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.Profile;

/**
 * Base interface for key validators. All key validators must implement this interface.
 * 
 * @version $Id$
 */

public interface Validator extends Profile, Cloneable {

    static final String TYPE_NAME = "VALIDATOR";
    
    /**
     * Initializes the key validator.
     */
    void init();

    /**
     * Populates the sub class specific key validator values with template values based on {@link KeyValidatorBase#getSettingsTemplate()}. 
     * Sub classes only need to implement this method if they support configuration templates.
     */
    void setKeyValidatorSettingsTemplate();
    
    /**
     * Gets the failed action index {@link KeyValidationFailedActions}
     * @return the index.
     */
    int getFailedAction();
    
    void setFailedAction(int index);

    /**
     * Method that validates the public key.
     * 
     * @param publicKey the public key to validate.
     * @param certificateProfile the Certificate Profile as input for validation
     * @return the error messages or an empty list if the public key was validated successfully.
     * @throws KeyValidationException if the certificate issuance MUST be aborted.
     */
    List<String> validate(PublicKey publicKey, CertificateProfile certificateProfiles) throws KeyValidationException;

    /**
     * @return the settings template index.
     */
    Integer getSettingsTemplate();
    
    /**
     * Sets the settings template index.
     * @param type the type {@link KeyValidatorSettingsTemplate}.
     */
    void setSettingsTemplate(Integer option);
    
    /**
     * Gets the XHTML template file in /WEB-INF/ca/editkeyvalidators.
     * @return the file path.
     */
    String getTemplateFile();
    
     /**
      * 
      * @return a display friendly string of this validator
      */
     String toDisplayString();

     /** 
      * If the validator should apply to All certificate profiles. 
      * 
      * @return true or false.
      */
     boolean isAllCertificateProfileIds();
     
     /** 
      * Sets if validation should be performed for all certificate profile ids.
      * 
      * @param isAll, true if validation should be done for all certificate profiles.
      */
     void setAllCertificateProfileIds(boolean isAll);

     /** 
      * Gets a list of selected certificate profile ids. 
      * 
      * @return the list.
      */
     List<Integer> getCertificateProfileIds();
     
     /** 
      * Sets the selected certificate profile ids.
      * 
      * @param ids the collection of ids.
      */
     void setCertificateProfileIds(Collection<Integer> ids);
     
     void setNotBefore(Date date);
     
     Date getNotBefore();
     
     void setNotBeforeCondition(int index);
     
     int getNotBeforeCondition();
     
     void setNotAfter(Date date);
     
     Date getNotAfter();
     
     int getNotAfterCondition();
     
     void setNotAfterCondition(int index);
     
     /**
      * Clone has to be implemented instead of a copy constructor due to the fact that we'll be referring to implementations by this interface only. 
      * 
      * @return a deep copied clone of this validator
      */
      Validator clone();
      
      /**
       * @return the description.
       */
      public String getDescription();

      /**
       * @param description the description. 
       */
      void setDescription(String description);
      
      /** Implementation of UpgradableDataHashMap function getLatestVersion */    
      float getLatestVersion();
      
      UpgradeableDataHashMap getUpgradableHashmap();
      
      /**
       * Returns an identifier for the type of the approval profile.
       * @return type of approval, e.g. "RSA_KEY_VALIDATOR"
       */
      String getValidatorTypeIdentifier();
      
      /**
       * @return the type as a human readable name.
       */
      String getLabel();
}
