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

import java.util.Collection;
import java.util.List;

import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.profiles.Profile;

/**
 * Base interface for validators. All validators must implement this interface.
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
     * Populates the sub class specific key validator values with template values based on {@link ValidatorBase#getSettingsTemplate()}. 
     * Sub classes only need to implement this method if they support configuration templates.
     */
    void setKeyValidatorSettingsTemplate();
    
    /**
     * Gets the failed action index {@link KeyValidationFailedActions}, defining what action should
     * be taken when validation fails, i.e. #validate returns errors
     * @return the index.
     */
    int getFailedAction();
    
    void setFailedAction(int index);

    /**
     * Gets the not_applicable action index {@link KeyValidationFailedActions}, defining what action should
     * be taken when a Validator is not applicable for the input (for example ECC keys to an RSA key validator),
     * i.e. #validate throws ValidatorNotApplicableException
     * @return the index.
     */
    void setNotApplicableAction(int index);

    int getNotApplicableAction();

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
      
      /**
       * @return the subtype of this validator
       */
      Class<? extends Validator> getValidatorSubType();
}
