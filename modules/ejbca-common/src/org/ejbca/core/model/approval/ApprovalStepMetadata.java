package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.List;

/**
 * Holds data of metadata of an approval step
 * 
 *  @version $Id$
 */
public class ApprovalStepMetadata implements Serializable {
    private static final long serialVersionUID = -8320579875930271365L;
    
    public static final int METADATATYPE_CHECKBOX = 1;
    public static final int METADATATYPE_RADIOBUTTON = 2;
    public static final int METADATATYPE_TEXTBOX = 3;
    
    private int metadataId;
    private String instruction;
    private List<String> options;
    private int optionsType;
    private String optionValue;
    private String optionNote;
    
    public ApprovalStepMetadata(final int id, final String instruction, final List<String> options, final int type) {
        this.metadataId = id;
        this.instruction = instruction;
        this.options = options;
        this.optionsType = type;
        this.optionValue = "";
        this.optionNote = "";
    }
    
    public int getMetadataId() { return metadataId; }
    public String getInstruction() { return instruction; }
    public void setDescription(final String instruction) { this.instruction = instruction; }
    public List<String> getOptions() {return options; }
    public void setOptions(final List<String> options) { this.options = options; }
    public int getOptionsType() { return optionsType; }
    public void setOptionsType(final int type) { optionsType = type; }
    public String getOptionValue() { return optionValue; }
    public void setOptionValue(final String value) { optionValue = value; }
    public String getOptionNote() { return optionNote; }
    public void setOptionNote(final String note) { optionNote = note; }
}