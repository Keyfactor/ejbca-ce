package com.example.entity;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "MyCounterData")
public class MyCounterData implements Serializable {

    private static final long serialVersionUID = -8493105317760641442L;

    private int pk;
    private int counter;
    
    public void setPk (int pk) { this.pk = pk; }
	public int getPk () { return pk; }
	
    public void setCounter (int counter) { this.counter = counter; }
	public int getCounter () { return counter; }

}
