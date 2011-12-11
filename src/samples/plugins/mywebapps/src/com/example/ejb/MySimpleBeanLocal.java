package com.example.ejb;

import com.example.entity.MyCounterData;

public interface  MySimpleBeanLocal  {

	public int updateCounter ();
	
	public MyCounterData getCurrent ();

	public void clearCounter();
	
}
