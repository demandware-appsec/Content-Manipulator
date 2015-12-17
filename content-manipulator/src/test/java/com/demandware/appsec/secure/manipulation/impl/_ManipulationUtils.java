package com.demandware.appsec.secure.manipulation.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.impl.ManipulationUtils;

public class _ManipulationUtils {

	@Test
	public void testCombineArrays() {
		Character[] test1 = new Character[]{'a','b','c'};
		Character[] test2 = new Character[]{'d','e','f'};
		Character[] testarr = ManipulationUtils.combineArrays(test1, test2);
		Character[] correct = new Character[]{'a','b','c','d','e','f'};
		assertArrayEquals(correct,testarr);
		
		test1 = new Character[]{'a','b','c'};
		test2 = null;
		testarr = ManipulationUtils.combineArrays(test1, test2);
		correct = new Character[]{'a','b','c'};
		assertArrayEquals(correct,testarr);
		
		test1 = null;
		test2 = new Character[]{'d','e','f'};
		testarr = ManipulationUtils.combineArrays(test1, test2);
		correct = new Character[]{'d','e','f'};
		assertArrayEquals(correct,testarr);
		
		test1 = null;
		test2 = null;
		testarr = ManipulationUtils.combineArrays(test1, test2);
		correct = null;
		assertArrayEquals(correct,testarr);
	}

	@Test
	public void testIsSame() {
		Character c = 'c';
		String s = "c";
		assertTrue(ManipulationUtils.isSame(c, s));
		
		c = 'c';
		s = "charlie";
		assertFalse(ManipulationUtils.isSame(c, s));
		
		c = 'c';
		s = "d";
		assertFalse(ManipulationUtils.isSame(c, s));
		
		c = 'c';
		s = "d";
		assertFalse(ManipulationUtils.isSame(c, s));
	}

	@Test
	public void testIsInList() {
		Character c = 'c';
		Character[] list = new Character[]{'a','c'};
		assertTrue(ManipulationUtils.isInList(c, list));

		c = 'c';
		list = null;
		assertFalse(ManipulationUtils.isInList(c, list));

		c = null;
		list = new Character[]{'a','c'};
		assertFalse(ManipulationUtils.isInList(c, list));

		c = null;
		list = null;
		assertTrue(ManipulationUtils.isInList(c, list));
	}

}
