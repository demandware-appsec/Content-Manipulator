package com.demandware.appsec.secure.manipulation;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.demandware.appsec.secure.manipulation.impl._HTMLManipulator;
import com.demandware.appsec.secure.manipulation.impl._JSONManipulator;
import com.demandware.appsec.secure.manipulation.impl._JavaScriptManipulator;
import com.demandware.appsec.secure.manipulation.impl._ManipulationUtils;
import com.demandware.appsec.secure.manipulation.impl._URIManipulator;
import com.demandware.appsec.secure.manipulation.impl._XMLManipulator;

@RunWith( Suite.class )
@SuiteClasses(	{
					_SecureEncoder.class,
					_SecureFilter.class,
					_ManipulationUtils.class,
					_HTMLManipulator.class,
					_JavaScriptManipulator.class,
					_JSONManipulator.class,
					_URIManipulator.class,
					_XMLManipulator.class,
					
				} )

public class _ManipulatorTestSuite
{

}
