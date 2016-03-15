/*
 * Copyright 2015 Demandware Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.demandware.appsec.secure.manipulation.impl;

import java.util.HashMap;
import java.util.Map;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;


/**
 * The ManipulatorFactory holds all Manipulators and manages their lifecycle.
 * The Factory can also be considered a Registrar as it maintains singular 
 * references to each Manipulator. 
 * <br>
 * Note: This class's 
 * {@linkplain #registerManipulationTypes(IManipulationType...)} is the only 
 * way to add new Manipulators to the library and so must be called 
 * when adding custom Manipulators. Additionally, you will need to subclass
 * {@linkplain IManipulationType}
 * 
 * @author Chris Smith
 *
 */
public class ManipulatorFactory
{
    private static final ManipulatorFactory instance = new ManipulatorFactory();

    private final Map<IManipulationType, AbstractManipulator> manipulatorMap = new HashMap<IManipulationType, AbstractManipulator>();

    private ManipulatorFactory()
    {
        for ( IManipulationType t : DefaultManipulationType.values() )
        {
            this.manipulatorMap.put( t, t.getManipulator() );
        }
    }
    
    /**
     * Given a new IManipulationType, add it to the Factory for later use
     * 
     * @param types one or more {@linkplain IManipulationType} objects to 
     * add to this Factory
     */
    public static void registerManipulationTypes( IManipulationType... types ){
    	if(types == null)
    	{
    		return;
    	}
    	
    	for( int i = 0; i < types.length; i++ )
    	{
    		IManipulationType type = types[i];
    		instance.manipulatorMap.put( type, type.getManipulator() );
    	}
    }

    /**
     * Given an IManipulationType, return the Factory's implemented Manipulator
     * 
     * @param type an {@linkplain IManipulationType} describing a desired 
     * Manipulator
     * @return the Manipulator described by the given type, or null, if none
     * was found
     */
    public static AbstractManipulator getManipulator( IManipulationType type )
    {
        return instance.manipulatorMap.get( type );
    }
}
