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
    
    public static void registerManipulationTypes( IManipulationType... types ){
    	for( int i = 0; i < types.length; i++ )
    	{
    		IManipulationType type = types[i];
    		instance.manipulatorMap.put( type, type.getManipulator() );
    	}
    }

    public static AbstractManipulator getManipulator( IManipulationType type )
    {
        return instance.manipulatorMap.get( type );
    }
}
