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

    public static AbstractManipulator getManipulator( IManipulationType type )
    {
        return instance.manipulatorMap.get( type );
    }
}
