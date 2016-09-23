package com.demandware.appsec.secure.manipulation;

/**
 * An abstract base for manipulators who require the full string to manipulate. E.g. an encoder that needs to know the
 * previous/next character to decide what to do with the current character.
 * 
 * @author Chris Smith
 */
public abstract class AbstractStringManipulator
    extends AbstractManipulator
{

    protected AbstractStringManipulator( IManipulateOption manipulatorOption )
    {
        super( manipulatorOption );
    }

}
