package com.demandware.appsec.secure.manipulation;

import java.io.IOException;

import com.demandware.appsec.secure.manipulation.impl.ManipulationUtils;

/**
 * An abstract base for manipulators who only require single characters to manipulate. E.g. an encoder that doesn't need
 * to know the previous/next character to decide what to do with the current character.
 * 
 * @author Chris Smith
 */
public abstract class AbstractCharacterManipulator
    extends AbstractManipulator
{

    protected AbstractCharacterManipulator( IManipulateOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected void encodeInternal( String input, Appendable output )
        throws IOException
    {
        for ( int i = 0; i < input.length(); i++ )
        {
            char c = input.charAt( i );
            output.append( getCorrectCharacter( c ) );
        }
    }

    @Override
    protected void filterInternal( String input, Appendable output )
        throws IOException
    {
        for ( int i = 0; i < input.length(); i++ )
        {
            Character c = input.charAt( i );
            String corr = getCorrectCharacter( c );
            if ( ManipulationUtils.isSame( c, corr ) )
            {
                output.append( c );
            }
        }
    }

    /**
     * Given a character, do any defined, necessary modifications to the input string and return it
     * 
     * @param input a character to possibly modify
     * @return a result of a modification of the input character, or the input character as a string
     */
    protected abstract String getCorrectCharacter( Character input );

}
