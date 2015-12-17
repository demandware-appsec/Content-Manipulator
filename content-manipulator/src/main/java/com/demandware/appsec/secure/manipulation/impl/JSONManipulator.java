package com.demandware.appsec.secure.manipulation.impl;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * JavaScriptManipulator handles all content related to JavaScript code
 *
 * @author Chris Smith
 */
public class JSONManipulator
    extends AbstractManipulator
{

    static enum JSONManipulatorOption
        implements IManipulateOption
    {
        //These values should be slash escaped
        JSON_VALUE( '\b', '\t', '\n', '\f', '\r', '"', '\\', '/' ), ;

        private final Character[] escape;

        private JSONManipulatorOption( Character... escape )
        {
            this.escape = escape;
        }

        public Character[] getEscapeCharacters()
        {
            return this.escape;
        }
    }

    JSONManipulator( JSONManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        JSONManipulatorOption opt = (JSONManipulatorOption) this.manipulatorOption;

        //if the character is alphanumeric, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        //if the character should be escaped, do it
        //this disallows users from escaping JSON and writing HTML or JS code
        else if ( ManipulationUtils.isInList( c, opt.getEscapeCharacters() ) )
        {
            correctedCharacter = ManipulationUtils.slashEscapeChar( c );
        }
        //otherwise hex-encode and pad with \u0000
        else
        {
            String hex = ManipulationUtils.getHexForCharacter( c );
            String pad = "0000".substring( hex.length() );
            correctedCharacter = "\\u" + pad + hex;
        }

        return correctedCharacter;
    }
}
