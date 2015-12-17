package com.demandware.appsec.secure.manipulation.impl;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * JavaScriptManipulator handles all content related to JavaScript code
 *
 * @author Chris Smith
 */
public class JavaScriptManipulator
    extends AbstractManipulator
{

    static enum JavaScriptManipulatorOption
        implements IManipulateOption
    {

        //         List of Characters to be slash escaped   List of characters to be ignored
        HTML     ( new Character[] {            '-', '/' }, null ),
        ATTRIBUTE( new Character[] {                     }, null ),
        BLOCK    ( new Character[] { '"', '\'', '-', '/' }, null ),
        SOURCE   ( new Character[] { '"', '\''           }, new Character[] { '&' } ),
        ;

        //These characters must always be slash escaped
        private final Character[] baseEscapeList =
                    {
                        '\b', '\t', '\n', '\f', '\r', '\\'
                    };

        //These characters are always allowed
        private final Character[] baseIgnoreList =
                    {
                        '~', '`', '!', '@', '#', '$', '%', '^',
                        '*', '(', ')', '_', '+', '=', '{', '}',
                        '|', '[', ']', ':', ';', '<', '>', '?',
                        ',', '.', '-', '/', ' '
                    };

        private final Character[] escapeList;
        private final Character[] ignoreList;

        private JavaScriptManipulatorOption( Character[] escapes, Character[] ignores )
        {
            this.escapeList = ManipulationUtils.combineArrays( escapes, this.baseEscapeList );
            this.ignoreList = ManipulationUtils.combineArrays( ignores, this.baseIgnoreList );
        }

        public Character[] getIgnoreList()
        {
            return this.ignoreList;
        }

        public Character[] getEscapeCharacters()
        {
            return this.escapeList;
        }
    }

    JavaScriptManipulator( JavaScriptManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        JavaScriptManipulatorOption opt = (JavaScriptManipulatorOption) this.manipulatorOption;

        //if the character is alphanumeric, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        //if the character should be escaped, escape it
        else if ( ManipulationUtils.isInList( c, opt.getEscapeCharacters() ) )
        {
            correctedCharacter = ManipulationUtils.slashEscapeChar( c );
        }
        //if the character should be ignored, do
        //this happens after escaping, as a character must be escaped instead of ignored
        //if it is in both lists, see '-'
        else if ( ManipulationUtils.isInList( c, opt.getIgnoreList() ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        else
        {
            //Now get the hex representation of the character and pad it
            String hex = ManipulationUtils.getHexForCharacter( c );

            String pad;
            String lead;

            //js pads ASCII under 128 as \x00 padded
            if ( c < 128 )
            {
                pad = "00".substring( hex.length() );
                lead = "\\x";
            }
            //js pads Unicode 128+ as \u0000 padded
            else
            {
                pad = "0000".substring( hex.length() );
                lead = "\\u";
            }

            correctedCharacter = lead + pad + hex;
        }

        return correctedCharacter;
    }
}
