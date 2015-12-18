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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * XMLManipulator handles all content related to XML
 *
 * @author Chris Smith
 */
public class XMLManipulator
    extends AbstractManipulator
{

    static enum XMLManipulatorOption
        implements IManipulateOption
    {
        //These characters are immune to modification
        CONTENT                 ( '-' ),
        SINGLE_QUOTE_ATTRIBUTE  ( '-', '"' ),
        DOUBLE_QUOTE_ATTRIBUTE  ( '-',      '\'' ),
        COMMENT_CONTENT         (      '"', '\'', '<', '!', '>', '#', '$',
                                  '%', '^', '*',  '+', '/', '=', '?', '@',
                                  '[', '\\',']',  '{', '|', '}', '~' ),
        ;

        //These characters are immune in all contexts
        private final Character[] baseImmune =
                                {
                                    ',', ';', ':', '.', '_', ' ', '(', ')',
                                    '\t', '\n', '\r'
                                };

        private final Character[] immune;

        private XMLManipulatorOption( Character... immune )
        {
        	this.immune = ManipulationUtils.combineArrays( immune, this.baseImmune );
        }

        public Character[] getImmuneCharacters()
        {
            return this.immune;
        }
    }

    private static final Map<Character, String> characterToEntityMap = createEntityMap();

    private static final String REPLACE_HEX = ""; // for control characters, use blank, from RFC

    //only used in JUnit
    static String getReplacementHex()
    {
        return REPLACE_HEX;
    }

    XMLManipulator( XMLManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        XMLManipulatorOption opt = (XMLManipulatorOption) this.manipulatorOption;

        //If the character is alphanumeric or is immune, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) || ManipulationUtils.isInList( c, opt.getImmuneCharacters() ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        else
        {
            //Check if the character can be written as an entity to block attacks
            String entity = characterToEntityMap.get( c );

            if ( entity != null )
            {
                correctedCharacter = entity;
            }
            //Otherwise, replace illegal control characters with a safe replacement
            //these characters can have special meaning and are recommended to be removed by the RFC
            else if ( ( c <= 0x1f ) ||              // lower bounds of control characters except tab and newlines
                ( c >= 0x7f && c <= 0x84 ) ||       // DEL through APC control characters,
                ( c >= 0x86 && c <= 0x9f ) ||       // (still allows NEL character)
                ( c >= 0xfdd0 && c <= 0xfddf ) )    // more control chars
            {
                correctedCharacter = REPLACE_HEX;
            }
            //Otherwise encode the character in hex
            else
            {
                correctedCharacter = "&#x" + ManipulationUtils.getHexForCharacter( c ) + ";";
            }
        }
        return correctedCharacter;
    }

    /**
     * Small unmodifiable map of entity mappings
     * @return
     */
    private static Map<Character, String> createEntityMap()
    {
        Map<Character, String> map = new HashMap<Character, String>( 4 );
        map.put( (char) 34, "&quot;" );       /* quotation mark */
        map.put( (char) 38, "&amp;" );        /* ampersand */
        map.put( (char) 39, "&apos;" );       /* single quote*/
        map.put( (char) 60, "&lt;" );         /* less-than sign */
        map.put( (char) 62, "&gt;" );         /* greater-than sign */
        return Collections.unmodifiableMap( map );
    }

}
