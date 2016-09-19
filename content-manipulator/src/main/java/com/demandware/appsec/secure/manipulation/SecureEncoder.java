/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation;

import java.io.IOException;
import java.io.Writer;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.IManipulationType;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;

/**
 * SecureEncode contains many methods for manipulating untrusted data Strings into RFC-Compliant Strings for a given
 * context by encoding "bad" data into the proper format.
 *
 * @author Chris Smith
 */
public class SecureEncoder
{

    /**
     * Shared method to handle encoder lookup by type and dispatch string
     * 
     * @param type the manipulation type to use for encoder lookup
     * @param input the string to encode
     * @return a properly encoded string representation of the input string, or null if the input is null
     */
    public static String encode( IManipulationType type, String input )
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );
        return manip.encode( input );
    }

    /**
     * Shared method to handle encoder lookup by type and dispatch string to be written with the given writer
     * 
     * @param type the manipulation type to use for encoder lookup
     * @param input the string to encode.
     * @param writer a Writer to write output to
     */
    public static void encode( IManipulationType type, String input, Writer writer )
    {
        AbstractManipulator manip = ManipulatorFactory.getManipulator( type );
        try
        {
            manip.encode( input, writer );
        }
        catch ( IOException e )
        {
            throw new IllegalArgumentException( "An error occurred while encoding", e );
        }
    }

    /**
     * <p>
     * Encodes content within a CDATA element.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * String cdata = "&lt;![CDATA[" + SecureEncode.encodeCDATAContent( untrustedInput ) + "]]&gt;";
     * </pre>
     * 
     * <b> Flow: </b>
     * <ul>
     * <li>Allow all AlphaNumerics, Special characters and Unicode</li>
     * <li>Disallow Control Characters</li>
     * <li>Replace instances of ]]&gt; with ]]&gt;]]&lt;![CDATA[&gt;</li>
     * </ul>
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeCDATAContent( String input )
    {
        return encode( DefaultManipulationType.CDATA_CONTENT_MANIPULATOR, input );
    }
    
    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeCDATAContent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeCDATAContent( String input, Writer out )
    {
        encode( DefaultManipulationType.CDATA_CONTENT_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in a general HTML context. E.g. text content and text attributes. This method takes
     * the UNION of allowed characters among all contexts, so may be more imprecise than the more specific contexts.
     * Generally, this method is preferred unless you specifically understand the context in which untrusted data will
     * be displayed.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;div&gt;${SecureEncode.encodeHtmlContent(unsafeData)}&lt;/div&gt;
     *
     * &lt;input value="${SecureEncode.encodeHtmlContent(unsafeData)}" /&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F) with &amp;#xfffd;, the Unicode
     * Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeHtmlContent( String input )
    {
        return encode( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeHtmlContent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeHtmlContent( String input, Writer out )
    {
        encode( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an HTML Attribute guarded by a single quote. This method is preferred if you
     * understand exactly how the output of this will be used in the HTML document.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;div id='${SecureEncode.encodeHtmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F) with &amp;#xfffd;, the Unicode
     * Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeHtmlInSingleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeHtmlInSingleQuoteAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeHtmlInSingleQuoteAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an HTML Attribute guarded by a double quote. This method is preferred if you
     * understand exactly how the output of this will be used in the HTML document.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;div id="${SecureEncode.encodeHtmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F) with &amp;#xfffd;, the Unicode
     * Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeHtmlInDoubleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeHtmlInDoubleQuoteAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeHtmlInDoubleQuoteAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an HTML Attribute left unguarded. This method is preferred if you understand
     * exactly how the output of this will be used in the HTML document.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;div id=${SecureEncode.encodeHtmlUnquotedAttribute(unsafeData)}&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F) with &amp;#xfffd;, the Unicode
     * Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeHtmlUnquotedAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeHtmlUnquotedAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeHtmlUnquotedAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in JavaScript inside an HTML context. This method takes the UNION of allowed
     * characters among the other contexts, so may be more imprecise than the more specific contexts. Generally, this
     * method is preferred unless you specifically understand the context in which untrusted data will be displayed.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureEncode.encodeJavaScriptInHTML(unsafeData)}";
     * &lt;/script&gt;
     *
     * &lt;button onclick="alert('${SecureEncode.encodeJavaScriptInHTML(unsafeData)}');"&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded equivalents prepended with \\x for character
     * codes under 128 and \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeJavaScriptInHTML( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeJavaScriptInHTML(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeJavaScriptInHTML( String input, Writer out )
    {
        encode( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in JavaScript inside an HTML attribute. This method is preferred if you understand
     * exactly how the output of this will be used in the page
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;button onclick="alert('${SecureEncode.encodeJavaScriptInAttribute(unsafeData)}');"&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded equivalents prepended with \\x for character
     * codes under 128 and \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeJavaScriptInAttribute( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeJavaScriptInAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeJavaScriptInAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in JavaScript inside an HTML block. This method is preferred if you understand
     * exactly how the output of this will be used in the page
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureEncode.encodeJavaScriptInBlock(unsafeData)}";
     * &lt;/script&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded equivalents prepended with \\x for character
     * codes under 128 and \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeJavaScriptInBlock( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeJavaScriptInBlock(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeJavaScriptInBlock( String input, Writer out )
    {
        encode( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in JavaScript inside a JavaScript source file. This method is preferred if you
     * understand exactly how the output of this will be used in the page
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;...inside foobar.js...&gt;
     * var data = "${SecureEncode.encodeJavaScriptInSource(unsafeData)}";
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded equivalents prepended with \\x for character
     * codes under 128 and \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeJavaScriptInSource( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeJavaScriptInSource(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeJavaScriptInSource( String input, Writer out )
    {
        encode( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in a JSON Object Value to prevent escaping into a trusted context.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * var json = {"trusted_data" : SecureEncoder.encodeJSONValue(unsafeData)};
     * return JSON.stringify(json);
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace all other characters with their Hex Encoded equivalents prepended with \\u</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeJSONValue( String input )
    {
        return encode( DefaultManipulationType.JSON_VALUE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeJSONValue(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeJSONValue( String input, Writer out )
    {
        encode( DefaultManipulationType.JSON_VALUE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use as a component of a URI. This is equivalent to javascript's encodeURIComponent and
     * does a realistic job of encoding.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;a href="http://host.com?value=${SecureEncoder.encodeUriComponent(unsafeData)}"/&gt;
     * </pre>
     *
     * <b>Allows:</b>
     * 
     * <pre>
     * A-Z, a-z, 0-9, -, _, ., ~, !, *, ', (, )
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Percent encode all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeUriComponent( String input )
    {
        return encode( DefaultManipulationType.URI_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeUriComponent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeUriComponent( String input, Writer out )
    {
        encode( DefaultManipulationType.URI_COMPONENT_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use as a component of a URI. This is a strict encoder and fully complies with RFC3986.
     * </p>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;a href="http://host.com?value=${SecureEncoder.encodeUriComponentStrict(unsafeData)}"/&gt;
     * </pre>
     *
     * <b>Allows:</b>
     * 
     * <pre>
     * A-Z, a-z, 0-9, -, _, ., ~
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Percent encode all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeUriComponentStrict( String input )
    {
        return encode( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeUriComponentStrict(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeUriComponentStrict( String input, Writer out )
    {
        encode( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in a general XML context. E.g. text content and text attributes. This method takes
     * the UNION of allowed characters between the other contexts, so may be more imprecise than the more specific
     * contexts. Generally, this method is preferred unless you specifically understand the context in which untrusted
     * data will be displayed.
     * </p>
     * <b>Note: It is recommended that you use a real parser, as this method can be misused, but is left here if a
     * parser is unavailable to you</b> <br>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;foo&gt;${SecureEncode.encodeXmlContent(unsafeData)}&lt;/foo&gt;
     *
     * &lt;bar attr="${SecureEncode.encodeXmlContent(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x84 or between 0x86 and 0x9F or between
     * 0xFDD0 and 0xFDDF) with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeXmlContent( String input )
    {
        return encode( DefaultManipulationType.XML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeXmlContent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeXmlContent( String input, Writer out )
    {
        encode( DefaultManipulationType.XML_CONTENT_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an XML attribute guarded by a single quote. This method is preferred if you
     * understand the context in which untrusted data will be displayed.
     * </p>
     * <b>Note: It is recommended that you use a real parser, as this method can be misused, but is left here if a
     * parser is unavailable to you</b> <br>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;bar attr='${SecureEncode.encodeXmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x84 or between 0x86 and 0x9F or between
     * 0xFDD0 and 0xFDDF) with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeXmlInSingleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeXmlInSingleQuoteAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeXmlInSingleQuoteAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an XML attribute guarded by a double quote. This method is preferred if you
     * understand the context in which untrusted data will be displayed.
     * </p>
     * <b>Note: It is recommended that you use a real parser, as this method can be misused, but is left here if a
     * parser is unavailable to you</b> <br>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;bar attr="${SecureEncode.encodeXmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x84 or between 0x86 and 0x9F or between
     * 0xFDD0 and 0xFDDF) with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeXmlInDoubleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeXmlInDoubleQuoteAttribute(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeXmlInDoubleQuoteAttribute( String input, Writer out )
    {
        encode( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Encodes a given input for use in an XML comments. This method is preferred if you understand the context in which
     * untrusted data will be displayed.
     * </p>
     * <b>Note: It is recommended that you use a real parser, as this method can be misused, but is left here if a
     * parser is unavailable to you</b> <br>
     * <b>Example Usage:</b>
     * 
     * <pre>
     * &lt;!-- ${SecureEncoder.encodeXmlCommentContent(unsafeData)} --&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x84 or between 0x86 and 0x9F or between
     * 0xFDD0 and 0xFDDF) with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input, or null if the input is null
     */
    public static String encodeXmlCommentContent( String input )
    {
        return encode( DefaultManipulationType.XML_COMMENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer See {@link #encodeXmlCommentContent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeXmlCommentContent( String input, Writer out )
    {
        encode( DefaultManipulationType.XML_COMMENT_MANIPULATOR, input, out );
    }

    protected SecureEncoder()
    {/*Cannot instantiate*/
    }
}
