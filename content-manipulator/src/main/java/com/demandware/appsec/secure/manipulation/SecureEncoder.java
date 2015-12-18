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
package com.demandware.appsec.secure.manipulation;

import java.io.IOException;
import java.io.Writer;

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;

/**
 * SecureEncode contains many methods for manipulating untrusted data Strings
 * into RFC-Compliant Strings for a given context by encoding "bad" data into
 * the proper format.
 *
 * @author Chris Smith
 */
public class SecureEncoder
{

    /**
     * Shared method to handle encoder lookup and dispatch string
     */
    protected static String encode( DefaultManipulationType type, String input )
    {
        AbstractManipulator enc = ManipulatorFactory.getManipulator( type );
        return enc.encode( input );
    }

    /**
     * Shared method to handle encoder lookup and dispatch string to be written
     * with the given writer
     */
    protected static void encode( DefaultManipulationType type, String input, Writer writer)
    {
        AbstractManipulator enc = ManipulatorFactory.getManipulator( type );
        try
        {
            enc.encode( input, writer );
        }
        catch ( IOException e )
        {
            throw new IllegalArgumentException( "An error occurred while encoding", e );
        }
    }

    /**
     * <p>
     * Encodes a given input for use in a general HTML context. E.g.
     * text content and text attributes. This method takes the UNION of allowed
     * characters between the two context, so may be more imprecise that the
     * more specific contexts. Generally, this method is preferred unless you
     * specifically understand the context in which untrusted data will be
     * output.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;div&gt;${SecureEncode.encodeHtmlContent(unsafeData)}&lt;/div&gt;
     *
     * &lt;input value="${SecureEncode.encodeHtmlContent(unsafeData)}" /&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F)
     * with &#xfffd;, the Unicode Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeHtmlContent( String input )
    {
        return encode( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeHtmlContent(String)}
     *
     * @param input untrusted input to be encoded, if necessary
     * @param out where to write the encoded output
     */
    public static void encodeHtmlContent( String input, Writer out )
    {
        encode( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input, out);
    }


    /**
     * <p>
     * Encodes a given input for use in an HTML Attribute guarded by a single
     * quote. This method is preferred if you understand exactly how the output
     * of this will be used in the HTML document.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;div id='${SecureEncode.encodeHtmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/div&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F)
     * with &#xfffd;, the Unicode Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeHtmlInSingleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeHtmlInSingleQuoteAttribute(String)}
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
     * Encodes a given input for use in an HTML Attribute guarded by a double
     * quote. This method is preferred if you understand exactly how the output
     * of this will be used in the HTML document.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;div id="${SecureEncode.encodeHtmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/div&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F)
     * with &#xfffd;, the Unicode Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeHtmlInDoubleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeHtmlInDoubleQuoteAttribute(String)}
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
     * Encodes a given input for use in an HTML Attribute left unguarded.
     * This method is preferred if you understand exactly how the output
     * of this will be used in the HTML document.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;div id=${SecureEncode.encodeHtmlUnquotedAttribute(unsafeData)}&gt;&lt;/div&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between 0x7F and 0x9F)
     * with &#xfffd;, the Unicode Replacement Character</li>
     * <li>Replace special HTML characters with their HTML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeHtmlUnquotedAttribute( String input )
    {
        return encode( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeHtmlUnquotedAttribute(String)}
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
     * Encodes a given input for use in JavaScript inside an HTML context.
     * This method takes the UNION of allowed characters among the other
     * contexts, so may be more imprecise that the more specific contexts.
     * Generally, this method is preferred unless you specifically understand
     * the context in which untrusted data will be output.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureEncode.encodeJavaScriptInHTML(unsafeData)}";
     * &lt;/script&gt;
     *
     * &lt;button onclick="alert('${SecureEncode.encodeJavaScriptInHTML(unsafeData)}');"&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded
     * equivalents prepended with \\x for character codes under 128 and
     * \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeJavaScriptInHTML( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeJavaScriptInHTML(String)}
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
     * Encodes a given input for use in JavaScript inside an HTML attribute.
     * This method is preferred if you understand exactly how the output
     * of the will be used in the page
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;button onclick="alert('${SecureEncode.encodeJavaScriptInAttribute(unsafeData)}');"&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded
     * equivalents prepended with \\x for character codes under 128 and
     * \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeJavaScriptInAttribute( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeJavaScriptInAttribute(String)}
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
     * Encodes a given input for use in JavaScript inside an HTML block.
     * This method is preferred if you understand exactly how the output
     * of the will be used in the page
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureEncode.encodeJavaScriptInBlock(unsafeData)}";
     * &lt;/script&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded
     * equivalents prepended with \\x for character codes under 128 and
     * \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeJavaScriptInBlock( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeJavaScriptInBlock(String)}
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
     * Encodes a given input for use in JavaScript inside a JavaScript source
     * file. This method is preferred if you understand exactly how the output
     * of the will be used in the page
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;...inside foobar.js...&gt;
     * var data = "${SecureEncode.encodeJavaScriptInSource(unsafeData)}";
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace special JavaScript characters with their Hex Encoded
     * equivalents prepended with \\x for character codes under 128 and
     * \\u for character codes over 128</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeJavaScriptInSource( String input )
    {
        return encode( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeJavaScriptInSource(String)}
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
     * Encodes a given input for use in a JSON Object Value to prevent
     * escaping into a trusted context.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * var json = {"trusted_data" : SecureEncoder.encodeJSONValue(unsafeData)};
     * return JSON.stringify(json);
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics</li>
     * <li>Slash escape certain illegal characters</li>
     * <li>Replace all other characters with their Hex Encoded
     * equivalents prepended with \\u</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeJSONValue( String input )
    {
        return encode( DefaultManipulationType.JSON_VALUE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeJSONValue(String)}
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
     * Encodes a given input for use as a component of a URI. This is
     * equivalent to javascript's encodeURIComponent and does a realistic
     * job of encoding.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;a href="http://host.com?value=${SecureEncoder.encodeUriComponent(unsafeData)}"/&gt;
     * </pre>
     *
     * <h5>Allows:</h5>
     * <pre>A-Z, a-z, 0-9, -, _, ., ~, !, *, ', (, )</pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Percent encode all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeUriComponent( String input )
    {
        return encode( DefaultManipulationType.URI_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeUriComponent(String)}
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
     * Encodes a given input for use as a component of a URI. This is a strict
     * encoder and fully complies with RFC3986.
     * </p>
     *
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;a href="http://host.com?value=${SecureEncoder.encodeUriComponentStrict(unsafeData)}"/&gt;
     * </pre>
     *
     * <h5>Allows:</h5>
     * <pre>A-Z, a-z, 0-9, -, _, ., ~</pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Percent encode all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeUriComponentStrict( String input )
    {
        return encode( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeUriComponentStrict(String)}
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
     * Encodes a given input for use in a general XML context. E.g.
     * text content and text attributes. This method takes the UNION of allowed
     * characters between the other contexts, so may be more imprecise that the
     * more specific contexts. Generally, this method is preferred unless you
     * specifically understand the context in which untrusted data will be
     * output.
     * </p>
     *
     * <h5>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</h5>
     * <br/>
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;foo&gt;${SecureEncode.encodeXmlContent(unsafeData)}&lt;/foo&gt;
     *
     * &lt;bar attr="${SecureEncode.encodeXmlContent(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between
     * 0x7F and 0x84 or between 0x86 and 0x9F or between 0xFDD0 and 0xFDDF)
     * with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeXmlContent( String input )
    {
        return encode( DefaultManipulationType.XML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeXmlContent(String)}
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
     * Encodes a given input for use in an XML attribute guarded by a single
     * quote. This method is preferred if you understand the context in which
     * untrusted data will be output.
     * </p>
     *
     * <h5>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</h5>
     * <br/>
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;bar attr='${SecureEncode.encodeXmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/bar&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between
     * 0x7F and 0x84 or between 0x86 and 0x9F or between 0xFDD0 and 0xFDDF)
     * with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeXmlInSingleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeXmlInSingleQuoteAttribute(String)}
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
     * Encodes a given input for use in an XML attribute guarded by a double
     * quote. This method is preferred if you understand the context in which
     * untrusted data will be output.
     * </p>
     *
     * <h5>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</h5>
     * <br/>
     * <h5>Example Usage:</h5>
     * <pre>
     * &lt;bar attr="${SecureEncode.encodeXmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between
     * 0x7F and 0x84 or between 0x86 and 0x9F or between 0xFDD0 and 0xFDDF)
     * with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeXmlInDoubleQuoteAttribute( String input )
    {
        return encode( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeXmlInDoubleQuoteAttribute(String)}
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
     * Encodes a given input for use in an XML comments.
     * This method is preferred if you understand the context in which
     * untrusted data will be output.
     * </p>
     *
     * <h5>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</h5>
     * <br/>
     * <h5>Example Usage:</h5>
     * <pre>
     * <!-- ${SecureEncoder.encodeXmlCommentContent(unsafeData)} -->
     * </pre>
     *
     * <h5>Flow:</h5>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Replace Illegal Control Characters (Below 0x1F or between
     * 0x7F and 0x84 or between 0x86 and 0x9F or between 0xFDD0 and 0xFDDF)
     * with an empty string</li>
     * <li>Replace special XML characters with their default XML Entity equivalents</li>
     * </ul>
     *
     * @param input untrusted input to be encoded, if necessary
     * @return a properly encoded string for the given input
     */
    public static String encodeXmlCommentContent( String input )
    {
        return encode( DefaultManipulationType.XML_COMMENT_MANIPULATOR, input );
    }
    /**
     * Writes encoded content directly to given java.io.Writer
     * See {@link #encodeXmlCommentContent(String)}
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
