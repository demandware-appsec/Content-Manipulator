/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation;

import static org.junit.Assert.assertEquals;

import java.io.StringWriter;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.SecureFilter;

public class SecureFilterTest
{

    @Test
    public void CDATATest()
    {
        String CDATA1 =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( CDATA1.length() );

        assertEquals( "filterCDATA positive test failed", CDATA1, SecureFilter.filterCDATAContent( CDATA1 ) );

        SecureFilter.filterCDATAContent( CDATA1, sw );
        assertEquals( "filterCDATA positive test failed", CDATA1, sw.toString() );

        String CDATA2 = "foo]]]]>]]";
        sw = new StringWriter( CDATA2.length() );
        String expected = "foo]]]]";
        assertEquals( "filterCDATA negative test failed", expected, SecureFilter.filterCDATAContent( CDATA2 ) );

        SecureFilter.filterCDATAContent( CDATA2, sw );
        assertEquals( "filterCDATA negative test failed", expected, sw.toString() );
    }
    
    @Test
    public void HTMLTest()
    {
        String htmlTest =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( htmlTest.length() * 2 );

        String htmlContent =
            "!--this! is/ a; comment: --foo attribute=valuetext/foobar attribute=doublevaluetext2/barbaz attribute=singlevalue)(*#$!@#?/baz";
        assertEquals( "filterHTMLContent failed", htmlContent, SecureFilter.filterHtmlContent( htmlTest ) );

        SecureFilter.filterHtmlContent( htmlTest, sw );
        assertEquals( "filterHTMLContent failed", htmlContent, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlDouble =
            "!--this! is/ a; comment: --foo attribute=valuetext/foobar attribute=doublevaluetext2/barbaz attribute='singlevalue')(*#$!@#?/baz";
        assertEquals( "filterHtmlInDoubleQuoteAttribute failed", htmlDouble,
            SecureFilter.filterHtmlInDoubleQuoteAttribute( htmlTest ) );

        SecureFilter.filterHtmlInDoubleQuoteAttribute( htmlTest, sw );
        assertEquals( "filterHtmlInDoubleQuoteAttribute failed", htmlDouble, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlSingle =
            "!--this! is/ a; comment: --foo attribute=valuetext/foobar attribute=\"doublevalue\"text2/barbaz attribute=singlevalue)(*#$!@#?/baz";
        assertEquals( "filterHtmlInSingleQuoteAttribute failed", htmlSingle,
            SecureFilter.filterHtmlInSingleQuoteAttribute( htmlTest ) );

        SecureFilter.filterHtmlInSingleQuoteAttribute( htmlTest, sw );
        assertEquals( "filterHtmlInSingleQuoteAttribute failed", htmlSingle, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlUnq =
            "!--this!is/a;comment:--fooattribute=valuetext/foobarattribute=doublevaluetext2/barbazattribute=singlevalue)(*#$!@#?/baz";
        assertEquals( "filterHtmlUnquotedAttribute failed", htmlUnq,
            SecureFilter.filterHtmlUnquotedAttribute( htmlTest ) );

        SecureFilter.filterHtmlUnquotedAttribute( htmlTest, sw );
        assertEquals( "filterHtmlUnquotedAttribute failed", htmlUnq, sw.toString() );

    }

    @Test
    public void XMLTest()
    {
        String xmlTest =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( xmlTest.length() * 2 );

        String xmlContent =
            "--this is a; comment: --foo attributevaluetextfoobar attributedoublevaluetext2barbaz attributesinglevalue)(baz";
        assertEquals( "filterXmlContent failed", xmlContent, SecureFilter.filterXmlContent( xmlTest ) );

        SecureFilter.filterXmlContent( xmlTest, sw );
        assertEquals( "filterXmlContent failed", xmlContent, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlDouble =
            "--this is a; comment: --foo attributevaluetextfoobar attributedoublevaluetext2barbaz attribute'singlevalue')(baz";
        assertEquals( "filterXmlInDoubleQuoteAttribute failed", xmlDouble,
            SecureFilter.filterXmlInDoubleQuoteAttribute( xmlTest ) );

        SecureFilter.filterXmlInDoubleQuoteAttribute( xmlTest, sw );
        assertEquals( "filterXmlInDoubleQuoteAttribute failed", xmlDouble, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlSingle =
            "--this is a; comment: --foo attributevaluetextfoobar attribute\"doublevalue\"text2barbaz attributesinglevalue)(baz";
        assertEquals( "filterXmlInSingleQuoteAttribute failed", xmlSingle,
            SecureFilter.filterXmlInSingleQuoteAttribute( xmlTest ) );

        SecureFilter.filterXmlInSingleQuoteAttribute( xmlTest, sw );
        assertEquals( "filterXmlInSingleQuoteAttribute failed", xmlSingle, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlComment =
            "<!this! is/ a; comment: ><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        assertEquals( "filterXmlComment failed", xmlComment, SecureFilter.filterXmlCommentContent( xmlTest ) );

        SecureFilter.filterXmlCommentContent( xmlTest, sw );
        assertEquals( "filterXmlComment failed", xmlComment, sw.toString() );

    }

    @Test
    public void JavaScriptTest()
    {
        String javascriptTest =
            "console.log(\"Log Message!\");\r\n $(ajax).postMessage('foo.com');\nvar x = 123+14*82/12-6;";
        StringWriter sw = new StringWriter( javascriptTest.length() * 2 );

        String jsHTML = "console.log(Log Message!); $(ajax).postMessage(foo.com);var x = 123+14*82126;";
        assertEquals( "filterJavaScriptInHTML failed", jsHTML, SecureFilter.filterJavaScriptInHTML( javascriptTest ) );

        SecureFilter.filterJavaScriptInHTML( javascriptTest, sw );
        assertEquals( "filterJavaScriptInHTML failed", jsHTML, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsAttr = "console.log(Log Message!); $(ajax).postMessage(foo.com);var x = 123+14*82/12-6;";
        assertEquals( "filterJavaScriptInAttribute failed", jsAttr,
            SecureFilter.filterJavaScriptInAttribute( javascriptTest ) );

        SecureFilter.filterJavaScriptInAttribute( javascriptTest, sw );
        assertEquals( "filterJavaScriptInAttribute failed", jsAttr, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsBlock = "console.log(Log Message!); $(ajax).postMessage(foo.com);var x = 123+14*82126;";
        assertEquals( "filterJavaScriptInBlock failed", jsBlock,
            SecureFilter.filterJavaScriptInBlock( javascriptTest ) );

        SecureFilter.filterJavaScriptInBlock( javascriptTest, sw );
        assertEquals( "filterJavaScriptInBlock failed", jsBlock, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsSource = "console.log(Log Message!); $(ajax).postMessage(foo.com);var x = 123+14*82/12-6;";
        assertEquals( "filterJavaScriptInSource failed", jsSource,
            SecureFilter.filterJavaScriptInSource( javascriptTest ) );

        SecureFilter.filterJavaScriptInSource( javascriptTest, sw );
        assertEquals( "filterJavaScriptInSource failed", jsSource, sw.toString() );

    }

    @Test
    public void JSONTest()
    {
        String jsonValues = "\"}{\"CustomData\":[\"foo bar\"]}";
        StringWriter sw = new StringWriter( jsonValues.length() * 2 );

        String json = "CustomDatafoobar";
        assertEquals( "filterJSONValue failed", json, SecureFilter.filterJSONValue( jsonValues ) );

        SecureFilter.filterJSONValue( jsonValues, sw );
        assertEquals( "filterJSONValue failed", json, sw.toString() );
    }

    @Test
    public void URITest()
    {
        String URI = "?foo=bar&test=^42@314*(&SF&Ts=+~\u0732";
        StringWriter sw = new StringWriter( URI.length() * 2 );

        String uriComp = "foobartest42314*(SFTs~";
        assertEquals( "filterUriComponent failed", uriComp, SecureFilter.filterUriComponent( URI ) );

        SecureFilter.filterUriComponent( URI, sw );
        assertEquals( "filterUriComponent failed", uriComp, sw.toString() );

        sw = new StringWriter( URI.length() * 2 );
        String uriStrict = "foobartest42314SFTs~";
        assertEquals( "filterUriComponentStrict failed", uriStrict, SecureFilter.filterUriComponentStrict( URI ) );

        SecureFilter.filterUriComponentStrict( URI, sw );
        assertEquals( "filterUriComponentStrict failed", uriStrict, sw.toString() );
    }
}
