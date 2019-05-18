package pdf.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;

import pdf.bouncycastle.mime.BasicMimeParser;
import pdf.bouncycastle.mime.Headers;
import pdf.bouncycastle.mime.MimeParser;
import pdf.bouncycastle.mime.MimeParserProvider;
import pdf.bouncycastle.operator.DigestCalculatorProvider;

public class SMimeParserProvider
    implements MimeParserProvider
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserProvider(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public MimeParser createParser(InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider), source);
    }

    public MimeParser createParser(Headers headers, InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider), headers, source);
    }
}
