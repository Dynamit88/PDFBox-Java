package pdf.bouncycastle.jce.provider;

import java.util.Collection;

import pdf.bouncycastle.util.CollectionStore;
import pdf.bouncycastle.util.Selector;
import pdf.bouncycastle.x509.X509CollectionStoreParameters;
import pdf.bouncycastle.x509.X509StoreParameters;
import pdf.bouncycastle.x509.X509StoreSpi;

public class X509StoreAttrCertCollection
    extends X509StoreSpi
{
    private CollectionStore _store;

    public X509StoreAttrCertCollection()
    {
    }

    public void engineInit(X509StoreParameters params)
    {
        if (!(params instanceof X509CollectionStoreParameters))
        {
            throw new IllegalArgumentException(params.toString());
        }

        _store = new CollectionStore(((X509CollectionStoreParameters)params).getCollection());
    }

    public Collection engineGetMatches(Selector selector)
    {
        return _store.getMatches(selector);
    }
}
