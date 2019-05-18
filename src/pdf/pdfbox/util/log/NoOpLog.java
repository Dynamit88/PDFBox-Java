package pdf.pdfbox.util.log;


import java.io.Serializable;


/**
 * <p>Trivial implementation of Log that throws away all messages.  No
 * configurable system properties are supported.</p>
 *
 * @author <a href="mailto:sanders@apache.org">Scott Sanders</a>
 * @author Rod Waldhoff
 * @version $Id: NoOpLog.java 155426 2005-02-26 13:10:49Z dirkv $
 *
 * @deprecated Please use {@link java.net.URL#openConnection} instead.
 *     Please visit <a href="http://android-developers.blogspot.com/2011/09/androids-http-clients.html">this webpage</a>
 *     for further details.
 */
@Deprecated
public class NoOpLog implements Log, Serializable {

    /** Convenience constructor */
    public NoOpLog() { }
    /** Base constructor */
    public NoOpLog(String name) { }
    /** Do nothing */
    public void trace(Object message) { }
    /** Do nothing */
    public void trace(Object message, Throwable t) { }
    /** Do nothing */
    public void debug(Object message) { }
    /** Do nothing */
    public void debug(Object message, Throwable t) { }
    /** Do nothing */
    public void info(Object message) { }
    /** Do nothing */
    public void info(Object message, Throwable t) { }
    /** Do nothing */
    public void warn(Object message) { }
    /** Do nothing */
    public void warn(Object message, Throwable t) { }
    /** Do nothing */
    public void error(Object message) { }
    /** Do nothing */
    public void error(Object message, Throwable t) { }
    /** Do nothing */
    public void fatal(Object message) { }
    /** Do nothing */
    public void fatal(Object message, Throwable t) { }

    /**
     * Debug is never enabled.
     *
     * @return false
     */
    public final boolean isDebugEnabled() { return false; }

    /**
     * Error is never enabled.
     *
     * @return false
     */
    public final boolean isErrorEnabled() { return false; }

    /**
     * Fatal is never enabled.
     *
     * @return false
     */
    public final boolean isFatalEnabled() { return false; }

    /**
     * Info is never enabled.
     *
     * @return false
     */
    public final boolean isInfoEnabled() { return false; }

    /**
     * Trace is never enabled.
     *
     * @return false
     */
    public final boolean isTraceEnabled() { return false; }

    /**
     * Warn is never enabled.
     *
     * @return false
     */
    public final boolean isWarnEnabled() { return false; }

}
