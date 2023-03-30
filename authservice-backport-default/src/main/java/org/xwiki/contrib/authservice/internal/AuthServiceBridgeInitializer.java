/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.authservice.internal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLifecycleException;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;

/**
 * Automatically register the bridge as authenticator at startup (unless there is already a configured authenticator).
 * 
 * @version $Id$
 */
@Component
@Singleton
@Named(AuthServiceBridgeInitializer.NAME)
public class AuthServiceBridgeInitializer extends AbstractEventListener implements Initializable, Disposable
{
    /**
     * The name of this event listener (and its component hint at the same time).
     */
    public static final String NAME = "org.xwiki.contrib.authservice.internal.AuthServiceBridgeInitializer";

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private XWikiAuthServiceComponent auth;

    @Inject
    @Named("xwikicfg")
    private ConfigurationSource xwikicfg;

    /**
     * Default constructor.
     */
    public AuthServiceBridgeInitializer()
    {
        super(NAME, new ApplicationReadyEvent());
    }

    private void unregister(XWiki xwiki)
    {
        if (xwiki.getAuthService() == this.auth) {
            // Reset the cached auth service so that it's released next time
            xwiki.setAuthService(null);
        }
    }

    private void register(XWiki xwiki)
    {
        // Check if an authenticator class is explicitly set (in which case we don't want to override it)
        String authServiceClass = this.xwikicfg.getProperty("xwiki.authentication.authclass");

        if (authServiceClass == null) {
            // If another authenticator already dynamically registered itself that way, don't override it
            XWikiAuthService currentAuthService = xwiki.getAuthService();
            if (currentAuthService == null || currentAuthService.getClass() == XWikiAuthServiceImpl.class) {
                // Register the bridge as authenticator
                xwiki.setAuthService(this.auth);
            }
        }
    }

    /////////////////////////////////////
    // XWiki startup

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        register(xcontext.getWiki());
    }

    /////////////////////////////////////
    // Install/uninstall/reload

    @Override
    public void initialize() throws InitializationException
    {
        XWiki xwiki = getXWiki();

        // XWiki might not be fully initialized yet in which case it means we are not installing or reloading the
        // extension
        if (xwiki != null) {
            register(xwiki);
        }
    }

    @Override
    public void dispose() throws ComponentLifecycleException
    {
        XWiki xwiki = getXWiki();

        // XWiki might not be fully initialized yet in which case we don't have anything to dispose
        if (xwiki != null) {
            unregister(xwiki);
        }
    }

    private XWiki getXWiki()
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        return xcontext != null ? xcontext.getWiki() : null;
    }
}
