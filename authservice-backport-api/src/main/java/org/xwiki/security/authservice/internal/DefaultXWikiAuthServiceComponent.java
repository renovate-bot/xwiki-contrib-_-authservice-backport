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
package org.xwiki.security.authservice.internal;

import java.security.Principal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.security.authservice.XWikiAuthServiceComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * The default implementation of {@link XWikiAuthService}, in charge of proxying to the right authentication service
 * based on the configuration.
 * 
 * @version $Id: 1b46887b9a1adc4058a5faf23a9799c0493a9592 $
 * @since 15.0RC1
 */
@Component
@Singleton
public class DefaultXWikiAuthServiceComponent implements XWikiAuthServiceComponent
{
    @Inject
    private AuthenticationServiceConfiguration configuration;

    @Inject
    @Named(StandardXWikiAuthServiceComponent.ID)
    private Provider<XWikiAuthServiceComponent> standardAuthenticatorProvider;

    private XWikiAuthServiceComponent standardAuthenticator;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private Logger logger;

    private XWikiAuthServiceComponent getStandardXWikiAuthService()
    {
        if (this.standardAuthenticator == null) {
            this.standardAuthenticator = this.standardAuthenticatorProvider.get();
        }

        return this.standardAuthenticator;
    }

    /**
     * @return the XWikiAuthService in the current context
     * @throws XWikiException when failing to get the current auth service
     */
    public XWikiAuthService getAuthService() throws XWikiException
    {
        // Get the configured authenticator
        String authHint = this.configuration.getAuthenticationService();

        // Resolve the corresponding authenticator
        ComponentManager componentManager = this.componentManagerProvider.get();
        if (authHint != null) {
            if (componentManager.hasComponent(XWikiAuthServiceComponent.class, authHint)) {
                try {
                    return componentManager.getInstance(XWikiAuthServiceComponent.class, authHint);
                } catch (ComponentLookupException e) {
                    throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_INIT,
                        authHint, e);
                }
            } else {
                this.logger.warn("No authentication service could be found for identifier [{}]. "
                    + "Fallbacking on the standard one.", authHint);
            }
        }

        // Fallback on the standard authenticator
        return getStandardXWikiAuthService();
    }

    @Override
    public String getId()
    {
        return "default";
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        return getAuthService().checkAuth(context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return getAuthService().checkAuth(username, password, rememberme, context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        getAuthService().showLogin(context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        return getAuthService().authenticate(username, password, context);
    }
}
