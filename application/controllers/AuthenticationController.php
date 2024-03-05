<?php
/* Icinga Web 2 | (c) 2013 Icinga Development Team | GPLv2+ */

namespace Icinga\Controllers;

use Icinga\Application\Config;
use Icinga\Application\Hook\AuthenticationHook;
use Icinga\Application\Icinga;
use Icinga\Application\Logger;
use Icinga\Authentication\Auth;
use Icinga\Common\Database;
use Icinga\Exception\AuthenticationException;
use Icinga\Forms\Authentication\LoginForm;
use Icinga\User;
use Icinga\Web\Controller;
use Icinga\Web\Helper\CookieHelper;
use Icinga\Web\RememberMe;
use RuntimeException;
use ipl\Html\HtmlElement;
use ipl\Web\Url;
use ipl\Web\Widget\Link;

/**
 * Application wide controller for authentication
 */
class AuthenticationController extends Controller
{
    use Database;

    /**
     * {@inheritdoc}
     */
    protected $requiresAuthentication = false;

    /**
     * {@inheritdoc}
     */
    protected $innerLayout = 'inline';

    /**
     * Log into the application
     */
    public function loginAction()
    {

        $icinga = Icinga::app();
        if (($requiresSetup = $icinga->requiresSetup()) && $icinga->setupTokenExists()) {
            $this->redirectNow(Url::fromPath('setup'));
        }
        $form = new LoginForm();

        $ssoLogin = new HtmlElement('p', null, new Link(
            'Login with OneLogin',
            Url::fromPath('authentication/sso'),
            [
                'class' => 'button-link login',
                'title' => 'Login with OneLogin'
            ]
        ));

        if (RememberMe::hasCookie() && $this->hasDb()) {
            $authenticated = false;
            try {

                $rememberMeOld = RememberMe::fromCookie();
                $authenticated = $rememberMeOld->authenticate();
                if ($authenticated) {
                    $rememberMe = $rememberMeOld->renew();
                    $this->getResponse()->setCookie($rememberMe->getCookie());
                    $rememberMe->persist($rememberMeOld->getAesCrypt()->getIV());
                }
            } catch (RuntimeException $e) {
                Logger::error("Can't authenticate user via remember me cookie: %s", $e->getMessage());
            } catch (AuthenticationException $e) {
                Logger::error($e);
            }

            if (! $authenticated) {
                $this->getResponse()->setCookie(RememberMe::forget());
            }
        }

        if ($this->Auth()->isAuthenticated()) {
            // Call provided AuthenticationHook(s) when login action is called
            // but icinga web user is already authenticated
            AuthenticationHook::triggerLogin($this->Auth()->getUser());

            $redirect = $this->params->get('redirect');
            if ($redirect) {
                $redirectUrl = Url::fromPath($redirect, [], $this->getRequest());
                if ($redirectUrl->isExternal()) {
                    $this->httpBadRequest('nope');
                }
            } else {
                $redirectUrl = $form->getRedirectUrl();
            }

            $this->redirectNow($redirectUrl);
        }
        if (! $requiresSetup) {
            $cookies = new CookieHelper($this->getRequest());
            if (! $cookies->isSupported()) {
                $this
                    ->getResponse()
                    ->setBody("Cookies must be enabled to run this application.\n")
                    ->setHttpResponseCode(403)
                    ->sendResponse();
                exit;
            }
            $form->handleRequest();
        }
        $this->view->ssoLink = $ssoLogin;
        $this->view->form = $form;
        $this->view->defaultTitle = $this->translate('Icinga Web 2 Login');
        $this->view->requiresSetup = $requiresSetup;
    }

    public function ssoAction()
    {
        if ($this->Auth()->isAuthenticated()) {
            // Call provided AuthenticationHook(s) when login action is called
            // but icinga web user is already authenticated
            AuthenticationHook::triggerLogin($this->Auth()->getUser());

            $this->redirectNow(Url::fromPath('dashboard'));
        }

        $provider = new \League\OAuth2\Client\Provider\GenericProvider([
            'clientId'                => Config::app()->get('sso_oauth2', 'clientId'),
            'clientSecret'            => Config::app()->get('sso_oauth2', 'clientSecret'),
            'redirectUri'             => Config::app()->get('sso_oauth2', 'redirectUri'),
            'urlAuthorize'            => Config::app()->get('sso_oauth2', 'urlAuthorize'),
            'urlAccessToken'          => Config::app()->get('sso_oauth2', 'urlAccessToken'),
            'urlResourceOwnerDetails' => Config::app()->get('sso_oauth2', 'urlResourceOwnerDetails'),
            'scopes'                  => Config::app()->get('sso_oauth2', 'scopes')
        ]);

        if (!isset($_GET['code'])) {
            $authorizationUrl = $provider->getAuthorizationUrl();

            $this->redirectHttp($authorizationUrl);
        } else {
            try {
                $accessToken = $provider->getAccessToken('authorization_code', [
                    'code' => $_GET['code']
                ]);
                $resourceOwner = $provider->getResourceOwner($accessToken);
                $resourceOwner = $resourceOwner->toArray();

                $auth = Auth::getInstance();
                $user = new User($resourceOwner[
                    Config::app()->get(
                        'sso_oauth2',
                        'resource_username',
                        'resource_username')]
                );
                $user->setFirstname(
                    $resourceOwner[
                    Config::app()->get(
                        'sso_oauth2',
                        'given_name',
                        'given_name')
                    ]
                );
                $user->setLastname(
                    $resourceOwner[
                    Config::app()->get(
                        'sso_oauth2',
                        'family_name',
                        'family_name')
                    ]
                );
                $user->setEmail(
                    $resourceOwner[
                    Config::app()->get(
                        'sso_oauth2',
                        'email',
                        'email')
                    ]
                );
                $user->setGroups(
                    $resourceOwner[
                    Config::app()->get(
                        'sso_oauth2',
                        'groups',
                        'groups')
                    ]
                );
                $user->setIsHttpUser(false);

                if (! $user->hasDomain()) {
                    $user->setDomain(Config::app()->get('authentication', 'default_domain'));
                }

                $auth->setAuthenticated($user);

                $this->redirectHttp(Url::fromPath('dashboard'));

            } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
                Logger::error('Error during SSO authentication: %s ', $e->getMessage(), $e);
                throw new \Exception($e->getMessage());
            }

        }
    }

    /**
     * Log out the current user
     */
    public function logoutAction()
    {
        $auth = $this->Auth();
        if (! $auth->isAuthenticated()) {
            $this->redirectToLogin();
        }
        // Get info whether the user is externally authenticated before removing authorization which destroys the
        // session and the user object
        $isExternalUser = $auth->getUser()->isExternalUser();
        // Call provided AuthenticationHook(s) when logout action is called
        AuthenticationHook::triggerLogout($auth->getUser());
        $auth->removeAuthorization();
        if ($isExternalUser) {
            $this->view->layout()->setLayout('external-logout');
            $this->getResponse()->setHttpResponseCode(401);
        } else {
            if (RememberMe::hasCookie() && $this->hasDb()) {
                $this->getResponse()->setCookie(RememberMe::forget());
            }

            $this->redirectToLogin();
        }
    }
}
