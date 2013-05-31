<?php
/*
 * CASAuthenticator class
 *
 * This class provides methods for CAS based authentication
 *
 * @author Anakeen
 * @license http://www.fsf.org/licensing/licenses/agpl-3.0.html GNU Affero General Public License
 * @package NU
*/

include_once ('WHAT/Class.Authenticator.php');

Class casAuthenticator extends Authenticator
{
    
    public $auth_session = null;
    /**
     **
     **
     *
     */
    public function checkAuthentication()
    {
        include_once ("CAS/CAS.php");
        
        $session = $this->getAuthSession();
        
        if ($session->read('username') != "") return Authenticator::AUTH_OK;
        
        $cas_version = $this->parms['cas_version'];
        $cas_server = $this->parms['cas_server'];
        $cas_port = $this->parms['cas_port'];
        $cas_uri = $this->parms['cas_uri'];
        
        if ($cas_version == 'CAS_VERSION_2_0') {
            $cas_version = CAS_VERSION_2_0;
        } elseif ($cas_version == 'CAS_VERSION_1_0') {
            $cas_version = CAS_VERSION_1_0;
        }
        
        if (!is_object($PHPCAS_CLIENT)) {
            phpCAS::setDebug();
            phpCAS::client($cas_version, $cas_server, $cas_port, $cas_uri, false);
        }
        phpCAS::setNoCasServerValidation();
        
        if (!phpCAS::isAuthenticated()) {
            phpCAS::forceAuthentication();
        }
        
        $session->register('username', phpCAS::getUser());
        $session->register('service', phpCAS::getServiceURL());
        
        if (!$this->freedomUserExists(phpCAS::getUser())) {
            if (!$this->tryInitializeUser(phpCAS::getUser())) {
                return Authenticator::AUTH_NOK;
            }
        }
        
        error_log(__CLASS__ . "::" . __FUNCTION__ . " " . sprintf("CAS login (user='%s', service='%s')", phpCAS::getUser() , phpCAS::getServiceURL()));
        
        return Authenticator::AUTH_OK;
    }
    /**
     * retrieve authentification session
     * @return Session the session object
     */
    public function getAuthSession()
    {
        if (!$this->auth_session) {
            include_once ('WHAT/Class.Session.php');
            $this->auth_session = new Session($this->parms{'cookie'});
            if (array_key_exists($this->parms{'cookie'}, $_COOKIE)) {
                $this->auth_session->Set($_COOKIE[$this->parms{'cookie'}]);
            } else {
                $this->auth_session->Set();
            }
        }
        return $this->auth_session;
    }
    /**
     **
     **
     *
     */
    function checkAuthorization($opt)
    {
        return TRUE;
    }
    /**
     **
     **
     *
     */
    public function askAuthentication($args)
    {
        include_once ("CAS/CAS.php");
        
        $cas_version = $this->parms['cas_version'];
        $cas_server = $this->parms['cas_server'];
        $cas_port = $this->parms['cas_port'];
        $cas_uri = $this->parms['cas_uri'];
        
        if ($cas_version == 'CAS_VERSION_2_0') {
            $cas_version = CAS_VERSION_2_0;
        } elseif ($cas_version == 'CAS_VERSION_1_0') {
            $cas_version = CAS_VERSION_1_0;
        }
        
        if (!is_object($PHPCAS_CLIENT)) {
            phpCAS::setDebug();
            phpCAS::client($cas_version, $cas_server, $cas_port, $cas_uri, false);
        }
        phpCAS::setNoCasServerValidation();
        
        phpCAS::forceAuthentication();
        
        return FALSE;
    }
    /**
     **
     **
     *
     */
    public function getAuthUser()
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read('username');
    }
    /**
     **
     **
     *
     */
    public function getAuthPw()
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read('password');
    }
    /**
     **
     **
     *
     */
    public function logout($redir_uri = '')
    {
        include_once ("CAS/CAS.php");
        
        $cas_version = $this->parms['cas_version'];
        $cas_server = $this->parms['cas_server'];
        $cas_port = $this->parms['cas_port'];
        $cas_uri = $this->parms['cas_uri'];
        
        if ($cas_version == 'CAS_VERSION_2_0') {
            $cas_version = CAS_VERSION_2_0;
        } elseif ($cas_version == 'CAS_VERSION_1_0') {
            $cas_version = CAS_VERSION_1_0;
        }
        
        if (!is_object($PHPCAS_CLIENT)) {
            phpCAS::setDebug();
            phpCAS::client($cas_version, $cas_server, $cas_port, $cas_uri, false);
        }
        phpCAS::setNoCasServerValidation();
        
        $session = $this->getAuthSession();
        $service = $session->read('service');
        
        error_log(__CLASS__ . "::" . __FUNCTION__ . " " . sprintf("CAS logout (service='%s', redirect='%')", $service, $redir_uri));
        
        $session->register('username', '');
        
        phpCAS::logoutWithRedirectServiceAndUrl($service, $service);
    }
    /**
     **
     **
     *
     */
    public function setSessionVar($name, $value)
    {
        $session_auth = $this->getAuthSession();
        $session_auth->register($name, $value);
        
        return $session_auth->read($name);
    }
    /**
     **
     **
     *
     */
    public function getSessionVar($name)
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read($name);
    }
}
?>
