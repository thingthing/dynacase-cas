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
include_once ('lib/CAS/CAS.php');

Class casAuthenticator extends Authenticator
{
    
    public $auth_session = null;

    /**
     * @throws Exception
     * @return int
     */
    public function checkAuthentication()
    {
        $session = $this->getAuthSession();
        
        if ($session->read('username') != "") return Authenticator::AUTH_OK;
        
        $this->setupCasClient($session);
        phpCAS::forceAuthentication();
        
        throw new Exception(sprintf("Error: you are not supposed to be here..."));
    }
    /**
     * Post authentication handling
     *
     * @param string $ticket
     * @param Session $session
     * @throws Exception
     */
    public function _cas_postAuthenticate($ticket, $session)
    {
        $session->register('username', phpCAS::getUser());
        $session->register('service', phpCAS::getServiceURL());
        
        if (!$this->freedomUserExists(phpCAS::getUser())) {
            if (!$this->tryInitializeUser(phpCAS::getUser())) {
                $session->register('username', '');
                throw new Exception(sprintf("Error creating CAS user '%s'.", phpCAS::getUser()));
            }
        }
        
        error_log(__METHOD__ . " " . sprintf("CAS login (user='%s', service='%s')", phpCAS::getUser() , phpCAS::getServiceURL()));
    }
    /**
     * Setup global phpCas client
     *
     * @param Session $session
     */
    public function setupCasClient($session)
    {
        $cas_version = $this->parms['cas_version'];
        $cas_server = $this->parms['cas_server'];
        $cas_port = $this->parms['cas_port'];
        $cas_uri = $this->parms['cas_uri'];
        $cas_debug = $this->parms['cas_debug'];
        $cas_sslversion = $this->parms['cas_sslversion'];
        $cas_servercacert = $this->parms['cas_servercacert'];
        
        if ($cas_version == 'CAS_VERSION_2_0') {
            $cas_version = CAS_VERSION_2_0;
        } elseif ($cas_version == 'CAS_VERSION_1_0') {
            $cas_version = CAS_VERSION_1_0;
        }
        
        if ($cas_debug == 'yes') {
            phpCAS::setDebug();
        }
        phpCAS::client($cas_version, $cas_server, $cas_port, $cas_uri, false);
        if ($cas_sslversion == 2 || $cas_sslversion == 3) {
            phpCas::setExtraCurlOption(CURLOPT_SSLVERSION, $cas_sslversion);
        }
        if ($cas_servercacert != '') {
            phpCAS::setCasServerCACert($cas_servercacert);
        } else {
            phpCAS::setNoCasServerValidation();
        }
        phpCAS::setPostAuthenticateCallback(array(
            $this,
            '_cas_postAuthenticate'
        ) , array(
            $session
        ));
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
     * @param $opt
     * @return bool
     */
    function checkAuthorization($opt)
    {
        return TRUE;
    }
    /**
     * @param $args
     * @return bool
     */
    public function askAuthentication($args)
    {
        return FALSE;
    }
    /**
     * @return string
     */
    public function getAuthUser()
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read('username');
    }
    /**
     * @return string
     */
    public function getAuthPw()
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read('password');
    }
    /**
     * @param string $redir_uri
     */
    public function logout($redir_uri = '')
    {
        $session = $this->getAuthSession();
        $service = $session->read('service');
        
        error_log(__CLASS__ . "::" . __FUNCTION__ . " " . sprintf("CAS logout (service='%s', redirect='%s')", $service, $redir_uri));
        
        $session->register('username', '');
        
        $this->setupCasClient($session);
        phpCAS::logoutWithRedirectService($service);
    }
    /**
     * @param $name
     * @param $value
     * @return string
     */
    public function setSessionVar($name, $value)
    {
        $session_auth = $this->getAuthSession();
        $session_auth->register($name, $value);
        
        return $session_auth->read($name);
    }
    /**
     * @param $name
     * @return string
     */
    public function getSessionVar($name)
    {
        $session_auth = $this->getAuthSession();
        return $session_auth->read($name);
    }
}
