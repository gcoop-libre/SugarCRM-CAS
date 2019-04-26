<?php

/**
 * Class that allows SugarCRM/SuiteCRM to perform user authentication using CAS.
 * php version 5.6+
 *
 * @category Login
 * @package  GCA
 * @author   David Burke <davidburke@dont-know-address.com>
 * @author   Al Gorgeous <algorgeous@dont-know-address.com>
 * @author   gcoop <info@gcoop.coop>
 * @license  Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @link     https://github.com/gcoop-libre/SugarCRM-CAS
 */


if (!defined('sugarEntry') || !sugarEntry) {
    die('Not A Valid Entry Point');
}
require_once 'modules/Users/authentication/SugarAuthenticate/SugarAuthenticate.php';
require_once SugarConfig::getInstance()->get('cas.library');

/**
 * Module that allows Sugar to perform user authentication using
 *  CAS.
 *
 * @category Login
 * @package  GCA
 * @author   David Burke <davidburke@dont-know-address.com>
 * @author   Al Gorgeous <algorgeous@dont-know-address.com>
 * @author   gcoop <info@gcoop.coop>
 * @license  Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @link     https://github.com/gcoop-libre/SugarCRM-CAS
 */

class CASAuthenticate extends SugarAuthenticate
{
    public $userAuthenticateClass = 'CASAuthenticateUser';
    public $authenticationDir = 'CASAuthenticate';


    /**
     * Constructor
     */
    public function __construct()
    {
        parent::SugarAuthenticate();
        $includeFile = 'modules/Users/authentication/'.
                     $this->authenticationDir .'/'
                     .$this->userAuthenticateClass .'.php';
        include_once $includeFile;
        $this->userAuthenticate = new $this->userAuthenticateClass();
        $this->doCASAuth();
    }


    /**
     * Deprecated since version SuiteCRM7.6.
     * PHP4 Style Constructors are deprecated and will be removed in 8.0,
     * please update your code, use __construct instead
     *
     * @return none
     */
    public function CASAuthenticate()
    {
        $deprecatedMessage
            = 'PHP4 Style Constructors are deprecated'.
            ' and will be remove in SuiteCRM 8.0, please update your code';

        if (LoggerManager::getLogger() !== null) {
            LoggerManager::getLogger()->deprecated($deprecatedMessage);
        } else {
            trigger_error($deprecatedMessage, E_USER_DEPRECATED);
        }
        self::__construct();
    }

    /**
     * Do CAS Auth.
     *
     * @return none
     */
    public function doCASAuth()
    {
        @session_start();

        // Don't try to login if the user is logging out
        if (isset($_REQUEST['action']) && $_REQUEST['action'] == 'Logout') {
            $this->logout();
            // If the user is already authenticated, do this.
        } elseif (isset($_SESSION['authenticated_user_id'])) {
            $this->sessionAuthenticate();
            return;
        } else {
            // Try to log the user in via SSO
            if ($this->userAuthenticate->loadUserOnLogin() == true) {
                parent::postLoginAuthenticate();
                header('Location: ' . SugarConfig::getInstance()->get('site_url'));
            } else {
                //I should redirect here.  I'm not sure on the syntax -- sorry.
                die();
            }
        }
    }

    /**
     * Session Authenticate
     *
     * @return $authenticated
     */
    public function sessionAuthenticate()
    {
        global $module, $action, $allowedActions;
        $authenticated = false;
        // these are actions where the user/server keys aren't compared
        $allowedActions = array ("Authenticate", "Login");

        if (isset($_SESSION['authenticated_user_id'])) {
            LoggerManager::getLogger()->debug(
                "We have an authenticated user id: "
                .$_SESSION["authenticated_user_id"]
            );
            $authenticated = $this->postSessionAuthenticate();
        } elseif (isset($action)
            && isset($module)
            && $action == "Authenticate"
            && $module == "Users"
        ) {
            LoggerManager::getLogger()->debug(
                "We are NOT authenticating user now.  CAS will redirect."
            );
        }
        return $authenticated;
    }

    /**
     * Post session Authenticate
     *
     * @return bool
     */
    public function postSessionAuthenticate()
    {
        global $action, $allowedActions;

        $uniqueKey = SugarConfig::getInstance()->get(unique_key);

        $_SESSION['userTime']['last'] = time();
        $user_unique_key = (isset($_SESSION['unique_key'])) ?
                         $_SESSION['unique_key'] : '';

        $server_unique_key = ($uniqueKey !== null) ? $uniqueKey : '';

        //CHECK IF USER IS CROSSING SITES
        if (($user_unique_key != $server_unique_key)
            && (!in_array($action, $allowedActions))
            && (!isset($_SESSION['login_error']))
        ) {
            session_destroy();
            $postLoginNav = '';
            if (!empty($record) && !empty($action) && !empty($module)) {
                $postLoginNav
                    = "&login_module=".$module."&login_action="
                    .$action."&login_record=".$record;
            }
            LoggerManager::getLogger()->debug(
                'Destroying Session User has crossed Sites'
            );
            sugar_cleanup(true);
            die();
        }

        $authenticatedUserID = $_SESSION['authenticated_user_id'];
        if (!$this->userAuthenticate->loadUserOnSession($authenticatedUserID)) {
            session_destroy();
            LoggerManager::getLogger()->debug(
                'Current user session does not exist redirecting to login'
            );
            sugar_cleanup(true);
            die();
        }
        LoggerManager::getLogger()->debug(
            'Current user is: '.$GLOBALS['current_user']->user_name
        );
        return true;
    }


    /**
     * Logout
     *
     * @return none
     */
    public function logout()
    {
        $hostname = SugarConfig::getInstance()->get('cas.hostname');
        $port = SugarConfig::getInstance()->get('cas.port');
        $uri = SugarConfig::getInstance()->get('cas.uri');
        $changeSessionID = SugarConfig::getInstance()->get('cas.changeSessionID');
        $logoutReturnURL = SugarConfig::getInstance()->get('cas.logout_return_url');

        phpCAS::client(CAS_VERSION_2_0, $hostname, $port, $uri, $changeSessionID);
        phpCAS::setNoCasServerValidation();
        $params = array();
        if ($logoutReturnURL !== null) {
            $params = array(
                'url' => $logoutReturnURL,
            );
        }
        phpCAS::logout($params);
    }
}
