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
 * @link     https://github.com/algorgeous/SugarCRM-CAS
 */

if (!defined('sugarEntry') || !sugarEntry) {
    die('Not A Valid Entry Point');
}

require_once 'modules/Users/authentication/LDAPAuthenticate/LDAPConfigs/default.php';
require_once 'modules/Users/authentication/SugarAuthenticate/SugarAuthenticateUser.php';
require_once SugarConfig::getInstance()->get('cas.library');


/**
 * This is called when a user logs in
 *
 * @category Login
 * @package  GCA
 * @author   David Burke <davidburke@dont-know-address.com>
 * @author   Al Gorgeous <algorgeous@dont-know-address.com>
 * @author   gcoop <info@gcoop.coop>
 * @license  Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @link     https://github.com/algorgeous/SugarCRM-CAS
 */
class CASAuthenticateUser extends SugarAuthenticateUser
{

    /**
     * This is called when a user logs in
     *
     * @return boolean
     */
    public function loadUserOnLogin()
    {
        $name = $this->authUser();
        if (empty($name)) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Attempt to authenticate the user via CAS SSO
     *
     * @return none
     */
    public function authUser()
    {
        $hostname = SugarConfig::getInstance()->get('cas.hostname');
        $port = SugarConfig::getInstance()->get('cas.port');
        $uri = SugarConfig::getInstance()->get('cas.uri');
        $changeSessionID = SugarConfig::getInstance()->get('cas.changeSessionID');
        $logoutReturnURL = SugarConfig::getInstance()->get('cas.logout_return_url');
        $proxies = SugarConfig::getInstance()->get('cas.proxies');
        $logFile = SugarConfig::getInstance()->get('cas.log_dir_file');
        phpCAS::client(CAS_VERSION_2_0, $hostname, $port, $uri, $changeSessionID);
        phpCAS::setDebug($logFile);

        if (!empty($proxies) && is_array($proxies)) {
            phpCAS::allowProxyChain(new CAS_ProxyChain($proxies));
        }

        $this->fromCASProxyWithTicket();
        phpCAS::setNoCasServerValidation();
        phpCAS::forceAuthentication();
        $authenticated = phpCAS::isAuthenticated();

        if ($authenticated) {
            $user_name = phpCAS::getUser();

            $dbresult = DBManagerFactory::getInstance()->query(
                "SELECT id, status FROM users WHERE user_name='"
                .$user_name . "' AND deleted = 0"
            );
            // User already exists use this one
            if ($row = DBManagerFactory::getInstance()->fetchByAssoc($dbresult)) {
                if ($row['status'] != 'Inactive') {
                    return $this->loadUserOnSession($row['id']);
                } else {
                    return '';
                }
            }
            $text = 'Not authorized user.'
                  .' You may need to ask an administrator to give you access'
                  .' to SugarCRM/SuiteCRM. You may try logging in again'
                  .' <a href="https://' . $hostname
                  . ':443/cas/logout?service=http://' . $_SERVER['SERVER_NAME']
                  . '">here</a>';
            echo $text;
            die();
            return ""; // SSO authentication was successful
        } else {
            return;
        }
    }


    /**
     * Returns true or false if http_referer host is in Proxies list.
     * If so, phpCAS allows this proxy.
     *
     * @return bool
     */
    public function fromCASProxyWithTicket()
    {
        $http_ref = parse_url(@$_SERVER['HTTP_REFERER']);
        $proxies = SugarConfig::getInstance()->get('cas.proxies');

        if (!empty($proxies)
            && is_array($proxies)
            && !empty($_REQUEST['ticket'])
            && !empty($http_ref)
            && is_array($http_ref)
            && !empty($http_ref['host'])
        ) {
            foreach ($proxies as $proxy) {
                $proxy_host = parse_url($proxy);
                $msg = 'fromCASProxyWithTicket:'
                .' proxy_host: '.$proxy_host['host']
                .' http_ref: '.$http_ref['host'];
                LoggerManager::getLogger()->debug($msg);

                if (!empty($proxy_host['host'])
                    && $http_ref['host'] == $proxy_host['host']
                ) {
                        $msg = 'fromCASProxyWithTicket:'
                            .' host: '.$http_ref['host']
                            .' ticket: '.$_REQUEST['ticket']
                            .' proxy: '.$proxy;
                        LoggerManager::getLogger()->info($msg);
                        phpCAS::allowProxyChain(new CAS_ProxyChain(array($proxy)));
                        return true;
                }
            }
        }

        return false;
    }
}
