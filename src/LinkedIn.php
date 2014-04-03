<?php

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.LinkedInStrategy
 * @license      MIT License
 */

namespace Opauth\LinkedIn\Strategy;

use Opauth\Opauth\AbstractStrategy;
use Opauth\Opauth\HttpClientInterface;

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * @package            Opauth.LinkedIn
 */
class LinkedIn extends AbstractStrategy
{

    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array('api_key', 'secret_key');

    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array();

    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        // For LinkedIn
        'request_token_url' => 'https://api.linkedin.com/uas/oauth/requestToken',
        'authorize_url' => 'https://www.linkedin.com/uas/oauth/authenticate',
        // or 'https://www.linkedin.com/uas/oauth/authorize'
        'access_token_url' => 'https://api.linkedin.com/uas/oauth/accessToken',
        'get_profile_url' => 'http://api.linkedin.com/v1/people/~',
        'profile_fields' => array(
            'id',
            'first-name',
            'last-name',
            'formatted-name',
            'headline',
            'picture-url',
            'summary',
            'location',
            'public-profile-url',
            'site-standard-profile-request'
        ),
        // From tmhOAuth
        'user_token' => '',
        'user_secret' => '',
        'use_ssl' => true,
        'debug' => false,
        'force_nonce' => false,
        'nonce' => false,
        // used for checking signatures. leave as false for auto
        'force_timestamp' => false,
        'timestamp' => false,
        // used for checking signatures. leave as false for auto
        'oauth_version' => '1.0',
        'curl_connecttimeout' => 30,
        'curl_timeout' => 10,
        'curl_ssl_verifypeer' => false,
        'curl_followlocation' => false,
        // whether to follow redirects or not
        'curl_proxy' => false,
        // really you don't want to use this if you are using streaming
        'curl_proxyuserpwd' => false,
        // format username:password for proxy, if required
        'is_streaming' => false,
        'streaming_eol' => "\r\n",
        'streaming_metrics_interval' => 60,
        'as_header' => true,
    );

    protected $responseMap = array(
        'uid' => 'id',
        'name' => 'formatted-name',
        'info.name' => 'formatted-name',
        'info.first_name' => 'first-name',
        'info.last_name' => 'last-name',
        'info.email' => 'email-address',
        'info.headline' => 'headline',
        'info.description' => 'summary',
        'info.location' => 'location.name',
        'info.image' => 'picture-url',
        'info.urls.linkedin' => 'public-profile-url',
        'info.urls.website' => 'url',
        'info.urls.linkedin_authenticated' => 'site-standard-profile-request.url'
    );

    public function __construct($config, $callbackUrl, HttpClientInterface $client)
    {
        parent::__construct($config, $callbackUrl, $client);

        $this->strategy['consumer_key'] = $this->strategy['api_key'];
        $this->strategy['consumer_secret'] = $this->strategy['secret_key'];
        $this->tmhOAuth = new \tmhOAuth($this->strategy);
    }

    /**
     * Auth request
     */
    public function request()
    {
        $params = array(
            'oauth_callback' => $this->callbackUrl(),
            //'scope' => $this->strategy['scope'],
        );

        $results = $this->tmhRequest('POST', $this->strategy['request_token_url'], $params);

        if ($results === false || empty($results['oauth_token']) || empty($results['oauth_token_secret'])) {
            return $this->error(
                'Could not obtain token from request_token_url',
                'token_request_failed',
                $this->tmhOAuth->response['response']
            );
        }

        $this->sessionData($results);

        $this->authorize($results['oauth_token']);
    }

    /**
     * Receives oauth_verifier, requests for access_token and redirect to callback
     */
    public function callback()
    {
        $results = $this->verifier();
        if ($results === false || empty($results['oauth_token']) || empty($results['oauth_token_secret'])) {
            return $this->error(
                'Oauth_verifier error.',
                'oauth_verifier',
                $this->tmhOAuth->response['response']
            );
        }

        $credentials = $this->verifyCredentials($results['oauth_token'], $results['oauth_token_secret']);

        if ($credentials === false || empty($credentials['id'])) {
            return $this->error(
                'Verify_credentials error.',
                'verify_credentials',
                $this->tmhOAuth->response['response']
            );
        }

        $response = $this->response($credentials);
        $response->credentials = array(
            'token' => $results['oauth_token'],
            'secret' => $results['oauth_token_secret']
        );
        $response->setMap($this->responseMap);
        return $response;
    }

    protected function verifier()
    {
        $session = $this->sessionData();
        if (empty($_REQUEST['oauth_token']) || $_REQUEST['oauth_token'] != $session['oauth_token']) {
            return $this->error(
                'User denied access.',
                'access_denied',
                $_GET
            );
        }

        $this->tmhOAuth->config['user_token'] = $session['oauth_token'];
        $this->tmhOAuth->config['user_secret'] = $session['oauth_token_secret'];
        $params = array(
            'oauth_verifier' => $_REQUEST['oauth_verifier']
        );

        return $this->tmhRequest('POST', $this->strategy['access_token_url'], $params);
    }

    protected function verifyCredentials($user_token, $user_token_secret)
    {
        $this->tmhOAuth->config['user_token'] = $user_token;
        $this->tmhOAuth->config['user_secret'] = $user_token_secret;

        $url = $this->strategy['get_profile_url'];
        if (!empty($this->strategy['profile_fields'])) {
            $fields = $this->strategy['profile_fields'];
            if (is_array($fields)) {
                $fields = implode(',', $fields);
            }
            $url .= ':(' . $fields . ')';
        }

        $response = $this->tmhRequest('GET', $url, array(), true, false, 'xml');
        if ($response === false) {
            return false;
        }

        return $this->recursiveGetObjectVars($response);
    }

    protected function authorize($oauth_token)
    {
        $params = array(
            'oauth_token' => $oauth_token
        );

        $this->http->redirect($this->strategy['authorize_url'], $params);
    }

    /**
     * Wrapper of tmhOAuth's request() with Opauth's error handling.
     *
     * request():
     * Make an HTTP request using this library. This method doesn't return anything.
     * Instead the response should be inspected directly.
     *
     * @param string $method the HTTP method being used. e.g. POST, GET, HEAD etc
     * @param string $url the request URL without query string parameters
     * @param array $params the request parameters as an array of key=value pairs
     * @param boolean|string $useauth whether to use authentication when making the request. Default true.
     * @param boolean $multipart whether this request contains multipart data. Default false
     * @param string $hander Set to 'json' or 'xml' to parse JSON or XML-based output.
     */
    protected function tmhRequest($method, $url, $params = array(), $useauth = true, $multipart = false, $handler = '')
    {
        $code = $this->tmhOAuth->request($method, $url, $params, $useauth, $multipart);

        if ($code != 200) {
            return false;
        }

        if (empty($handler)) {
            if (strpos($url, '.json') !== false) {
                $handler = 'json';
            } elseif (strpos($url, '.xml') !== false) {
                $handler = 'xml';
            }
        }

        if ($handler == 'json') {
            return json_decode($this->tmhOAuth->response['response']);
        } elseif ($handler == 'xml') {
            return simplexml_load_string($this->tmhOAuth->response['response']);
        }
        return $this->tmhOAuth->extract_params($this->tmhOAuth->response['response']);
    }
}
