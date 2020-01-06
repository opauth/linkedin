<?php
/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © U-Zyn Chua (http://uzyn.com)
 * @link         http://opauth.org
 * @package      Opauth.LinkedInStrategy
 * @license      MIT License
 */

/**
 * LinkedIn strategy for Opauth
 * based on https://developer.linkedin.com/documents/authentication
 *
 * @package			Opauth.LinkedIn
 */
class LinkedInStrategy extends OpauthStrategy{

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('api_key', 'secret_key');

	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'state', 'response_type');

	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
		'response_type' => 'code'
	);

	/**
	 * Auth request
	 */
	public function request(){
		$url = 'https://www.linkedin.com/uas/oauth2/authorization';

		$params = array();

		$params = array(
			'client_id' => $this->strategy['api_key'],
			'state' => sha1(time()),
			'scope' => 'r_emailaddress r_liteprofile'
		);

		foreach ($this->optionals as $key){
			if (!empty($this->strategy[$key])) {
				$params[$key] = $this->strategy[$key];
			}
		}

		$this->clientGet($url, $params);
	}

	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback(){
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
			$code = $_GET['code'];
			$url = 'https://www.linkedin.com/uas/oauth2/accessToken';

			$params = array(
				'grant_type' => 'authorization_code',
				'code' => $code,
				'client_id' => $this->strategy['api_key'],
				'client_secret' => $this->strategy['secret_key'],
				'redirect_uri' => $this->strategy['redirect_uri'],
			);
			$response = $this->serverPost($url, $params, null, $headers);

			$results = json_decode($response);

			if (!empty($results) && !empty($results->access_token)){
				$profile = $this->getProfile($results->access_token);

				$this->auth = array(
					'uid' => $profile['id'],
					'info' => array(),
					'credentials' => array(
						'token' => $results->access_token,
						'expires' => date('c', time() + $results->expires_in)
					),
					'raw' => $profile
				);

				$this->mapProfile($profile, 'firstName', 'info.first_name');
				$this->mapProfile($profile, 'lastName', 'info.last_name');
				$this->mapProfile($profile, 'emailAddress', 'info.email');
				$this->mapProfile($profile, 'profilePicture', 'info.image');

				$this->callback();
			}
			else{
				$error = array(
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response,
						'headers' => $headers
					)
				);

				$this->errorCallback($error);
			}
		}
		else{
			$error = array(
				'code' => 'oauth2callback_error',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * Queries LinkedIn API for user info
	 *
	 * @param string $access_token
	 * @return array Parsed JSON results
	 * @link https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin
	 * @link https://docs.microsoft.com/en-us/linkedin/shared/references/v2/profile/basic-profile?context=linkedin/consumer/context
	 * @link https://developer.linkedin.com/docs/ref/v2/profile/localized-profile
	 */
	private function getProfile($access_token){
		$return = array();
		$options = array(
			'http' => array(
				'method' => 'GET',
				'header' => "Authorization: Bearer $access_token"
			)
		);

		if (empty($this->strategy['profile_fields'])) {
			$this->strategy['profile_fields'] = array('id', 'firstName', 'lastName', 'profilePicture(displayImage~:playableStreams)');
		}
		elseif (!is_array($this->strategy['profile_fields'])) {
			$this->strategy['profile_fields'] = explode(',', $this->strategy['profile_fields']);
		}

		// Combine fields
		$fields = '(' . implode(',', $this->strategy['profile_fields']) . ')';

		// Get the email address.
		$response = $this->httpRequest('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', $options, $headers);
		if (!empty($response)) {
			$data = (array) json_decode($response, TRUE);
			if (isset($data['elements'])) {
				$data = $data['elements'][0];
			}
			$return['emailAddress'] = $data['handle~']['emailAddress'];
		}
		else{
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query for user email information',
				'raw' => array(
					'response' => $userinfo,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
			return;
		}

		// Get other profile details.
		$userinfo = $this->httpRequest('https://api.linkedin.com/v2/me?projection=' . $fields, $options, $headers);
		if (!empty($userinfo)){
			$data = (array) json_decode($userinfo, TRUE);
			if (isset($data['elements'])) {
				$data = $data['elements'][0];
			}
			foreach ($data as $k => $v) {
				if (is_string($v)) {
					$return[$k] = $v;
				}
				elseif (isset($v['localized'])) {
					$return[$k] = $v['localized'][$v['preferredLocale']['language'] . '_' . $v['preferredLocale']['country']];
				}
				elseif (isset($v['displayImage~'])) {
					$return[$k] = $v['displayImage~']['elements'][0]['identifiers'][0]['identifier'];
				}
				else {
					$return[$k] = $v;
				}
			}
		}
		else{
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query for user information',
				'raw' => array(
					'response' => $userinfo,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
			return;
		}

		return $return;
	}
}