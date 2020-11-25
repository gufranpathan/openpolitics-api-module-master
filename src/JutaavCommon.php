<?php
namespace Drupal\jutaav_civicrm_access;

use Drupal\Core\Url;
use Drupal\Core\Datetime\DrupalDateTime;

class JutaavCommon {
  /**
   * Generic request function.
   *
   * @param string $method
   *   The REST API method.
   * @param string $url
   *   Request url.
   * @param string $body.
   *   Json encoded array.
   *
   * @return object
   *   The response object.
   */
  public function basicRequest($method, $url, $body = '', $headers, $authToken = '') {

    $client = \Drupal::httpClient();
    $options = [
      'verify' => FALSE,
      'headers' => $headers,
      'http_errors' => FALSE,
    ];

    if ($body) {
      if (empty($body['form_params'])) {
        $options['body'] = $body;
      }
      else {
        $options['form_params'] = $body['form_params'];
      }
    }
    if ($authToken) {
      $options['headers']['Authorization'] = 'Bearer ' . $authToken;
    }
    $response = $client->request($method, $url, $options);
    return $response;
  }

  public function authenticateAuth() {
    $config = \Drupal::config('jutaav_civicrm_access.webclient.settings');
    $conf_url = $config->get('auth0_domain');
    $url = $conf_url . '/oauth/token';
    $method = 'POST';
    $body['form_params'] = [
      'grant_type' => 'client_credentials',
      'client_id' => $config->get('auth0_client_id'),
      'client_secret' => $config->get('auth0_client_secret'),
      'audience' => $conf_url . '/api/v2/',
    ];

    $headers = [
      'Content-Type' => 'application/x-www-form-urlencoded',
    ];

    $request = $this->basicRequest($method, $url, $body, $headers);

    $request_data = $request->getBody()->getContents();
    $status_code = $request->getStatusCode();
    $status_text = $request->getReasonPhrase();

    if ($status_code != 200) {
      $response_data['error'] = $status_text;
    }
    else {
      $token_data = json_decode($request_data);
      $this->setToken($token_data->access_token, $token_data->expires_in);
      $response_data['message'] = 'ok';

    }
    return $response_data;
  }

  public function IsTokenExpired() {
    $current_time = time();
    $config = \Drupal::config('jutaav_civicrm_access.webclient.settings');

    return $config->get('auth0_token_expired') <= $current_time;
  }

  public function setToken($token, $expires = '') {
    $config = \Drupal::service('config.factory')->getEditable('jutaav_civicrm_access.webclient.settings');
    $config->set('auth0_access_token', $token);
    $timestamp = time();
    $expires = $expires ? $expires : 86400;
    $config->set('auth0_token_expired', (int)$timestamp + (int)$expires);
    $config->save();
  }

  public function getUserWorkspaces($userid) {

    if ($this->IsTokenExpired()) {
      $this->authenticateAuth();
    }
    $method = 'GET';
    $config = \Drupal::config('jutaav_civicrm_access.webclient.settings');
    $conf_url = $config->get('auth0_domain');
    $url = $conf_url . '/api/v2/users/' . $userid;
    $token = $config->get('auth0_access_token');

    $headers = [
      'Content-Type' => 'application/json',
    ];

    $request = $this->basicRequest($method, $url, '', $headers, $token);
    $request_data = $request->getBody()->getContents();
    $status_code = $request->getStatusCode();
    $status_text = $request->getReasonPhrase();

    if ($status_code != 200) {
      return [
        'status_code' => $status_code,
        'message' => $status_text,
      ];
    }
    else {
      $uinfo = json_decode($request_data);
      return [
        'status_code' => 200,
        'workspaces' => $uinfo->app_metadata->workspaces,
      ];
    }

  }
}
