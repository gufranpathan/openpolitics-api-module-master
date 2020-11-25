<?php

namespace Drupal\jutaav_civicrm_access\Controller;

use Drupal\Core\Cache\CacheableJsonResponse;
use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\Query\QueryFactory;
use Symfony\Component\HttpFoundation\Request;
use Drupal\jutaav_civicrm_access\JutaavCommon as Common;
use Auth0\SDK\JWTVerifier;
use Drupal\auth0\Util\AuthHelper;

/**
* Class CustomEndpointsController.
*/
class CustomEndpointsController extends ControllerBase {

  /**
   * REST Enpoint for setting user workspace.
   */
  public function setUserWorkspace(Request $request) {

    if ( 0 === strpos( $request->headers->get( 'Content-Type' ), 'application/json' ) ) {
      $data = json_decode( $request->getContent(), TRUE );
      $request->request->replace( is_array( $data ) ? $data : [] );
    }
    else {
      $this->returnBadRequest('Wrong content type format. Expecting application/json');
    }

    $cache_metadata = new CacheableMetadata();
    $cache_metadata->setCacheTags(['auth0_user_workspace']);

    $status_code = 200;
    $status_text = 'OK';
    $rest_data['message'] = 'ok';

    if (empty($data['userid'])) {
      return $this->returnBadRequest('The "userid" parameter is missed out.');
    }

    if (empty($data['workspace'])) {
       return $this->returnBadRequest('The "workspace" parameter is missed out.');
    }

    $common = new Common();
    if ($common->isTokenExpired()) {
      $common->authenticateAuth();
    }
    $config = \Drupal::config('custom_endpoints.settings');
    $method = 'patch';
    $url = $config->get('provider-url') . '/api/v2/users/' . $data['userid'];
    $token = $config->get('access_token');
    $uinfo = $common->getUserWorkspaces($data['userid']);
    if (isset($uinfo['message'])) {
      $rest_data = $workspaces['message'];
      $status_code = $workspaces['status_code'];
      $status_text = $workspaces['message'];
    }
    else {
      $workspaces = $uinfo['workspaces'];
      if (!in_array($data['workspace'], $workspaces)) {
        $workspaces[] = $data['workspace'];
      }
      $body_arr = [
        'app_metadata' => [
          'workspaces' => $workspaces,
        ],
      ];
      $body = json_encode($body_arr);

      $headers = [
        'Content-Type' => 'application/json',
      ];

      $request = $common->basicRequest($method, $url, $body, $headers, $token);
      $request_data = $request->getBody()->getContents();
      $status_code = $request->getStatusCode();
      $status_text = $request->getReasonPhrase();
      $rest_data = $request_data;
    }

   // Create the JSON response object and add the cache metadata.
   $response = new CacheableJsonResponse($rest_data);
   $response->setStatusCode($status_code, $status_text);
   $response->addCacheableDependency($rest_data);

   return $response;
  }

  public function createUserByMailPhone(Request $request) {

    $status_code = 200;
    $status_text = 'OK';
    $rest_data['message'] = 'ok';

    if ( 0 === strpos( $request->headers->get( 'Content-Type' ), 'application/json' ) ) {
      $data = json_decode( $request->getContent(), TRUE );
      $request->request->replace( is_array( $data ) ? $data : [] );
    }
    else {
      $this->returnBadRequest('Wrong content type format. Expecting application/json');
    }

    if ((empty($data['phone'])) && (empty($data['mail']))) {
      return $this->returnBadRequest('At least one parameter required "phone" or "mail"');
    }
    if ($data['mail']) {
      $usermail = $data['mail'];

      if (!\Drupal::service('email.validator')->isValid($usermail)) {
        return $this->returnBadRequest('The "mail" parameter should be the valid email address.');
      }
    }

    if (empty($data['mail'])) {
      $usermail = $data['phone'] . '@jutaav.com';
    }
    $userStorage = \Drupal::entityTypeManager()->getStorage('user');
    if ($user = $userStorage->loadByProperties(['name' => $usermail])) {
      return $this->returnBadRequest('The user with mail ' . $usermail . ' already exists.');
    }

    $user_arr = [
      'name' => $usermail,
      'password' => '',
      'mail' => $usermail,
    ];

    $user = $userStorage->create($user_arr);
    $user->addRole('unapproved');
    $user->save();

    $response = new CacheableJsonResponse($user->toArray());
    $response->setStatusCode($status_code, $status_text);
    $response->addCacheableDependency($user);

    return $response;
  }

  protected function returnBadRequest($reason, $status_code = 400) {
    $data['message'] = $reason;

    $response = new CacheableJsonResponse($data);
    $response->setStatusCode($status_code, $reason);
    $response->addCacheableDependency($data);
    return $response;
  }

  protected function checkAuth(Request $request) {

    $appConfig = \Drupal::config('jutaav_civicrm_access.webclient.settings');
    $auth0_settings = [];

    $auth0_settings['authorized_iss'] = [$appConfig->get('auth0_domain')];
    $auth0_settings['supported_algs'] = [$appConfig->get(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM)];
    $auth0_settings['valid_audiences'] = [$appConfig->get('auth0_client_id')];
    $auth0_settings['client_secret'] = $appConfig->get('auth0_client_secret');
    $jwt_verifier = new JWTVerifier($auth0_settings);

    $user = $jwt_verifier->verifyAndDecode($idToken);

    if (empty($user->email)) {
      $this->returnBadRequest('No email address found for this user', 401);
    }

    $user = user_load_by_mail($user->email);
    if ($user) {
      return TRUE;
    }
    else {
      $this->returnBadRequest('No authorized', 401);
    }
  }
}
