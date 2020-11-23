<?php

namespace Drupal\jutaav_civicrm_access\Controller;

if (!defined('AUTH0_PATH')) {
  define('AUTH0_PATH', drupal_get_path('module', 'auth0'));
}

if (file_exists(AUTH0_PATH . '/vendor/autoload.php')) {
  require_once AUTH0_PATH . '/vendor/autoload.php';
}

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Drupal\user\PrivateTempStoreFactory;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Render\Markup;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Drupal\Core\PageCache\ResponsePolicyInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\auth0\Util\AuthHelper;
use Symfony\Component\HttpFoundation\JsonResponse;

use Symfony\Component\DependencyInjection\ContainerInterface;

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Auth0;
use Auth0\SDK\API\Authentication;
use Auth0\SDK\API\Helpers\State\SessionStateHandler;
use Auth0\SDK\Store\SessionStore;
use GuzzleHttp\Client;
use Auth0\SDK\API\Helpers\TokenGenerator;

/**
 * Controller routines for auth0 authentication.
 */
class AuthController extends ControllerBase {
  use StringTranslationTrait;

  const SESSION = 'auth0';
  const STATE = 'state';
  const AUTH0_LOGGER = 'auth0_controller';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';

  protected $tempStore;
  protected $sessionManager;
  /**
   * The logger.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;
  /**
   * The config.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The Auth0 Domain.
   *
   * @var string|null
   */
  protected $domain;

  /**
   * The Auth0 Custom Domain.
   *
   * @var string|null
   */
  protected $customDomain;

  /**
   * The Auth0 client id.
   *
   * @var string|null
   */
  protected $clientId;

  /**
   * The Auth0 client secret.
   *
   * @var string|null
   */
  protected $clientSecret;

  /**
   * If we should redirect for SSO.
   *
   * @var int
   */
  protected $redirectForSso;

  /**
   * The type of Jwt algorithm.
   *
   * @var string
   */
  protected $auth0JwtSignatureAlg;

  /**
   * If the secret is encoded.
   *
   * @var bool
   */
  protected $secretBase64Encoded;

  /**
   * If we allow offline access.
   *
   * @var bool|null
   */
  protected $offlineAccess;

  /**
   * The Auth0 helper.
   *
   * @var \Drupal\auth0\Util\AuthHelper
   */
  protected $helper;

  /**
   * The Auth0 SDK.
   *
   * @var bool
   */
  protected $auth0;

  /**
   * Logger to log 'auth0' messages.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $auth0Logger;

  /**
   * The http client.
   *
   * @var \GuzzleHttp\Client
   */
  protected $httpClient;

  public function __construct(
    PrivateTempStoreFactory $temp_store_factory,
    SessionManagerInterface $session_manager,
    ResponsePolicyInterface $page_cache,
    LoggerChannelFactoryInterface $logger_factory,
    EventDispatcherInterface $event_dispatcher,
    ConfigFactoryInterface $config_factory,
    AuthHelper $auth0_helper,
    Client $http_client
  ) {
    $this->helper = $auth0_helper;
    $this->config = $config_factory->get('auth0.settings');
    $this->tempStore = $temp_store_factory->get(AuthController::SESSION);
    $this->sessionManager = $session_manager;
    $this->domain = $this->config->get(AuthController::AUTH0_DOMAIN);
    $this->auth0Logger = $logger_factory->get('auth0');
    $this->logger = $logger_factory->get(AuthController::AUTH0_LOGGER);
    $this->customDomain = $this->config->get(AuthHelper::AUTH0_CUSTOM_DOMAIN);
    $this->clientId = $this->config->get(AuthController::AUTH0_CLIENT_ID);
    $this->clientSecret = $this->config->get(AuthController::AUTH0_CLIENT_SECRET);
    $this->redirectForSso = $this->config->get(AuthController::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0JwtSignatureAlg = $this->config->get(AuthController::AUTH0_JWT_SIGNING_ALGORITHM);
    $this->secretBase64Encoded = FALSE || $this->config->get(AuthController::AUTH0_SECRET_ENCODED);
    $this->offlineAccess = FALSE || $this->config->get(AuthController::AUTH0_OFFLINE_ACCESS);
    $this->httpClient = $http_client;
    $this->auth0 = FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
        $container->get('user.private_tempstore'),
        $container->get('session_manager'),
        $container->get('page_cache_kill_switch'),
        $container->get('logger.factory'),
        $container->get('event_dispatcher'),
        $container->get('config.factory'),
        $container->get('auth0.helper'),
        $container->get('http_client')
    );
  }

  public function getConfig($type) {
    switch($type) {
      case 'web':
        return $this->configFactory()->get('jutaav_civicrm_access.webclient.settings');

      case 'phone':
        return $this->configFactory()->get('jutaav_civicrm_access.phoneapp.settings');

      default:
        return FALSE;
    }
  }

  public function login(Request $request) {
    $idToken = $request->get('idToken');
    $type = $request->get('type') ?: 'web';
    $appConfig = $this->getConfig($type);

    if (!$appConfig) {
      return new JsonResponse(['Missing parameter \'type\'']);
    }

    // Validate the ID Token.
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$appConfig->get('auth0_domain')];
    $auth0_settings['supported_algs'] = [$appConfig->get(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM)];
    $auth0_settings['valid_audiences'] = [$appConfig->get('auth0_client_id')];
    $auth0_settings['client_secret'] = $appConfig->get('auth0_client_secret');
    $jwt_verifier = new JWTVerifier($auth0_settings);

    try {
      $user = $jwt_verifier->verifyAndDecode($idToken);

      if (empty($user->email)) {
        return new JsonResponse(['error' => 'No email address found for this user', 'isAuthenticated' => FALSE]);
      }
      $user = user_load_by_mail($user->email);
      if ($user) {
        $token_generator = new TokenGenerator($appConfig->get('auth0_client_id'), $appConfig->get('auth0_client_secret'));
        $jwt = $token_generator->generate(['user' => ['id' => $user->id()]]);
        return new JsonResponse(['access_token' => $jwt]);
      }
      else {
        return new JsonResponse(['error' => 'No email address found for this user', 'isAuthenticated' => FALSE]);
      }
    }
    catch (\Exception $e) {
      $response = ['error' => $e->getMessage()];
      return new JsonResponse($response);
    }

    return new JsonResponse($user);
  }

  public function signup(Request $request) {
    $token = $request->get('idToken');
    $type = $request->get('type') ?: 'web';
    $appConfig = $this->getConfig($type);

    // Validate the ID Token.
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$appConfig->get('auth0_domain')];
    $auth0_settings['supported_algs'] = [$appConfig->get(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM)];
    $auth0_settings['valid_audiences'] = [$appConfig->get('auth0_client_id')];
    $auth0_settings['client_secret'] = $appConfig->get('auth0_client_secret');
    $jwt_verifier = new JWTVerifier($auth0_settings);

    try {
      $user = $jwt_verifier->verifyAndDecode($idToken);
      $newUser = User::create();
      $newUser->setPassword('changeme');
      $newUser->enforceIsNew();
      $newUser->addRole('unapproved');
      $newUser->setUsername($user->nickname);
      if (empty($user->email)) {
        return new JsonResponse(['error' => 'No email address found for this user']);
      }
      else {
        $newUser->setEmail($user->email);
      }
      $newUser->save();
      return new JsonResponse(['success' => 'User created successfully.']);
    }
    catch (\Exception $e) {
      $response = ['error' => $e->getMessage()];
      return new JsonResponse($response);
    }
  }

  public function updateRole(Request $request) {
    $idToken = $request->get('idToken');
    $type = $request->get('type') ?: 'web';
    $newRole = $request->get('role') ?: 'approved';
    $appConfig = $this->getConfig($type);

    if (!$appConfig) {
      return new JsonResponse(['Missing parameter \'type\'']);
    }

    $user = $jwt_verifier->verifyAndDecode($idToken);
    if (empty($user->email)) {
      return new JsonResponse(['error' => 'No email address found for this user']);
    }
    $user = user_load_by_mail($user->email);
    if ($user) {
      $user->removeRole('unapproved');
      $user->addRole($newRole);
      $user->save();
      return new JsonResponse(['success' => 'User role updated successfully.']);
    }
    else {
      return new JsonResponse(['error' => 'No user found for this email address']);
    }
  }

  /**
   * Handles the callback for the oauth transaction.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse|null|\Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   *
   * @throws \Auth0\SDK\Exception\CoreException
   *   The Auth0 exception.
   */
  public function callback(Request $request) {
    global $base_root;

    $token = $request->get('accessToken');
    $type = $request->get('type') ?: 'web';
    $appConfig = $this->getConfig($type);

    if (!$appConfig) {
      return new JsonResponse(['Missing parameter \'type\'']);
    }

    $user = NULL;

    if (!$token) {
      return new JsonResponse(['error' => 'Missing access token', 'isAuthenticated' => FALSE]);
    }
    else {
      // Validate the ID Token.
      $auth0_settings = [];
      $auth0_settings['authorized_iss'] = [$appConfig->get('auth0_domain')];
      $auth0_settings['supported_algs'] = [$appConfig->get(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM)];
      $auth0_settings['valid_audiences'] = [$appConfig->get('auth0_client_id')];
      $auth0_settings['client_secret'] = $appConfig->get('auth0_client_secret');
      $jwt_verifier = new JWTVerifier($auth0_settings);
      $userInfo = $jwt_verifier->verifyAndDecode($token);
      $user = User::load($userInfo->scopes->user->id);
      user_login_finalize($user);
    }

    try {
      if ($user) {
        $this->auth0Logger->notice('uid of existing Drupal user found');
        $uid = $user->id();

        require_once __DIR__ . '/../../../civicrm/civicrm.config.php.drupal';
        \CRM_Core_Config::singleton();
         // @todo : return error on bootstrapping the drupal user
        // \CRM_Utils_System::loadBootStrap(['uid' => $uid], TRUE, FALSE);
        $contact_id = \CRM_Core_DAO::getFieldValue('CRM_Core_DAO_UFMatch', $uid, 'contact_id', 'uf_id');
        if ($contact_id) {
          // set session
          if (!isset($_SESSION['CiviCRM'])) {
            $session = \CRM_Core_Session::singleton();
            $session->set('ufID', $uid);
            $session->set('userID', $contact_id);
            \CRM_Core_DAO::executeQuery('SET @civicrm_user_id = %1',
              [1 => [$contact_id, 'Integer']]
            );
          }
          $entity = $request->get('entity');
          $action = $request->get('action');
          $params = (array) json_decode($request->get('params'), TRUE);
          $params = array_merge($params, ['check_permissions' => TRUE]);
          if (!$entity || !$action) {
            return new JsonResponse(['error' => 'API entity and/or action missing']);
          }
          else {
            $result = \civicrm_api3($entity, $action, $params);
            return new JsonResponse($result);
          }
        }
        else {
          return new JsonResponse(['error' => 'This account does not have an associated civicrm contact.']);
        }
      }
      else {
        throw new EmailNotSetException();
      }
    }
    catch (EmailNotSetException $e) { }
  }

  /**
   * Handles the login page override.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   The response after logout.
   */
  public function logout(Request $request) {
    $type = $request->get('type') ?: 'web';
    $appConfig = $this->getConfig($type);

    if (!$appConfig) {
      return new JsonResponse(['Missing parameter \'type\'']);
    }

    $auth0_domain = $appConfig->get('auth0_domain');
    $clientId = $appConfig->get('auth0_client_id');
    $auth0Api = new Authentication($auth0_domain, $clientId);

    user_logout();

    // If we are using SSO, we need to logout completely from Auth0,
    // otherwise they will just logout of their client.
    return new TrustedRedirectResponse($auth0Api->get_logout_link(
      \Drupal::request()->getSchemeAndHttpHost(),
      $clientId
    ));
  }

}
