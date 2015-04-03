<?php

/**
 * @file
 * Contains \Drupal\uwauth\Authentication\Provider\UwAuth.
 */

namespace Drupal\uwauth\Authentication\Provider;

use Drupal\Component\Utility\String;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Authentication\AuthenticationProviderChallengeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityManagerInterface;
use Drupal\user\UserAuthInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * HTTP Basic authentication provider.
 */
class UwAuth implements AuthenticationProviderInterface, AuthenticationProviderChallengeInterface {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The user auth service.
   *
   * @var \Drupal\user\UserAuthInterface
   */
  protected $userAuth;

  /**
   * The entity manager.
   *
   * @var \Drupal\Core\Entity\EntityManagerInterface
   */
  protected $entityManager;

  /**
   * Constructs a HTTP basic authentication provider object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\user\UserAuthInterface $user_auth
   *   The user authentication service.
   * @param \Drupal\Core\Entity\EntityManagerInterface $entity_manager
   *   The entity manager service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, UserAuthInterface $user_auth, EntityManagerInterface $entity_manager) {
    $this->configFactory = $config_factory;
    $this->userAuth = $user_auth;
    $this->entityManager = $entity_manager;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $username = $request->headers->get('PHP_AUTH_USER');
    return isset($username);
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $username = $request->headers->get('PHP_AUTH_USER');
    $accounts = $this->entityManager->getStorage('user')->loadByProperties(array('name' => $username, 'status' => 1));
    $account = reset($accounts);
    if ($account) {
      $uid = $account->id();
      return $this->entityManager->getStorage('user')->load($uid);
    }
    return [];
  }

  /**
   * {@inheritdoc}
   */
  public function challengeException(Request $request, \Exception $previous) {
    $site_name = $this->configFactory->get('system.site')->get('name');
    $challenge = String::format('Basic realm="@realm"', array(
      '@realm' => !empty($site_name) ? $site_name : 'Access restricted',
    ));
    return new UnauthorizedHttpException($challenge, 'No authentication credentials provided.', $previous);
  }

}
