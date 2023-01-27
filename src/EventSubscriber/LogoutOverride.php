<?php

namespace Drupal\uwauth\EventSubscriber;

use Drupal\Core\Routing\RouteSubscriberBase;
use Symfony\Component\Routing\RouteCollection;

/**
 * Class LogoutOverride alters the user.logout route to logout from Shibboleth.
 */
class LogoutOverride extends RouteSubscriberBase {

  /**
   * {@inheritdoc}
   */
  public function alterRoutes(RouteCollection $collection): void {
    if (!$route = $collection->get('user.logout')) {
      return;
    }

    $route->setDefault('_controller', '\Drupal\uwauth\Controller\LogoutController::logout');
  }

}
