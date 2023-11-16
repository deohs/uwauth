<?php

namespace Drupal\uwauth\Form;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Config\Config;

/**
 * Configure UwAuth settings for this site.
 */
class UwAuthSettingsForm extends ConfigFormBase {
  public const SETTINGS_NAME = 'uwauth.settings';
  public const DEFAULT_SP_ENDPOINT = '/Shibboleth.sso';
  public const SYNC_AD = 'ad';
  public const SYNC_GROUPS = 'gws';
  public const SYNC_LOCAL = 'local';
  public const SYNC_NONE = 'none';

  /**
   * The current_user service.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
  protected AccountProxyInterface $account;

  /**
   * The logger_channel.uwauth service.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected LoggerInterface $logger;

  /**
   * The module settings.
   *
   * @var \Drupal\Core\Config\Config
   */
  protected Config $settings;

  /**
   * {@inheritdoc}
   */
  public function __construct(ConfigFactoryInterface $configFactory, LoggerInterface $logger, AccountProxyInterface $account) {
    parent::__construct($configFactory);
    $this->account = $account;
    $this->logger = $logger;
    $this->settings = $this->config(static::SETTINGS_NAME);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new static(
      $container->get('config.factory'),
      $container->get('logger.channel.uwauth'),
      $container->get('current_user')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'uwauth_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return [
      static::SETTINGS_NAME,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $this->logger->info('User @name accessed the SSO configuration form', [
      '@name' => $this->account->getDisplayName(),
    ]);
    $form = $this->buildUwSettings($form, $form_state);
    $form = $this->buildLocalSettings($form, $form_state);
    $form = $this->buildMailSettings($form, $form_state);
    return parent::buildForm($form, $form_state);
  }

  /**
   * Build the mail-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildMailSettings(array $form, FormStateInterface $form_state): array {
    $validDomains = $this->settings->get('mail.valid_domains');
    $validDomains = implode("\n", $validDomains);
    $form['uwauth_general']['valid_domains'] = [
      '#default_value' => $validDomains,
      '#description' => $this->t('The list of domains allowed for email addresses.'),
      '#title' => $this->t('Valid email domains'),
      '#type' => 'textarea',
    ];
    return $form;
  }

  /**
   * Build the Drupal-local-groups-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildLocalSettings(array $form, FormStateInterface $form_state): array {
    $groupSource = $this->settings->get('group.source');
    $form['uwauth_local'] = [
      '#type' => 'details',
      '#title' => $this->t('Local Drupal groups'),
      '#open' => $groupSource === static::SYNC_LOCAL,
    ];

    $excludedRoutes = $this->settings->get('auth.excluded_routes');
    $excludedRoutes = implode("\n", $excludedRoutes);
    $form['uwauth_local']['excluded_routes'] = [
      '#cols' => 20,
      '#default_value' => $excludedRoutes,
      '#description' => $this->t('List the routes not using SSO, one per line.'),
      '#title' => $this->t('Excluded routes'),
      '#type' => 'textarea',
    ];
    return $form;
  }

  /**
   * Build the UW-related part of the form.
   *
   * @param array $form
   *   The form array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The modified form array.
   */
  protected function buildUwSettings(array $form, FormStateInterface $form_state): array {
    $form['uwauth_general'] = [
      '#type' => 'details',
      '#title' => $this->t('General'),
      '#open' => TRUE,
    ];

    $groupSource = $this->settings->get('group.source');
    $form['uwauth_general']['source'] = [
      '#type' => 'select',
      '#title' => $this->t('Group Source'),
      '#description' => $this->t('Choose your group membership source, or none to disable.'),
      '#options' => [
        static::SYNC_GROUPS => $this->t('Groups Web Service'),
        static::SYNC_AD => $this->t('Active Directory'),
        static::SYNC_LOCAL => $this->t('Local Drupal groups'),
        static::SYNC_NONE => $this->t("None, don't login"),
      ],
      '#default_value' => $groupSource,
    ];

    $form['uwauth_general']['name_id'] = [
      '#default_value' => $this->settings->get('auth.name_id'),
      '#description' => $this->t('The property used as Shibboleth NameID, to be used as Drupal username.'),
      '#title' => $this->t('NameID name'),
      '#type' => 'textfield',
    ];
    $allowedAttributes = $this->settings->get('auth.allowed_attributes');
    $allowedAttributes = implode("\n", $allowedAttributes);
    $form['uwauth_general']['allowed_attributes'] = [
      '#cols' => 20,
      '#default_value' => $allowedAttributes,
      '#description' => $this->t('List the allowed attributes, one per line'),
      '#title' => $this->t('Allowed attributes'),
      '#type' => 'textarea',
    ];

    $form['uwauth_general']['sp_endpoint'] = [
      '#default_value' => $this->settings->get('auth.sp_endpoint'),
      '#description' => $this->t('The path used by the Shibboleth SP endpoint, usually <code>@path</code>.', [
        '@path' => static::DEFAULT_SP_ENDPOINT,
      ]),
      '#placeholder' => static::DEFAULT_SP_ENDPOINT,
      '#required' => TRUE,
      '#title' => $this->t('Shibboleth SP endpoint'),
      '#type' => 'textfield',
    ];

    $form['uwauth_gws'] = [
      '#type' => 'details',
      '#title' => $this->t('Groups Web Service'),
      '#description' => $this->t('If using GWS as your group source, please provide the paths to your UW certificates. For security purposes, the certificates should be stored outside of your website root.'),
      '#open' => $groupSource === static::SYNC_GROUPS,
    ];

    $form['uwauth_gws']['cert'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Certificate Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_cert.pem'),
      '#default_value' => $this->settings->get('gws.cert'),
    ];

    $form['uwauth_gws']['key'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Private Key Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_key.pem'),
      '#default_value' => $this->settings->get('gws.key'),
    ];

    $form['uwauth_gws']['cacert'] = [
      '#type' => 'textfield',
      '#title' => $this->t('CA Certificate Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_ca.pem'),
      '#default_value' => $this->settings->get('gws.cacert'),
    ];

    $form['uwauth_ad'] = [
      '#type' => 'details',
      '#title' => $this->t('Active Directory'),
      '#description' => $this->t('If using AD as your group source, please provide the LDAP URI and Base DN for your domain. For anonymous lookups, leave the Bind DN and Bind Password fields blank.'),
      '#open' => $groupSource === static::SYNC_AD,
    ];

    $form['uwauth_ad']['uri'] = [
      '#type' => 'textfield',
      '#title' => $this->t('LDAP URI'),
      '#description' => $this->t('Example: ldap://domaincontroller.example.org'),
      '#default_value' => $this->settings->get('ad.uri'),
    ];

    $form['uwauth_ad']['basedn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Base DN'),
      '#description' => $this->t('Example: DC=example,DC=org'),
      '#default_value' => $this->settings->get('ad.basedn'),
    ];

    $form['uwauth_ad']['binddn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Bind DN'),
      '#description' => $this->t('Example: CN=drupal,CN=Users,DC=example,DC=org'),
      '#default_value' => $this->settings->get('ad.binddn'),
    ];

    $form['uwauth_ad']['bindpass'] = [
      '#type' => 'password',
      '#title' => $this->t('Bind Password'),
      '#description' => $this->t('NOTE: If a bind password has been set, leave this field blank to leave it unchanged.'),
    ];

    $form['uwauth_map'] = [
      '#type' => 'details',
      '#title' => $this->t('Group to Role Mapping'),
      '#description' => $this->t('For group source portability, groups are mapped to roles. Each group can be mapped to a single role.'),
      '#open' => \in_array($groupSource, [static::SYNC_AD, static::SYNC_GROUPS]),
    ];

    $form['uwauth_map']['map'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Group Map'),
      '#description' => $this->t('Note: Each row corresponds to a single group to role mapping. The format is group|role. All roles should be entered as their machine name.'),
      '#default_value' => $this->settings->get('group.map'),
      '#rows' => 15,
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state): void {
    $baseDn = $form_state->getValue('basedn');
    $bindDn = $form_state->getValue('binddn');
    $caCert = $form_state->getValue('cacert');
    $cert = $form_state->getValue('cert');
    $key = $form_state->getValue('key');
    $map = $form_state->getValue('map');
    $source = $form_state->getValue('source');
    $uri = $form_state->getValue('uri');

    if (($source == static::SYNC_AD) && (($uri == '') || ($baseDn == ''))) {
      $form_state->setErrorByName('source', $this->t('Active Directory requires both the URI and Base DN to be configured.'));
    }

    if (($source == static::SYNC_GROUPS) && (($cert == '') || ($key == '') || ($caCert == ''))) {
      $form_state->setErrorByName('source', $this->t('Groups Web Service requires the Certificate, Key, and CA Certificate to be configured.'));
    }

    if (($cert != '') && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $cert)) {
      $form_state->setErrorByName('cert', $this->t('The Certificate path contains invalid characters.'));
    }
    elseif (($cert != '') && !is_readable($cert)) {
      $form_state->setErrorByName('cert', $this->t('The Certificate file could not be read. Please verify the path is correct.'));
    }

    if (($key != '') && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $key)) {
      $form_state->setErrorByName('key', $this->t('The Key path contains invalid characters.'));
    }
    elseif (($key != '') && !is_readable($key)) {
      $form_state->setErrorByName('key', $this->t('The Key file could not be read. Please verify the path is correct.'));
    }

    if (($caCert != '') && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $caCert)) {
      $form_state->setErrorByName('cacert', $this->t('The CA Certificate path contains invalid characters.'));
    }
    elseif (($caCert != '') && !is_readable($caCert)) {
      $form_state->setErrorByName('cacert', $this->t('The CA Certificate file could not be read. Please verify the path is correct.'));
    }

    if (($uri != '') && (preg_match("/^(ldap:\/\/|ldaps:\/\/)[a-z0-9_\.\-]*[a-z0-9]$/i", $uri) === 0)) {
      $form_state->setErrorByName('uri', $this->t('The LDAP URI contains invalid characters or formatting.'));
    }

    if (($baseDn != '') && (preg_match("/^(OU=|DC=)[a-z0-9_\-=, ]*[a-z0-9]$/i", $baseDn) === 0)) {
      $form_state->setErrorByName('basedn', $this->t('The Base DN contains invalid characters or formatting.'));
    }

    if (($bindDn != '') && (preg_match("/^CN=[a-z0-9_\-=, ]*[a-z0-9]$/i", $bindDn) === 0)) {
      $form_state->setErrorByName('binddn', $this->t('The Bind DN contains invalid characters or formatting.'));
    }

    if (($map != '') && preg_match_all("/^([^a-z0-9_\-]*\|[a-z0-9_\-]*|[a-z0-9_\-]*\|[^a-z0-9_\-]*)$/mi", $map)) {
      $form_state->setErrorByName('map', $this->t('The Group Map contains invalid characters or formatting.'));
    }

    if ($form_state->getErrors()) {
      $this->logger->info('User {name} attempted to change SSO configuration and failed.', [
        'name' => $this->account->getDisplayName(),
      ]);
    }
  }

  /**
   * Convert a multi-line form state value to an array of non-empty strings.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $key
   *   The key for the value in form state.
   *
   * @return array
   *   The value as an array of single-line, non-empty strings.
   */
  public static function getTextFromValues(FormStateInterface $form_state, string $key): array {
    $rawValue = $form_state->getValue($key);
    $arrayValue = explode("\n", "$rawValue\n");
    return array_filter(array_map('trim', $arrayValue));
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $allowedAttributes = static::getTextFromValues($form_state, 'allowed_attributes');
    $excludedRoutes = static::getTextFromValues($form_state, 'excluded_routes');
    $validDomains = static::getTextFromValues($form_state, 'valid_domains');

    $this->settings
      ->set('auth.allowed_attributes', $allowedAttributes)
      ->set('auth.excluded_routes', $excludedRoutes)
      ->set('auth.name_id', $form_state->getValue('name_id'))
      ->set('auth.sp_endpoint', $form_state->getValue('sp_endpoint'))
      ->set('mail.valid_domains', $validDomains)
      ->set('gws.cert', $form_state->getValue('cert'))
      ->set('gws.key', $form_state->getValue('key'))
      ->set('gws.cacert', $form_state->getValue('cacert'))
      ->set('ad.uri', $form_state->getValue('uri'))
      ->set('ad.basedn', $form_state->getValue('basedn'))
      ->set('ad.binddn', $form_state->getValue('binddn'));
    if (($this->settings->get('ad.bindpass') === NULL) || ($form_state->getValue('bindpass') != '')) {
      $this->settings->set('ad.bindpass', $form_state->getValue('bindpass'));
    }
    $this->settings->set('group.map', $form_state->getValue('map'))
      ->set('group.source', $form_state->getValue('source'));

    $this->settings->save();

    parent::submitForm($form, $form_state);
    $this->logger->warning('User {name} changed the SSO configuration.', [
      'name' => $this->account->getDisplayName(),
    ]);
  }

}
