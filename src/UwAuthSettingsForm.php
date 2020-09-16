<?php

namespace Drupal\uwauth;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Configure UwAuth settings for this site.
 */
class UwAuthSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'uwauth_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'uwauth.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('uwauth.settings');

    $form['uwauth_general'] = [
      '#type' => 'details',
      '#title' => $this->t('General'),
      '#open' => TRUE,
    ];

    $form['uwauth_general']['source'] = [
      '#type' => 'select',
      '#title' => $this->t('Group Source'),
      '#description' => $this->t('Choose your group membership source, or none to disable.'),
      '#options' => [
        'gws' => $this->t('Groups Web Service'),
        'ad' => $this->t('Active Directory'),
        'none' => $this->t('None'),
      ],
      '#default_value' => $config->get('group.source'),
    ];

    $form['uwauth_gws'] = [
      '#type' => 'details',
      '#title' => $this->t('Groups Web Service'),
      '#description' => $this->t('If using GWS as your group source, please provide the paths to your UW certificates. For security purposes, the certificates should be stored outside of your website root.'),
      '#open' => TRUE,
    ];

    $form['uwauth_gws']['cert'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Certificate Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_cert.pem'),
      '#default_value' => $config->get('gws.cert'),
    ];

    $form['uwauth_gws']['key'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Private Key Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_key.pem'),
      '#default_value' => $config->get('gws.key'),
    ];

    $form['uwauth_gws']['cacert'] = [
      '#type' => 'textfield',
      '#title' => $this->t('CA Certificate Path'),
      '#description' => $this->t('Example: /etc/ssl/drupal_uwca_ca.pem'),
      '#default_value' => $config->get('gws.cacert'),
    ];

    $form['uwauth_ad'] = [
      '#type' => 'details',
      '#title' => $this->t('Active Directory'),
      '#description' => $this->t('If using AD as your group source, please provide the LDAP URI and Base DN for your domain. For anonymous lookups, leave the Bind DN and Bind Password fields blank.'),
      '#open' => TRUE,
    ];

    $form['uwauth_ad']['uri'] = [
      '#type' => 'textfield',
      '#title' => $this->t('LDAP URI'),
      '#description' => $this->t('Example: ldap://domaincontroller.example.org'),
      '#default_value' => $config->get('ad.uri'),
    ];

    $form['uwauth_ad']['basedn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Base DN'),
      '#description' => $this->t('Example: DC=example,DC=org'),
      '#default_value' => $config->get('ad.basedn'),
    ];

    $form['uwauth_ad']['binddn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Bind DN'),
      '#description' => $this->t('Example: CN=drupal,CN=Users,DC=example,DC=org'),
      '#default_value' => $config->get('ad.binddn'),
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
      '#open' => TRUE,
    ];

    $form['uwauth_map']['map'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Group Map'),
      '#description' => $this->t('Note: Each row corresponds to a single group to role mapping. The format is group|role. All roles should be entered as their machine name.'),
      '#default_value' => $config->get('group.map'),
      '#rows' => 15,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {

    if (($form_state->getValue('source') == "ad") && ((strlen($form_state->getValue('uri')) == 0) || (strlen($form_state->getValue('basedn')) == 0))) {
      $form_state->setErrorByName('source', $this->t('Active Directory requires both the URI and Base DN to be configured.'));
    }

    if (($form_state->getValue('source') == "gws") && ((strlen($form_state->getValue('cert')) == 0) || (strlen($form_state->getValue('key')) == 0) || (strlen($form_state->getValue('cacert')) == 0))) {
      $form_state->setErrorByName('source', $this->t('Groups Web Service requires the Certificate, Key, and CA Certificate to be configured.'));
    }

    if ((strlen($form_state->getValue('cert')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('cert'))) {
      $form_state->setErrorByName('cert', $this->t('The Certificate path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('cert')) > 0) && !is_readable($form_state->getValue('cert'))) {
      $form_state->setErrorByName('cert', $this->t('The Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('key')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('key'))) {
      $form_state->setErrorByName('key', $this->t('The Key path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('key')) > 0) && !is_readable($form_state->getValue('key'))) {
      $form_state->setErrorByName('key', $this->t('The Key file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('cacert')) > 0) && preg_match_all("/[^a-zA-Z0-9_\-\/:\\. ]/", $form_state->getValue('cacert'))) {
      $form_state->setErrorByName('cacert', $this->t('The CA Certificate path contains invalid characters.'));
    }
    elseif ((strlen($form_state->getValue('cacert')) > 0) && !is_readable($form_state->getValue('cacert'))) {
      $form_state->setErrorByName('cacert', $this->t('The CA Certificate file could not be read. Please verify the path is correct.'));
    }

    if ((strlen($form_state->getValue('uri')) > 0) && (preg_match("/^(ldap:\/\/|ldaps:\/\/)[a-z0-9_\.\-]*[a-z0-9]$/i", $form_state->getValue('uri')) === 0)) {
      $form_state->setErrorByName('uri', $this->t('The LDAP URI contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('basedn')) > 0) && (preg_match("/^(OU=|DC=)[a-z0-9_\-=, ]*[a-z0-9]$/i", $form_state->getValue('basedn')) === 0)) {
      $form_state->setErrorByName('basedn', $this->t('The Base DN contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('binddn')) > 0) && (preg_match("/^CN=[a-z0-9_\-=, ]*[a-z0-9]$/i", $form_state->getValue('binddn')) === 0)) {
      $form_state->setErrorByName('binddn', $this->t('The Bind DN contains invalid characters or formatting.'));
    }

    if ((strlen($form_state->getValue('map')) > 0) && preg_match_all("/^([^a-z0-9_\-]*\|[a-z0-9_\-]*|[a-z0-9_\-]*\|[^a-z0-9_\-]*)$/mi", $form_state->getValue('map'))) {
      $form_state->setErrorByName('map', $this->t('The Group Map contains invalid characters or formatting.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->config('uwauth.settings')->set('gws.cert', $form_state->getValue('cert'));
    $this->config('uwauth.settings')->set('gws.key', $form_state->getValue('key'));
    $this->config('uwauth.settings')->set('gws.cacert', $form_state->getValue('cacert'));
    $this->config('uwauth.settings')->set('ad.uri', $form_state->getValue('uri'));
    $this->config('uwauth.settings')->set('ad.basedn', $form_state->getValue('basedn'));
    $this->config('uwauth.settings')->set('ad.binddn', $form_state->getValue('binddn'));
    if (($this->config('uwauth.settings')->get('ad.bindpass') === NULL) || (strlen($form_state->getValue('bindpass')) > 0)) {
      $this->config('uwauth.settings')->set('ad.bindpass', $form_state->getValue('bindpass'));
    }
    $this->config('uwauth.settings')->set('group.map', $form_state->getValue('map'));
    $this->config('uwauth.settings')->set('group.source', $form_state->getValue('source'));

    $this->config('uwauth.settings')->save();

    parent::submitForm($form, $form_state);
  }

}
