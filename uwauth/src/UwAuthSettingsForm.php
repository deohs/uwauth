<?php

/**
 * @file
 * Contains \Drupal\uwauth\UwAuthSettingsForm
 */

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

    $form['uwauth_general'] = array(
      '#type' => 'details',
      '#title' => t('General'),
      '#open' => TRUE,
    );

    $form['uwauth_general']['source'] = array(
      '#type' => 'select',
      '#title' => t('Group Source'),
      '#description' => t('Choose your group membership source, or none to disable.'),
      '#options' => array(
        'gws' => t('Groups Web Service'),
        'ad' => t('Active Directory'),
        'none' => t('None'),
      ),
      '#default_value' => $config->get('group.source'),
    );

    $form['uwauth_gws'] = array(
      '#type' => 'details',
      '#title' => t('Groups Web Service'),
      '#description' => t('If using GWS as your group source, please provide the paths to your UW certificates. For security purposes, the certificates should be stored outside of your website root.'),
      '#open' => TRUE,
    );

    $form['uwauth_gws']['cert'] = array(
      '#type' => 'textfield',
      '#title' => t('Certificate Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_cert.pem'),
      '#default_value' => $config->get('gws.cert'),
    );

    $form['uwauth_gws']['key'] = array(
      '#type' => 'textfield',
      '#title' => t('Private Key Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_key.pem'),
      '#default_value' => $config->get('gws.key'),
    );

    $form['uwauth_gws']['cacert'] = array(
      '#type' => 'textfield',
      '#title' => t('CA Certificate Path'),
      '#description' => t('Example: /etc/ssl/drupal_uwca_ca.pem'),
      '#default_value' => $config->get('gws.cacert'),
    );

    $form['uwauth_ad'] = array(
      '#type' => 'details',
      '#title' => t('Active Directory'),
      '#description' => t('If using AD as your group source, please provide the LDAP URI and Base DN for your domain. This method assumes your AD installation enables anonymous lookups for group membership.'),
      '#open' => TRUE,
    );

    $form['uwauth_ad']['uri'] = array(
      '#type' => 'textfield',
      '#title' => t('LDAP URI'),
      '#description' => t('Example: ldap://domaincontroller.example.org'),
      '#default_value' => $config->get('ad.uri'),
    );

    $form['uwauth_ad']['basedn'] = array(
      '#type' => 'textfield',
      '#title' => t('Base DN'),
      '#description' => t('Example: DC=example,DC=org'),
      '#default_value' => $config->get('ad.basedn'),
    );

    $form['uwauth_map'] = array(
      '#type' => 'details',
      '#title' => t('Group to Role Mapping'),
      '#description' => t('For group source portability, groups are mapped to roles. Each group can be mapped to a single role.'),
      '#open' => TRUE,
    );

    $form['uwauth_map']['map'] = array(
      '#type' => 'textarea',
      '#title' => t('Group Map'),
      '#description' => t('Note: Each row corresponds to a single group to role mapping. The format is group|role.'),
      '#default_value' => $config->get('group.map'),
      '#rows' => 15,
    );

    return parent::buildForm($form, $form_state);
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
    $this->config('uwauth.settings')->set('group.map', $form_state->getValue('map'));
    $this->config('uwauth.settings')->set('group.source', $form_state->getValue('source'));

    $this->config('uwauth.settings')->save();

    parent::submitForm($form, $form_state);
  }
}
