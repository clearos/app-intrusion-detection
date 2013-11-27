<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'intrusion_detection';
$app['version'] = '1.5.15';
$app['release'] = '1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['description'] = lang('intrusion_detection_app_description');
$app['tooltip'] = lang('intrusion_detection_tooltip');

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('intrusion_detection_app_name');
$app['category'] = lang('base_category_gateway');
$app['subcategory'] = lang('base_subcategory_intrusion_protection');

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['requires'] = array(
    'app-network',
);

$app['core_requires'] = array(
    'app-network-core',
    'rsyslog',
    'snort >= 2.9.5.3',
    'snort-gpl-rules',
);

$app['core_directory_manifest'] = array(
    '/var/clearos/intrusion_detection' => array(),
    '/var/clearos/intrusion_detection/backup' => array(),
);

$app['core_file_manifest'] = array(
    'snort.php'=> array('target' => '/var/clearos/base/daemon/snort.php'),
    'snort-rsyslog.conf'=> array(
        'target' => '/etc/rsyslog.d/snort.conf',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
    'intrusion_detection.conf'=> array(
        'target' => '/etc/clearos/intrusion_detection.conf',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
    'network-configuration-event'=> array(
        'target' => '/var/clearos/events/network_configuration/intrusion_detection',
        'mode' => '0755'
    ),
    'network-connected-event'=> array(
        'target' => '/var/clearos/events/network_connected/intrusion_detection',
        'mode' => '0755'
    ),
);

$app['delete_dependency'] = array(
    'app-intrusion-detection-core',
    'snort',
    'snort-gpl-rules'
);
