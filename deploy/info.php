<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'intrusion_detection';
$app['version'] = '1.0.4';
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
    'csplugin-routewatch',
    'snort >= 2.9.0.4',
    'snort-gpl-rules',
);

$app['core_directory_manifest'] = array(
    '/var/clearos/intrusion_detection' => array(),
    '/var/clearos/intrusion_detection/backup' => array(),
);

$app['core_file_manifest'] = array(
    'snort.php'=> array('target' => '/var/clearos/base/daemon/snort.php'),
    'routewatch-intrusion-detection.conf' => array('target' => '/etc/clearsync.d/routewatch-intrusion-detection.conf'),
);
